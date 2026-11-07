package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"
)

// CPU/GPU staging is enabled by default for single-vault jobs; the CLI can disable it.
var gpuPrepPipelineEnabled bool

// gpuPipelineSlot is owned by the CPU producer until it is sent to the GPU
// consumer. The consumer owns it until finalization and MAC verification are
// complete, then returns the slot to the producer. No state buffers are shared
// across in-flight batches.
type gpuPipelineSlot struct {
	state       []byte
	transformed []byte
}

type gpuPipelineBatch struct {
	passwords [][]byte
	passes    [][]byte
	state     []byte
	blocklen  int
	slot      int
	closed    bool
	err       error
}

// prepareGPUStream is the only goroutine that receives candidates on behalf
// of this GPU worker. It never calls OpenCL and never accesses gpuBackend.
// Up to two batches can be in flight, one on the CPU and one on the GPU.
func prepareGPUStream(ctx context.Context, abort <-chan struct{}, ch <-chan []byte, v vault, batchSize, prepThreads int, free [2]chan struct{}, ready chan<- gpuPipelineBatch) {
	defer close(ready)
	scratch := acquireCPUScratch()
	defer releaseCPUScratch(scratch)
	var slots [2]gpuPipelineSlot
	for seq := 0; ; seq++ {
		idx := seq % len(slots)
		select {
		case <-ctx.Done():
			return
		case <-abort:
			return
		case <-free[idx]:
		}
		batch := make([][]byte, 0, batchSize)
		closed := false
		aborted := false
	collect:
		for len(batch) < batchSize {
			select {
			case <-ctx.Done():
				return
			case <-abort:
				aborted = true
				break collect
			case pw, ok := <-ch:
				if !ok {
					closed = true
					break collect
				}
				batch = append(batch, pw)
			}
		}
		if len(batch) == 0 {
			return
		}
		result := gpuPipelineBatch{passwords: batch, slot: idx, closed: closed || aborted}
		if !aborted {
			stateLen := len(batch) * v.p * 1024
			slot := &slots[idx]
			if cap(slot.state) < stateLen {
				slot.state = make([]byte, stateLen)
			}
			result.state = slot.state[:stateLen]
			var transformed []byte
			if v.presalt != nil {
				need := len(batch) * presaltPassLen
				if cap(slot.transformed) < need {
					slot.transformed = make([]byte, need)
				}
				transformed = slot.transformed[:need]
			}
			checkCanceled := func() error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-abort:
					return fmt.Errorf("GPU prefetch interrupted")
				default:
					return nil
				}
			}
			result.passes, result.blocklen, result.err = gpuPrepareBatchIntoChecked(v, batch, result.state, transformed, prepThreads, scratch, checkCanceled)
		} else {
			// A GPU failure stopped prefetch. Return every dequeued candidate
			// to the consumer so it can retry them on the CPU.
			result.err = fmt.Errorf("GPU prefetch aborted")
		}
		select {
		case ready <- result:
		case <-ctx.Done():
			return
		}
		if result.closed || result.err != nil {
			return
		}
	}
}

// gpuWorkerPipelinedSingleVault overlaps CPU preparation for the next batch
// with the current batch's synchronous OpenCL execution. OpenCL still uses
// blocking transfers: Go-owned state is never retained across cgo calls.
// Multi-vault jobs use the existing worker, preserving its behavior.
func gpuWorkerPipelinedSingleVault(ctx context.Context, d gpuDevice, g *gpuBackend, batchSize, manualStep, prepThreads int, allowRuntimeFallback bool, ch <-chan []byte, v vault, processed *atomic.Uint64, emit emitFn, alreadyCracked func(int) bool) error {
	finalScratch := acquireCPUScratch()
	defer releaseCPUScratch(finalScratch)
	var free [2]chan struct{}
	for i := range free {
		free[i] = make(chan struct{}, 1)
		free[i] <- struct{}{}
	}
	ready := make(chan gpuPipelineBatch, 2)
	abort := make(chan struct{})
	go prepareGPUStream(ctx, abort, ch, v, batchSize, prepThreads, free, ready)
	stopped := false
	stopPrep := func() {
		if !stopped {
			close(abort)
			stopped = true
		}
	}
	defer func() {
		stopPrep()
		// Do not return while a preparation goroutine still owns a buffer.
		for range ready {
		}
	}()

	currentStep := manualStep
	if currentStep == 0 {
		currentStep = 4096
	}
	steps := [...]int{2048, 4096, 8192}
	trials := make(map[int]float64, len(steps))
	batches := 0
	for {
		var item gpuPipelineBatch
		select {
		case <-ctx.Done():
			return nil
		case next, ok := <-ready:
			if !ok {
				return nil
			}
			item = next
		}
		if ctx.Err() != nil {
			return nil
		}
		step := currentStep
		if manualStep == 0 && batches > 0 && batches <= len(steps) && len(item.passwords) >= batchSize/2 {
			step = steps[batches-1]
		}
		begin := time.Now()
		err := item.err
		if err == nil && !alreadyCracked(0) {
			err = g.romix(item.state, len(item.passwords)*v.p, step)
		}
		// The OpenCL call above may block after an interrupt; do not start
		// finalization for an abandoned batch once it returns.
		if ctx.Err() != nil {
			return nil
		}
		if err == nil && !alreadyCracked(0) {
			var derived [][]byte
			derived, err = gpuFinalizeBatch(v, item.passes, item.state, item.blocklen, finalScratch)
			if err == nil {
				for i, dk := range derived {
					if verifyMAC(v, dk) {
						emit(0, v, item.passwords[i], dk)
					}
				}
			}
		}
		if err != nil {
			gpuErr := fmt.Errorf("GPU %d vault 1: %w", d.id, err)
			stopPrep()
			if !allowRuntimeFallback {
				return gpuErr
			}
			log.Printf("%v; switching GPU %d worker to CPU for remaining candidates", gpuErr, d.id)
			g.close()
			if err := processBatchCPU(ctx, item.passwords, []vault{v}, processed, emit, alreadyCracked); err != nil {
				return fmt.Errorf("GPU %d CPU fallback: %w", d.id, err)
			}
			// The producer might have dequeued the next batch already. It
			// always publishes it before exiting, including partial batches.
			for pending := range ready {
				if err := processBatchCPU(ctx, pending.passwords, []vault{v}, processed, emit, alreadyCracked); err != nil {
					return fmt.Errorf("GPU %d CPU fallback: %w", d.id, err)
				}
			}
			return consumeCPU(ctx, ch, []vault{v}, 1, processed, emit, alreadyCracked)
		}
		elapsed := time.Since(begin).Seconds()
		if elapsed > 0 && manualStep == 0 && batches > 0 && batches <= len(steps) && len(item.passwords) >= batchSize/2 {
			rate := float64(len(item.passwords)) / elapsed
			trials[step] = rate
			if gpuVerbose {
				fmt.Fprintf(os.Stderr, "GPU %d auto-step trial: step=%d batch=%d rate=%.2f H/s\n", d.id, step, len(item.passwords), rate)
			}
			if len(trials) == len(steps) {
				bestStep, bestRate := 0, 0.0
				for s, r := range trials {
					if r > bestRate {
						bestStep, bestRate = s, r
					}
				}
				currentStep = bestStep
				if gpuVerbose {
					fmt.Fprintf(os.Stderr, "GPU %d auto-step selected %d (trial %.2f H/s)\n", d.id, bestStep, bestRate)
				}
			}
		}
		processed.Add(uint64(len(item.passwords)))
		batches++
		// Hand off the buffer only after the synchronous OpenCL readback,
		// final PBKDF2 and MAC verification have all completed.
		free[item.slot] <- struct{}{}
		if item.closed {
			return nil
		}
	}
}
