package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

func runCPU(ctx context.Context, scan candidateSource, vaults []vault, threads int, processed *atomic.Uint64, emit emitFn, alreadyCracked func(int) bool) error {
	ch := make(chan []byte, 1024)
	errCh := make(chan error, 1)
	go func() { errCh <- consumeCPU(ctx, ch, vaults, threads, processed, emit, alreadyCracked) }()
	var scanErr error
scanloop:
	for scan.Scan() {
		select {
		case ch <- decodedCandidate(bytes.Clone(scan.Bytes())):
		case <-ctx.Done():
			break scanloop
		}
	}
	if err := scan.Err(); err != nil {
		scanErr = err
	}
	close(ch)
	workerErr := <-errCh
	if scanErr != nil {
		return scanErr
	}
	return workerErr
}

// shared cpu worker for cpu and hybrid backends

func consumeCPU(ctx context.Context, ch <-chan []byte, vaults []vault, threads int, processed *atomic.Uint64, emit emitFn, alreadyCracked func(int) bool) error {
	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pw := range ch {
				if ctx.Err() != nil {
					return
				}
				for vi, v := range vaults {
					if alreadyCracked(vi) {
						continue
					}
					dk, err := cpuDerive(v, pw)
					if err != nil {
						errOnce.Do(func() { firstErr = err })
						continue
					}
					if verifyMAC(v, dk) {
						emit(vi, v, pw, dk)
					}
				}
				processed.Add(1)
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return nil
}

func runGPUs(ctx context.Context, stop context.CancelFunc, scan candidateSource, vaults []vault, devicesSpec string, memPercent, manualBatch, manualStep, cpuThreads int, allowRuntimeFallback bool, processed *atomic.Uint64, emit emitFn, alreadyCracked func(int) bool) error {
	for _, v := range vaults {
		if v.r != 8 || v.kdf != "scrypt" {
			return fmt.Errorf("%w: GPU requires scrypt r=8 (wallet r=%d)", errGPUInitialization, v.r)
		}
	}
	// one gpu allocation per worker with shared kdf parameters
	for _, v := range vaults[1:] {
		if v.n != vaults[0].n || v.p != vaults[0].p {
			return fmt.Errorf("%w: GPU multi-vault mode requires identical N,p, r=8; split vaults by KDF parameters", errGPUInitialization)
		}
	}
	detected, err := gpuDevices()
	if err != nil {
		return fmt.Errorf("%w: %v", errGPUInitialization, err)
	}
	selected, err := selectedDevices(detected, devicesSpec)
	if err != nil {
		return fmt.Errorf("%w: %v", errGPUInitialization, err)
	}
	if len(selected) == 0 {
		return fmt.Errorf("%w: no OpenCL GPUs detected", errGPUInitialization)
	}
	type worker struct {
		d     gpuDevice
		g     *gpuBackend
		batch int
	}
	workers := make([]worker, 0, len(selected))
	defer func() {
		for _, w := range workers {
			w.g.close()
		}
	}()
	n, p := vaults[0].n, vaults[0].p
	for _, d := range selected {
		batch := manualBatch
		if batch == 0 {
			batch = batchForDevice(d, n, 8, p, memPercent)
		}
		if batch < 1 {
			return fmt.Errorf("%w: GPU %d has insufficient usable memory for one password", errGPUInitialization, d.id)
		}
		// reduce gpu allocations on automatic fallback
		var g *gpuBackend
		var openErr error
		for attempt := 0; attempt < 10; attempt++ {
			g, openErr = openGPU(d.id, n, p, batch)
			if openErr == nil {
				break
			}
			if manualBatch != 0 || batch <= 1 {
				break
			}
			reduced := batch * 9 / 10
			if reduced == batch {
				reduced--
			}
			if gpuVerbose {
				fmt.Fprintf(os.Stderr, "GPU %d allocation failed at batch %d (%v); retrying batch %d\n", d.id, batch, openErr, reduced)
			}
			batch = reduced
		}
		if openErr != nil {
			return fmt.Errorf("%w: GPU %d initialization: %v", errGPUInitialization, d.id, openErr)
		}
		workers = append(workers, worker{d: d, g: g, batch: batch})
		targetPct := float64(uint64(n)*1024*uint64(p)*uint64(batch)) / float64(d.mem) * 100
		free := "unknown"
		if d.free > 0 {
			free = fmt.Sprintf("%.0f MiB", float64(d.free)/float64(MiB))
		}
		if gpuVerbose {
			fmt.Fprintf(os.Stderr, "GPU %d: %s; N=%d r=8 p=%d; total=%.0f MiB free=%s; batch=%d; scratch=%d MiB (%.1f%% VRAM); step=%s\n", d.id, d.name, n, p, float64(d.mem)/float64(MiB), free, batch, int(uint64(n)*1024*uint64(p)*uint64(batch)/MiB), targetPct, map[bool]string{true: "auto", false: strconv.Itoa(manualStep)}[manualStep == 0])
		}
	}
	candidateCh := make(chan []byte, 8192)
	errCh := make(chan error, len(workers)+1)
	var wg sync.WaitGroup
	for _, w := range workers {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := gpuWorker(ctx, w.d, w.g, w.batch, manualStep, allowRuntimeFallback, candidateCh, vaults, processed, emit, alreadyCracked); err != nil {
				select {
				case errCh <- err:
				default:
				}
				stop()
			}
		}()
	}
	// hybrid workers share a single candidate queue
	if cpuThreads > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := consumeCPU(ctx, candidateCh, vaults, cpuThreads, processed, emit, alreadyCracked); err != nil {
				select {
				case errCh <- err:
				default:
				}
				stop()
			}
		}()
	}
	var scanErr error
scanloop:
	for scan.Scan() {
		select {
		case candidateCh <- decodedCandidate(bytes.Clone(scan.Bytes())):
		case <-ctx.Done():
			break scanloop
		}
	}
	if err := scan.Err(); err != nil {
		scanErr = err
	}
	close(candidateCh)
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
	}
	if scanErr != nil {
		return scanErr
	}
	return nil
}

// retry failed gpu batches on cpu

func processBatchCPU(ctx context.Context, batch [][]byte, vaults []vault, processed *atomic.Uint64, emit emitFn, alreadyCracked func(int) bool) error {
	for _, pw := range batch {
		if err := ctx.Err(); err != nil {
			return nil
		}
		for vi, v := range vaults {
			if alreadyCracked(vi) {
				continue
			}
			dk, err := cpuDerive(v, pw)
			if err != nil {
				return err
			}
			if verifyMAC(v, dk) {
				emit(vi, v, pw, dk)
			}
		}
		processed.Add(1)
	}
	return nil
}

func gpuWorker(ctx context.Context, d gpuDevice, g *gpuBackend, batchSize, manualStep int, allowRuntimeFallback bool, ch <-chan []byte, vaults []vault, processed *atomic.Uint64, emit emitFn, alreadyCracked func(int) bool) error {
	currentStep := manualStep
	if currentStep == 0 {
		currentStep = 4096
	}
	samples := []int{2048, 4096, 8192}
	trials := make(map[int]float64, len(samples))
	batches := 0
	for {
		batch := make([][]byte, 0, batchSize)
		closed := false
		// allow smaller final gpu batches
	collect:
		for len(batch) < batchSize {
			select {
			case <-ctx.Done():
				return nil
			case pw, ok := <-ch:
				if !ok {
					closed = true
					break collect
				}
				batch = append(batch, pw)
			}
		}
		if len(batch) == 0 {
			return nil
		}
		step := currentStep
		if manualStep == 0 && batches > 0 && batches <= len(samples) && len(batch) >= batchSize/2 {
			step = samples[batches-1]
		}
		begin := time.Now()
		for vi, v := range vaults {
			if alreadyCracked(vi) {
				continue
			}
			dkList, err := gpuDeriveBatch(v, batch, g, step)
			if err != nil {
				gpuErr := fmt.Errorf("GPU %d vault %d: %w", d.id, vi+1, err)
				if !allowRuntimeFallback {
					return gpuErr
				}
				// retry failed gpu batch before dequeuing more candidates
				log.Printf("%v; switching GPU %d worker to CPU for remaining candidates", gpuErr, d.id)
				g.close()
				if err := processBatchCPU(ctx, batch, vaults, processed, emit, alreadyCracked); err != nil {
					return fmt.Errorf("GPU %d CPU fallback: %w", d.id, err)
				}
				return consumeCPU(ctx, ch, vaults, 1, processed, emit, alreadyCracked)
			}
			for i, dk := range dkList {
				if verifyMAC(v, dk) {
					emit(vi, v, batch[i], dk)
				}
			}
		}
		elapsed := time.Since(begin).Seconds()
		if elapsed > 0 && manualStep == 0 && batches > 0 && batches <= len(samples) && len(batch) >= batchSize/2 {
			rate := float64(len(batch)) / elapsed
			trials[step] = rate
			if gpuVerbose {
				fmt.Fprintf(os.Stderr, "GPU %d auto-step trial: step=%d batch=%d rate=%.2f H/s\n", d.id, step, len(batch), rate)
			}
			if len(trials) == len(samples) {
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
		processed.Add(uint64(len(batch)))
		batches++
		if closed {
			return nil
		}
	}
}
