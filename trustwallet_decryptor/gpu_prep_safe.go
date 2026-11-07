package main

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

// gpuPrepareBatch fills the reusable synchronous OpenCL input buffer.
// A gpuBackend is owned by exactly one GPU worker: no overlapping calls are
// permitted. For presalted passwords, transformed bytes are retained in a
// separate backend-owned buffer until the final PBKDF2 is complete.
func gpuPrepareBatch(v vault, passwords [][]byte, g *gpuBackend, prepareThreads int, serialScratch *cpuWorkerScratch) ([][]byte, []byte, int, error) {
	B := g.batchStateBuffer(len(passwords) * v.p)
	var transformed []byte
	if v.presalt != nil {
		transformed = g.batchTransformedBuffer(len(passwords))
	}
	passes, blocklen, err := gpuPrepareBatchInto(v, passwords, B, transformed, prepareThreads, serialScratch)
	return passes, B, blocklen, err
}

// gpuPrepareBatchInto accepts independently owned staging buffers. This permits
// preparing a subsequent batch on the CPU while the previous batch executes
// synchronously in OpenCL, without sharing mutable slices between stages.
// The caller owns B and transformed until GPU finalization has completed.
func gpuPrepareBatchInto(v vault, passwords [][]byte, B, transformed []byte, prepareThreads int, serialScratch *cpuWorkerScratch) ([][]byte, int, error) {
	return gpuPrepareBatchIntoChecked(v, passwords, B, transformed, prepareThreads, serialScratch, nil)
}

// stop is checked between expensive CPU derivations, never in the middle of a
// cryptographic operation. A canceled prep still returns the original batch
// to its consumer, which owns the decision to fall back or terminate.
func gpuPrepareBatchIntoChecked(v vault, passwords [][]byte, B, transformed []byte, prepareThreads int, serialScratch *cpuWorkerScratch, stop func() error) ([][]byte, int, error) {
	blocklen := 128 * v.r * v.p
	if len(B) != len(passwords)*blocklen {
		return nil, 0, fmt.Errorf("GPU preparation buffer: expected %d bytes, got %d", len(passwords)*blocklen, len(B))
	}
	if v.presalt != nil && len(transformed) != len(passwords)*presaltPassLen {
		return nil, 0, fmt.Errorf("GPU transformed buffer: invalid size")
	}
	passes := make([][]byte, len(passwords))
	const passLen = presaltPassLen
	prepareCandidate := func(i int, scratch *cpuWorkerScratch) error {
		if stop != nil {
			if err := stop(); err != nil {
				return err
			}
		}
		pass, err := scratch.transformedPassword(v, passwords[i])
		if err != nil {
			return err
		}
		if v.presalt != nil {
			// Copy before the per-thread scratch is reused for the next item.
			dst := transformed[i*passLen : (i+1)*passLen]
			copy(dst, pass)
			pass = dst
		}
		passes[i] = pass
		off := i * blocklen
		return pbkdf2KeyInto(B[off:off+blocklen], pass, v.salt, 1, sha256.New, scratch.pbkdf2U[:], scratch.pbkdf2T[:])
	}
	if prepareThreads < 1 {
		prepareThreads = 1
	}
	if prepareThreads > len(passwords) {
		prepareThreads = len(passwords)
	}
	if v.presalt == nil {
		prepareThreads = 1
	}
	if prepareThreads <= 1 {
		for i := range passwords {
			if err := prepareCandidate(i, serialScratch); err != nil {
				return nil, 0, err
			}
		}
	} else {
		errs := make([]error, len(passwords))
		jobs := make(chan int)
		var wg sync.WaitGroup
		for worker := 0; worker < prepareThreads; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				scratch := acquireCPUScratch()
				defer releaseCPUScratch(scratch)
				for i := range jobs {
					errs[i] = prepareCandidate(i, scratch)
				}
			}()
		}
		for i := range passwords {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				return nil, 0, fmt.Errorf("prepare candidate %d: %w", i, err)
			}
		}
	}
	return passes, blocklen, nil
}

func gpuFinalizeBatch(v vault, passes [][]byte, B []byte, blocklen int, scratch *cpuWorkerScratch) ([][]byte, error) {
	derived := make([][]byte, len(passes))
	for i, pass := range passes {
		derived[i] = make([]byte, v.dklen)
		off := i * blocklen
		if err := pbkdf2KeyInto(derived[i], pass, B[off:off+blocklen], 1, sha256.New, scratch.pbkdf2U[:], scratch.pbkdf2T[:]); err != nil {
			return nil, err
		}
	}
	return derived, nil
}
