package main

import (
	"context"
	"sync/atomic"
	"testing"
)

// A canceled run must not begin another expensive KDF, even if candidates
// remain buffered in the worker queue.
func TestCanceledCPUWorkersSkipQueuedCandidates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	candidates := make(chan []byte, 4)
	for i := 0; i < cap(candidates); i++ {
		candidates <- []byte("unused")
	}
	close(candidates)
	var processed atomic.Uint64
	emit := func(int, vault, []byte, []byte) {
		t.Fatal("unexpected result after cancellation")
	}
	if err := consumeCPU(ctx, candidates, []vault{{}}, 4, &processed, emit, func(int) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if got := processed.Load(); got != 0 {
		t.Fatalf("processed %d candidates after cancellation", got)
	}
}

func TestCanceledGPUFallbackSkipsRemainingBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var processed atomic.Uint64
	emit := func(int, vault, []byte, []byte) {
		t.Fatal("unexpected result after cancellation")
	}
	if err := processBatchCPU(ctx, [][]byte{[]byte("unused")}, []vault{{}}, &processed, emit, func(int) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if processed.Load() != 0 {
		t.Fatal("processed a canceled batch")
	}
}
