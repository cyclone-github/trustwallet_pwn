package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// Verify the CPU producer uses two independent staging buffers, returns
// candidates in order, and never overwrites a slot until its consumer releases
// it. All cryptographic preparation here is independent of OpenCL.
func TestPrepareGPUStreamTwoSlotOwnership(t *testing.T) {
	v := vault{kdf: "scrypt", n: 16, r: 8, p: 1, salt: []byte("example-salt"), dklen: 32}
	ch := make(chan []byte, 5)
	for _, candidate := range []string{"first", "second", "third", "fourth", "fifth"} {
		ch <- []byte(candidate)
	}
	close(ch)
	var free [2]chan struct{}
	for i := range free {
		free[i] = make(chan struct{}, 1)
		free[i] <- struct{}{}
	}
	ready := make(chan gpuPipelineBatch, 2)
	abort := make(chan struct{})
	go prepareGPUStream(context.Background(), abort, ch, v, 2, 1, free, ready)
	first := <-ready
	second := <-ready
	if first.err != nil || second.err != nil || first.slot != 0 || second.slot != 1 {
		t.Fatalf("invalid producer results: %#v %#v", first.err, second.err)
	}
	if len(first.passwords) != 2 || len(second.passwords) != 2 {
		t.Fatalf("unexpected batches: %d, %d", len(first.passwords), len(second.passwords))
	}
	if &first.state[0] == &second.state[0] {
		t.Fatal("in-flight batches share mutable state memory")
	}
	original := bytes.Clone(first.state)
	// Producer cannot proceed with batch 3 until slot 0 is released.
	select {
	case <-ready:
		t.Fatal("producer reused an in-flight buffer")
	case <-time.After(10 * time.Millisecond):
	}
	if !bytes.Equal(first.state, original) {
		t.Fatal("first state changed before release")
	}
	for i, pw := range first.passwords {
		want := make([]byte, first.blocklen)
		scratch := newCPUWorkerScratch()
		if err := pbkdf2KeyInto(want, pw, v.salt, 1, sha256.New, scratch.pbkdf2U[:], scratch.pbkdf2T[:]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, first.state[i*first.blocklen:(i+1)*first.blocklen]) {
			t.Fatalf("wrong initial state at index %d", i)
		}
	}
	free[0] <- struct{}{}
	third := <-ready
	if third.slot != 0 || len(third.passwords) != 1 || string(third.passwords[0]) != "fifth" || !third.closed {
		t.Fatalf("unexpected final batch: %+v", third)
	}
	free[1] <- struct{}{}
	free[0] <- struct{}{}
	for range ready {
	}
}

func TestPrepareGPUStreamAbortKeepsDequeuedCandidates(t *testing.T) {
	v := vault{kdf: "scrypt", n: 16, r: 8, p: 1, salt: []byte("salt"), dklen: 32}
	ch := make(chan []byte, 1)
	ch <- []byte("pending")
	var free [2]chan struct{}
	for i := range free {
		free[i] = make(chan struct{}, 1)
		free[i] <- struct{}{}
	}
	ready := make(chan gpuPipelineBatch, 2)
	abort := make(chan struct{})
	go prepareGPUStream(context.Background(), abort, ch, v, 4, 1, free, ready)
	deadline := time.After(time.Second)
	for len(ch) != 0 {
		select {
		case <-deadline:
			t.Fatal("producer did not consume queued candidate")
		default:
		}
	}
	close(abort)
	select {
	case result, ok := <-ready:
		if !ok || len(result.passwords) != 1 || string(result.passwords[0]) != "pending" {
			t.Fatalf("prefetched candidate was lost on abort: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("producer failed to stop")
	}
	for range ready {
	}
}

// The staged preparation plus the unchanged, CPU-reference ROMix and final
// PBKDF2 stages must match independently generated hashlib.scrypt vectors.
// This does not require an OpenCL device and exercises both preprocessing modes.
func TestGPUPreparedStageReferenceVectors(t *testing.T) {
	vectors := []struct {
		name, pass, want string
		p                int
		presalt          []byte
	}{
		{"standard-alpha", "alpha", "0410b29bf0bc7c9acab9e5f1a817ddf14d0f1d6a217bc6fe9926c8299822654a", 1, nil},
		{"standard-beta", "beta", "1afa402a222039eee8dbf88b34172c6db3dbb64bdc38f3733bd03483959a4e61", 1, nil},
		{"presalt-alpha", "alpha", "f54525a26f449c7ff180316c59a835a00783f295c2eec71ca176afcf220a33d9", 1, []byte("presalt-example")},
		{"presalt-beta", "beta", "ef74f27193d6de965f3a299da9edc80117ef9bb413c47fed19e5660a21621bf8", 1, []byte("presalt-example")},
		{"p4-standard-alpha", "alpha", "01050e133a45bbb54bef4ec3f82a4ae0fa691ecbce0d6414733b03242409d57a", 4, nil},
		{"p4-presalt-alpha", "alpha", "7d3f68363a87dca85f4978bddb392fa497eb989eb21447f31647a51f48c4841f", 4, []byte("presalt-example")},
	}
	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			v := vault{kdf: "scrypt", n: 16, r: 8, p: tc.p, salt: []byte("benchmark-salt"), dklen: 32, presalt: tc.presalt}
			state := make([]byte, v.p*128*v.r)
			var transformed []byte
			if v.presalt != nil {
				transformed = make([]byte, presaltPassLen)
			}
			prepScratch := newCPUWorkerScratch()
			passes, blocklen, err := gpuPrepareBatchInto(v, [][]byte{[]byte(tc.pass)}, state, transformed, 1, prepScratch)
			if err != nil {
				t.Fatal(err)
			}
			romixScratch := newCPUWorkerScratch()
			if err := romixScratch.scrypt.reset(v.n, v.r, v.p); err != nil {
				t.Fatal(err)
			}
			for lane := 0; lane < v.p; lane++ {
				start := lane * 128 * v.r
				scryptSmix(state[start:start+128*v.r], v.r, v.n, romixScratch.scrypt.v, romixScratch.scrypt.xy)
			}
			keys, err := gpuFinalizeBatch(v, passes, state, blocklen, prepScratch)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(keys[0]); got != tc.want {
				t.Fatalf("staged KDF mismatch: got %s, want %s", got, tc.want)
			}
		})
	}
}
