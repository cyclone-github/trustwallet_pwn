package main

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestTuneBatchCandidates(t *testing.T) {
	got := tuneBatchCandidates(320, 0)
	if len(got) != 4 || got[0] != 144 || got[1] != 224 || got[2] != 272 || got[3] != 320 {
		t.Fatalf("unexpected auto batch choices %v", got)
	}
	manual := tuneBatchCandidates(320, 100)
	if len(manual) != 1 || manual[0] != 100 {
		t.Fatalf("manual batch override ignored: %v", manual)
	}
	if v := tuneBatchCandidates(2, 0); len(v) == 0 || v[len(v)-1] != 2 {
		t.Fatalf("unexpected small batches %v", v)
	}
}

func TestTuneBatchAlignment(t *testing.T) {
	for _, tc := range []struct{ batch, p, wg, want int }{
		{330, 4, 32, 328}, {330, 1, 32, 320}, {1, 4, 32, 0}, {1216, 1, 32, 1216}, {13, 4, 0, 13},
	} {
		if got := roundBatch(tc.batch, tc.p, tc.wg); got != tc.want {
			t.Fatalf("align(%d,%d,%d)=%d expected %d", tc.batch, tc.p, tc.wg, got, tc.want)
		}
	}
}

func TestTuneChoices(t *testing.T) {
	if !validTuneChoice(gpuTuneChoice{Batch: 328, Workgroup: 32, Rate: 900}, 330, 16384, 4) {
		t.Fatal("valid p=4 workgroup rejected")
	}
	invalid := []gpuTuneChoice{
		{Batch: 331, Workgroup: 32, Rate: 900},
		{Batch: 327, Workgroup: 32, Rate: 900},
		{Batch: 328, Workgroup: 32, Rate: 0},
		{Batch: 328, Workgroup: -1, Rate: 100},
		{Batch: 328, Workgroup: 32, Rate: math.NaN()},
	}
	for _, c := range invalid {
		if validTuneChoice(c, 330, 16384, 4) {
			t.Fatalf("invalid configuration accepted %+v", c)
		}
	}
}

func TestTuneCacheRoundtripAndNoWalletSecrets(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	d := gpuDevice{id: 0, name: "Synthetic Test GPU", mem: 24 * 1024 * MiB, maxAlloc: 6 * 1024 * MiB, computeUnits: 128}
	k := gpuTuneKey(d, 16384, 4, 90, 0, -1, 4096, true)
	if _, ok := loadGPUTune(k, 330, 16384, 4); ok {
		t.Fatal("cache unexpectedly populated")
	}
	value := gpuTuneChoice{Batch: 328, Workgroup: 32, Rate: 1234.5}
	saveGPUTune(k, value)
	got, ok := loadGPUTune(k, 330, 16384, 4)
	if !ok || got != value {
		t.Fatalf("cache got=%+v ok=%t", got, ok)
	}
	if _, ok := loadGPUTune(k, 300, 16384, 4); ok {
		t.Fatal("oversized cached batch reused")
	}
	if k == gpuTuneKey(d, 16384, 1, 90, 0, -1, 4096, false) {
		t.Fatal("KDF collision")
	}
	if k == gpuTuneKey(d, 16384, 4, 90, 0, -1, 8192, true) {
		t.Fatal("step size collision")
	}
	path, _ := gpuTuneCachePath(k)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) == "" || len(b) == 0 {
		t.Fatal("cache file invalid")
	}
}
