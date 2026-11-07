package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testGPUProfile(pre bool, n, r, p, dklen int) string {
	v := vault{kdf: "scrypt", n: n, r: r, p: p, dklen: dklen}
	if pre {
		v.presalt = []byte{1, 2, 3}
	}
	return gpuTuneWorkload([]vault{v})
}

func TestTuneWorkloadProfiles(t *testing.T) {
	ios := testGPUProfile(false, 16384, 8, 4, 32)
	desktop := testGPUProfile(true, 16384, 8, 4, 32)
	if ios == desktop || !strings.Contains(desktop, "trust:pbkdf2") {
		t.Fatalf("preprocessing modes must differ: standard=%q desktop=%q", ios, desktop)
	}
	if ios != gpuTuneWorkload([]vault{
		{kdf: "scrypt", n: 16384, r: 8, p: 4, dklen: 32, salt: []byte("salt A")},
		{kdf: "scrypt", n: 16384, r: 8, p: 4, dklen: 32, salt: []byte("salt B")},
	}) {
		t.Fatal("different salts or repeated same-type wallets must share one profile")
	}
	for _, tc := range []struct{ n, r, p, dklen int }{
		{8192, 8, 4, 32}, {16384, 8, 1, 32}, {16384, 4, 4, 32}, {16384, 8, 4, 64},
	} {
		if ios == testGPUProfile(false, tc.n, tc.r, tc.p, tc.dklen) {
			t.Fatalf("different KDF parameters collided: %+v", tc)
		}
	}
	mixed := gpuTuneWorkload([]vault{
		{kdf: "scrypt", n: 16384, r: 8, p: 4, dklen: 32},
		{kdf: "scrypt", n: 16384, r: 8, p: 4, dklen: 32, presalt: []byte{9}},
	})
	reverse := gpuTuneWorkload([]vault{
		{kdf: "scrypt", n: 16384, r: 8, p: 4, dklen: 32, presalt: []byte{7}},
		{kdf: "scrypt", n: 16384, r: 8, p: 4, dklen: 32},
	})
	if mixed == ios || mixed == desktop || mixed != reverse {
		t.Fatalf("mixed wallet profiles must be distinct and order-independent: %q / %q", mixed, reverse)
	}
}

func TestTuneBatchCandidates(t *testing.T) {
	got := tuneBatchCandidates(320, 0)
	if len(got) != 3 || got[0] != 224 || got[1] != 288 || got[2] != 320 {
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
	ios := testGPUProfile(false, 16384, 8, 4, 32)
	desktop := testGPUProfile(true, 16384, 8, 4, 32)
	k := gpuTuneKey(d, ios, 16384, 4, 90, 0, -1, 4096)
	if _, ok := loadGPUTune(d.name, k, ios, 330, 16384, 4); ok {
		t.Fatal("cache unexpectedly populated")
	}
	value := gpuTuneChoice{Batch: 328, Workgroup: 32, Rate: 1234.5}
	saveGPUTune(d.name, k, ios, value)
	got, ok := loadGPUTune(d.name, k, ios, 330, 16384, 4)
	if !ok || got != value {
		t.Fatalf("cache got=%+v ok=%t", got, ok)
	}
	if _, ok := loadGPUTune(d.name, k, desktop, 330, 16384, 4); ok {
		t.Fatal("other wallet type reused the cache")
	}
	if _, ok := loadGPUTune(d.name, k, ios, 300, 16384, 4); ok {
		t.Fatal("oversized cached batch reused")
	}
	if k == gpuTuneKey(d, desktop, 16384, 4, 90, 0, -1, 4096) ||
		k == gpuTuneKey(d, ios, 16384, 1, 90, 0, -1, 4096) ||
		k == gpuTuneKey(d, ios, 16384, 4, 90, 0, -1, 8192) ||
		k == gpuTuneKey(d, ios, 16384, 4, 80, 0, -1, 4096) {
		t.Fatal("different tuning profile collided")
	}
	path, _ := gpuTuneCachePath(k)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) == "" || len(b) == 0 || !strings.Contains(string(b), `"workload"`) {
		t.Fatal("cache file invalid or missing workload identity")
	}
	var entry gpuTuneCache
	if err := json.Unmarshal(b, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.GPUName != d.name || entry.HashType != "standard scrypt (iOS-compatible)" || !strings.Contains(string(b), "\n  ") {
		t.Fatalf("missing readable cache labels: %s", b)
	}
	if gpuTuneHashType(desktop) != "trust:pbkdf2 (desktop)" {
		t.Fatal("wrong desktop hash type label")
	}
}

func TestTuneSharedIdenticalGPUsAndDistinctWorkloads(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	d0 := gpuDevice{id: 0, name: "RTX 4090", driver: "123.45", mem: 24 * 1024 * MiB, maxAlloc: 6 * 1024 * MiB, computeUnits: 128}
	d1 := d0
	d1.id = 1
	ios := testGPUProfile(false, 16384, 8, 4, 32)
	desktop := testGPUProfile(true, 16384, 8, 4, 32)
	k0 := gpuTuneKey(d0, ios, 16384, 4, 92, 0, -1, 0)
	k1 := gpuTuneKey(d1, ios, 16384, 4, 92, 0, -1, 0)
	if k0 != k1 || gpuModelKey(d0) != gpuModelKey(d1) {
		t.Fatal("identical GPUs should share tuning cache, independent of device ID")
	}
	choice := gpuTuneChoice{Batch: 320, Workgroup: 8, Rate: 1100}
	saveGPUTune(d0.name, k0, ios, choice)
	if got, ok := loadGPUTune(d1.name, k1, ios, 320, 16384, 4); !ok || got != choice {
		t.Fatalf("identical GPU cache miss: %+v %v", got, ok)
	}
	if _, ok := loadGPUTune(d1.name, gpuTuneKey(d1, desktop, 16384, 4, 92, 0, -1, 0), desktop, 320, 16384, 4); ok {
		t.Fatal("desktop wallet incorrectly reused iOS profile")
	}
	if _, ok := loadGPUTune(d1.name, gpuTuneKey(d1, ios, 8192, 1, 92, 0, -1, 0), ios, 320, 8192, 1); ok {
		t.Fatal("different scrypt parameters reused tuning profile")
	}
	other := d1
	other.driver = "124.00"
	if gpuModelKey(d0) == gpuModelKey(other) {
		t.Fatal("driver version should separate profiles")
	}
}

func TestTuneCandidateRanges(t *testing.T) {
	got := tuneWorkgroupCandidates(-1)
	want := []int{4, 8, 16, 32, 64, 0}
	if len(got) != len(want) {
		t.Fatalf("workgroups: %v", got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("workgroups: %v", got)
		}
	}
	if w := tuneWorkgroupCandidates(2); len(w) != 1 || w[0] != 2 {
		t.Fatal("manual workgroup override lost")
	}
}

func TestTuneRevisionMatchesProgramVersion(t *testing.T) {
	want := "tw-gpu-autotune-" + strings.TrimSuffix(version, "-dev")
	if autoTuneRevision != want {
		t.Fatalf("tune cache revision %q must track version %q", autoTuneRevision, version)
	}
}

func TestSelectGPUTuningUsesExactSharedCacheWithoutOpenCL(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	d := gpuDevice{id: 0, name: "RTX 4090", driver: "123.45", mem: 24 * 1024 * MiB, maxAlloc: 6 * 1024 * MiB, computeUnits: 128}
	ios := testGPUProfile(false, 16384, 8, 4, 32)
	desktop := testGPUProfile(true, 16384, 8, 4, 32)
	maxBatch := batchForDevice(d, 16384, 8, 4, 90)
	choice := gpuTuneChoice{Batch: roundBatch(maxBatch, 4, 8), Workgroup: 8, Rate: 1100}
	saveGPUTune(d.name, gpuTuneKey(d, ios, 16384, 4, 90, 0, -1, 0), ios, choice)
	d.id = 1
	got, source, err := selectGPUTuning(d, ios, 16384, 4, 90, 0, -1, 0)
	if err != nil || source != "cache" || got != choice {
		t.Fatalf("exact GPU cache not reused: %+v %s %v", got, source, err)
	}
	// Different workload has no cache entry. Only validate that it has a
	// distinct key here; exercising a miss would require a real OpenCL GPU.
	if k := gpuTuneKey(d, desktop, 16384, 4, 90, 0, -1, 0); k == gpuTuneKey(d, ios, 16384, 4, 90, 0, -1, 0) {
		t.Fatal("wallet-specific cache keys collided")
	}
}

func TestTuneCacheAnnotatesLegacyEntriesWithoutRetuning(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	d := gpuDevice{id: 0, name: "NVIDIA RTX 4090", driver: "test-driver", mem: 24 * 1024 * MiB, maxAlloc: 6 * 1024 * MiB, computeUnits: 128}
	workload := testGPUProfile(true, 16384, 8, 4, 32)
	key := gpuTuneKey(d, workload, 16384, 4, 90, 0, -1, 4096)
	path, err := gpuTuneCachePath(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	choice := gpuTuneChoice{Batch: 320, Workgroup: 8, Rate: 1234}
	legacy, err := json.Marshal(gpuTuneCache{Revision: autoTuneRevision, Fingerprint: key, Workload: workload, Choice: choice})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	got, ok := loadGPUTune(d.name, key, workload, 320, 16384, 4)
	if !ok || got != choice {
		t.Fatalf("legacy cache changed or invalidated: %+v ok=%t", got, ok)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var annotated gpuTuneCache
	if err := json.Unmarshal(data, &annotated); err != nil {
		t.Fatal(err)
	}
	if annotated.GPUName != d.name || annotated.HashType != "trust:pbkdf2 (desktop)" || annotated.Choice != choice || annotated.Fingerprint != key {
		t.Fatalf("legacy annotation failed: %+v", annotated)
	}
}
