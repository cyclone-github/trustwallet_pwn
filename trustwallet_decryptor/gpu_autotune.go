package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Keep GPU tuning profiles tied to the application release. A new release
// must change this ID when the kernel, bridge or tuning methodology changes.
const autoTuneRevision = "tw-gpu-autotune-v0.3.8"

type gpuTuneChoice struct {
	Batch     int     `json:"batch"`
	Workgroup int     `json:"workgroup"`
	Rate      float64 `json:"hashes_per_second"`
}

type gpuTuneCache struct {
	Revision    string        `json:"revision"`
	Fingerprint string        `json:"fingerprint"`
	GPUName     string        `json:"gpu_name,omitempty"`  // Display only; not part of cache matching.
	HashType    string        `json:"hash_type,omitempty"` // Display only; canonical workload remains authoritative.
	Workload    string        `json:"workload"`
	Choice      gpuTuneChoice `json:"choice"`
}

// Human-readable labels for cache inspection. These never replace the existing
// fingerprint/workload checks, and contain no wallet-specific material.
func gpuTuneHashType(workload string) string {
	switch {
	case strings.Contains(workload, ";"):
		return "mixed wallet types"
	case strings.Contains(workload, "pre=trust:pbkdf2"):
		return "trust:pbkdf2 (desktop)"
	case strings.Contains(workload, "pre=none"):
		return "standard scrypt (iOS-compatible)"
	default:
		return "other"
	}
}

// gpuTuneWorkload describes the cryptographic work without including wallet
// secrets, salt, ciphertext, wordlist or file path. It is stable across wallets
// of the same kind and parameters, and independent of vault order/count.
// Mixed standard and trust:pbkdf2 vaults get a separate profile.
func gpuTuneWorkload(vaults []vault) string {
	kinds := make(map[string]struct{}, len(vaults))
	for _, v := range vaults {
		pre := "none"
		if v.presalt != nil {
			pre = "trust:pbkdf2-sha512-i20000"
		}
		kind := fmt.Sprintf("%s|N=%d|r=%d|p=%d|dklen=%d|pre=%s", v.kdf, v.n, v.r, v.p, v.dklen, pre)
		kinds[kind] = struct{}{}
	}
	parts := make([]string, 0, len(kinds))
	for kind := range kinds {
		parts = append(parts, kind)
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// A batch must not exceed the currently selected memory limit, even when a
// cached calibration was produced with more available VRAM.
func validTuneChoice(c gpuTuneChoice, maxBatch, n, p int) bool {
	if c.Batch < 1 || c.Batch > maxBatch || c.Workgroup < 0 || c.Rate <= 0 || math.IsNaN(c.Rate) || math.IsInf(c.Rate, 0) {
		return false
	}
	if c.Workgroup > 0 && (c.Batch*p)%c.Workgroup != 0 {
		return false
	}
	return n >= 2 && p >= 1
}

// Identical GPUs on this host share a profile regardless of OpenCL index.
// Driver, reported VRAM, and allocation capabilities remain part of identity.
func gpuModelKey(d gpuDevice) string {
	value := fmt.Sprintf("%s|%s|%s|%s|%d|%d|%d", autoTuneRevision,
		runtime.GOOS, d.name, d.driver, d.mem, d.maxAlloc, d.computeUnits)
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

func gpuTuneKey(d gpuDevice, workload string, n, p, memoryPercent, forcedBatch, forcedWorkgroup, step int) string {
	value := fmt.Sprintf("%s|%s|%d|%d|%d|%d|%d|%d", gpuModelKey(d), workload,
		n, p, memoryPercent, forcedBatch, forcedWorkgroup, step)
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

func gpuTuneCachePath(key string) (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "trustwallet_pwn", "gpu-tune-"+key+".json"), nil
}

func loadGPUTune(gpuName, key, workload string, maxBatch, n, p int) (gpuTuneChoice, bool) {
	path, err := gpuTuneCachePath(key)
	if err != nil {
		return gpuTuneChoice{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return gpuTuneChoice{}, false
	}
	var entry gpuTuneCache
	if json.Unmarshal(data, &entry) != nil || entry.Revision != autoTuneRevision || entry.Fingerprint != key || entry.Workload != workload || !validTuneChoice(entry.Choice, maxBatch, n, p) {
		return gpuTuneChoice{}, false
	}
	// Annotate older entries on first use without changing the tuning decision.
	// The fingerprint, rather than these display fields, controls cache validity.
	if entry.GPUName == "" || entry.HashType == "" {
		entry.GPUName = gpuName
		entry.HashType = gpuTuneHashType(workload)
		if contents, err := json.MarshalIndent(entry, "", "  "); err == nil {
			writeTuneFile(path, append(contents, '\n'))
		}
	}
	return entry.Choice, true
}

func saveGPUTune(gpuName, key, workload string, choice gpuTuneChoice) {
	path, err := gpuTuneCachePath(key)
	if err != nil || os.MkdirAll(filepath.Dir(path), 0700) != nil {
		return
	}
	contents, err := json.MarshalIndent(gpuTuneCache{
		Revision: autoTuneRevision, Fingerprint: key, GPUName: gpuName,
		HashType: gpuTuneHashType(workload), Workload: workload, Choice: choice,
	}, "", "  ")
	if err == nil {
		writeTuneFile(path, append(contents, '\n'))
	}
}

func writeTuneFile(path string, contents []byte) {
	f, err := os.CreateTemp(filepath.Dir(path), ".gpu-tune-*")
	if err != nil {
		return
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(contents); err != nil {
		f.Close()
		return
	}
	if err = f.Close(); err != nil {
		return
	}
	// Concurrent processes may tune independently; atomic rename avoids partial JSON.
	_ = os.Rename(f.Name(), path)
}

func roundBatch(batch, p, workgroup int) int {
	if workgroup > 0 {
		alignment := workgroup / gcdInt(workgroup, p)
		batch -= batch % alignment
	}
	return batch
}

// Include broad memory usage in the search; the benchmark results showed that
// maximum VRAM usage is not necessarily the fastest configuration.
func tuneBatchCandidates(maxBatch, forcedBatch int) []int {
	if forcedBatch > 0 {
		return []int{forcedBatch}
	}
	seen := make(map[int]bool)
	var out []int
	for _, fraction := range []float64{0.70, 0.90, 1.0} {
		b := int(float64(maxBatch) * fraction)
		if b < 1 {
			b = 1
		}
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	sort.Ints(out)
	return out
}

func tuneWorkgroupCandidates(forced int) []int {
	if forced >= 0 {
		return []int{forced}
	}
	// Keep the useful smaller workgroups found on RTX 4090/5090, with
	// WG 32/64 and driver selection (0) for other GPU architectures.
	// Explicit -gpu-workgroup can still select excluded extremes.
	return []int{4, 8, 16, 32, 64, 0}
}

func benchmarkGPUChoice(deviceID, n, p, batch, workgroup, step int) (float64, error) {
	gpu, err := openGPUWorkgroup(deviceID, n, p, batch, workgroup)
	if err != nil {
		return 0, err
	}
	defer gpu.close()
	lanes := batch * p
	state := make([]byte, lanes*1024)
	// Use differing deterministic input for each lane, independent of wallet data.
	for i := range state {
		x := uint32(i)*2654435761 + uint32(i>>10)*2246822519
		state[i] = byte(x >> 16)
	}
	if step <= 0 {
		step = 4096
	}
	// Warmup plus two samples to limit tuning cost for cluster chunk workers.
	if err := gpu.romix(state, lanes, step); err != nil {
		return 0, err
	}
	start := time.Now()
	if err := gpu.romix(state, lanes, step); err != nil {
		return 0, err
	}
	if err := gpu.romix(state, lanes, step); err != nil {
		return 0, err
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0, fmt.Errorf("invalid ROMix benchmark time")
	}
	return float64(2*batch) / elapsed, nil
}

// selectGPUTuning uses exact hardware, KDF-parameter and wallet-type profiles.
// Preprocessing affects the cache identity even though the ROMix microbenchmark
// does not measure it. Manual values stay authoritative.
func selectGPUTuning(d gpuDevice, workload string, n, p, memPercent, forcedBatch, forcedWorkgroup, step int) (gpuTuneChoice, string, error) {
	maxBatch := batchForDevice(d, n, 8, p, memPercent)
	if maxBatch < 1 {
		return gpuTuneChoice{}, "", fmt.Errorf("insufficient GPU scratch memory")
	}
	if forcedBatch > 0 && forcedBatch > maxBatch {
		return gpuTuneChoice{}, "", fmt.Errorf("-gpu-batch %d exceeds memory budget (%d candidates)", forcedBatch, maxBatch)
	}
	key := gpuTuneKey(d, workload, n, p, memPercent, forcedBatch, forcedWorkgroup, step)
	if choice, ok := loadGPUTune(d.name, key, workload, maxBatch, n, p); ok {
		return choice, "cache", nil
	}
	candidates := tuneBatchCandidates(maxBatch, forcedBatch)
	workgroups := tuneWorkgroupCandidates(forcedWorkgroup)
	best := gpuTuneChoice{}
	for _, b := range candidates {
		for _, wg := range workgroups {
			batch := roundBatch(b, p, wg)
			// A manually requested batch size is an override, not a hint.
			if forcedBatch > 0 && batch != b {
				continue
			}
			if batch < 1 || (wg > 0 && (batch*p)%wg != 0) {
				continue
			}
			rate, err := benchmarkGPUChoice(d.id, n, p, batch, wg, step)
			if err != nil {
				if gpuVerbose {
					fmt.Fprintf(os.Stderr, "GPU %d auto-tune skipped batch=%d workgroup=%d: %v\n", d.id, batch, wg, err)
				}
				continue
			}
			if gpuVerbose {
				fmt.Fprintf(os.Stderr, "GPU %d auto-tune: batch=%d workgroup=%d ROMix=%.2f candidates/s\n", d.id, batch, wg, rate)
			}
			if rate > best.Rate || (rate >= best.Rate*0.995 && (best.Batch == 0 || batch < best.Batch)) {
				best = gpuTuneChoice{Batch: batch, Workgroup: wg, Rate: rate}
			}
		}
	}
	if best.Batch == 0 {
		if forcedWorkgroup > 0 || forcedBatch > 0 {
			return best, "", fmt.Errorf("no usable GPU configuration for requested overrides")
		}
		// Safe fallback: the original memory-based automatic configuration.
		return gpuTuneChoice{Batch: maxBatch, Workgroup: 0, Rate: 1}, "fallback", nil
	}
	saveGPUTune(d.name, key, workload, best)
	return best, "benchmark", nil
}
