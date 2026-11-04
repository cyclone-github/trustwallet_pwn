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
	"time"
)

// autoTuneRevision must change when the ROMix kernel, bridge, or tuning
// methodology changes, because the cache is deliberately per device/KDF.
const autoTuneRevision = "tw-gpu-autotune-v1-20261103"

type gpuTuneChoice struct {
	Batch     int     `json:"batch"`
	Workgroup int     `json:"workgroup"`
	Rate      float64 `json:"hashes_per_second"`
}

type gpuTuneCache struct {
	Revision    string        `json:"revision"`
	Fingerprint string        `json:"fingerprint"`
	Choice      gpuTuneChoice `json:"choice"`
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

func gpuTuneKey(d gpuDevice, n, p, memoryPercent, forcedBatch, forcedWorkgroup, step int, hasPreprocess bool) string {
	// No salt, ciphertext, candidate or password is stored in this fingerprint.
	value := fmt.Sprintf("%s|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%t|%s", autoTuneRevision,
		runtime.GOOS, d.name+"@"+d.driver, d.id, d.mem, d.maxAlloc, d.computeUnits,
		n, p, memoryPercent, forcedBatch, hasPreprocess, fmt.Sprintf("%d|%d", forcedWorkgroup, step))
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

func loadGPUTune(key string, maxBatch, n, p int) (gpuTuneChoice, bool) {
	path, err := gpuTuneCachePath(key)
	if err != nil {
		return gpuTuneChoice{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return gpuTuneChoice{}, false
	}
	var entry gpuTuneCache
	if json.Unmarshal(data, &entry) != nil || entry.Revision != autoTuneRevision || entry.Fingerprint != key || !validTuneChoice(entry.Choice, maxBatch, n, p) {
		return gpuTuneChoice{}, false
	}
	return entry.Choice, true
}

func saveGPUTune(key string, choice gpuTuneChoice) {
	path, err := gpuTuneCachePath(key)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0700) != nil {
		return
	}
	contents, err := json.Marshal(gpuTuneCache{Revision: autoTuneRevision, Fingerprint: key, Choice: choice})
	if err != nil {
		return
	}
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
	// Best effort. Concurrent cluster processes may calibrate independently.
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
	for _, fraction := range []float64{0.45, 0.70, 0.85, 1.0} {
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
	// 32 matches NVIDIA warp width, 64 is typical AMD wavefront width.
	// 0 gives the OpenCL driver's preferred choice.
	return []int{32, 64, 128, 0}
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

// selectGPUTuning measures combinations at the loaded vault's real N and p.
// It does not benchmark the wallet's optional CPU pre-PBKDF2, which is tuned
// separately by the preparation worker count. Manual values stay authoritative.
func selectGPUTuning(d gpuDevice, n, p, memPercent, forcedBatch, forcedWorkgroup, step int, hasPreprocess bool) (gpuTuneChoice, string, error) {
	maxBatch := batchForDevice(d, n, 8, p, memPercent)
	if maxBatch < 1 {
		return gpuTuneChoice{}, "", fmt.Errorf("insufficient GPU scratch memory")
	}
	if forcedBatch > 0 && forcedBatch > maxBatch {
		return gpuTuneChoice{}, "", fmt.Errorf("-gpu-batch %d exceeds memory budget (%d candidates)", forcedBatch, maxBatch)
	}
	key := gpuTuneKey(d, n, p, memPercent, forcedBatch, forcedWorkgroup, step, hasPreprocess)
	if choice, ok := loadGPUTune(key, maxBatch, n, p); ok {
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
	saveGPUTune(key, best)
	return best, "benchmark", nil
}
