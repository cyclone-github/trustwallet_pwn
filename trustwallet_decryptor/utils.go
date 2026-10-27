package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const MiB uint64 = 1024 * 1024

var errGPUInitialization = errors.New("GPU initialization")

var gpuVerbose bool

// 92 percent is the gpu memory target

func batchForDevice(d gpuDevice, n, r, p, percent int) int {
	perPassword := uint64(n) * uint64(128*r) * uint64(p)
	if perPassword == 0 {
		return 0
	}
	budget := d.mem * uint64(percent) / 100
	if d.free > 512*MiB {
		freeBudget := d.free - 512*MiB
		if freeBudget < budget {
			budget = freeBudget
		}
	}
	if d.maxAlloc > 0 {
		perBuffer := (d.maxAlloc - d.maxAlloc/20) / (uint64(n) * uint64(128*r))
		maxScratch := 8 * perBuffer * uint64(n) * uint64(128*r)
		if budget > maxScratch {
			budget = maxScratch
		}
	}
	batch := int(budget / perPassword)
	if batch > 4096 {
		batch = 4096
	}
	return batch
}

func selectedDevices(all []gpuDevice, spec string) ([]gpuDevice, error) {
	if spec == "" || strings.EqualFold(spec, "all") {
		return all, nil
	}
	selected := make([]gpuDevice, 0)
	seen := make(map[int]bool)
	for _, part := range strings.Split(spec, ",") {
		id, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("bad -gpu-devices id %q", part)
		}
		if id < 0 || id >= len(all) {
			return nil, fmt.Errorf("GPU %d unavailable (detected %d)", id, len(all))
		}
		if !seen[id] {
			selected = append(selected, all[id])
			seen[id] = true
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no devices selected")
	}
	return selected, nil
}

// support hex-encoded binary password candidates

func decodedCandidate(raw []byte) []byte {
	candidate, _, _ := checkForHexBytes(raw)
	return candidate
}

// status reports elapsed time and wordlist eta

func gpuEligible(vaults []vault) error {
	if len(vaults) == 0 {
		return errors.New("no vaults")
	}
	first := vaults[0]
	for i, v := range vaults {
		if v.kdf != "scrypt" || v.r != 8 || v.dklen != 32 || v.cipher != "aes-128-ctr" {
			return fmt.Errorf("vault %d has unsupported GPU parameters (%s/%s,r=%d,dklen=%d)", i+1, v.kdf, v.cipher, v.r, v.dklen)
		}
		if v.n != first.n || v.p != first.p {
			return fmt.Errorf("vault %d uses different scrypt N,p", i+1)
		}
	}
	return nil
}

type executionMode string

const (
	modeHybrid executionMode = "Hybrid/GPU+CPU"
	modeGPU    executionMode = "GPU/OpenCL"
	modeCPU    executionMode = "CPU"
)

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func chooseBackend(forceCPU, forceGPU, forceHybrid, gpuOK, cpuOK bool) (executionMode, error) {
	if boolInt(forceCPU)+boolInt(forceGPU)+boolInt(forceHybrid) > 1 {
		return "", errors.New("backend flags are mutually exclusive")
	}
	if forceCPU {
		if !cpuOK {
			return "", errors.New("CPU backend unavailable")
		}
		return modeCPU, nil
	}
	if forceGPU {
		if !gpuOK {
			return "", errors.New("GPU backend unavailable")
		}
		return modeGPU, nil
	}
	if forceHybrid {
		if !gpuOK || !cpuOK {
			return "", errors.New("hybrid requires both CPU and GPU backends")
		}
		return modeHybrid, nil
	}
	if gpuOK && cpuOK {
		return modeHybrid, nil
	}
	if gpuOK {
		return modeGPU, nil
	}
	if cpuOK {
		return modeCPU, nil
	}
	return "", errors.New("no usable CPU or GPU backend")
}

func autoHybridThreads(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

func cpuBackendReady() bool {
	v, err := pbkdf2Derive([]byte("probe"), []byte("salt"), 1, 32, false)
	return err == nil && len(v) == 32
}
