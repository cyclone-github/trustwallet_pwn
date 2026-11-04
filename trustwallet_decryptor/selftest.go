package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// cyclone sample wallet
const selfTestWalletJSON = `{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"8cc8cf025dab07940b2fb5594c65a39d"},"ciphertext":"a45b57056b2fab289b44d18f54af43ed5e523505009a8f35ad57496d74fb43f6d6248926a49b6c2e1df1debad6ea532f826ad637f65cc831d7cbf46c38490f07d9d1691c67aa02a4c7ca","kdf":"scrypt","kdfparams":{"dklen":32,"n":16384,"p":4,"r":8,"salt":"c302622d54247a7eeef2b33e2925c0875a89c52d6c9a5856694f6d262ae7f18e"},"mac":"acef4b2b49067c235693661964520773a4d910d3e061f7c314f4e4ac07970a1b"},"trust:pbkdf2":{"salt":"0x39c0f6ce6c2559f91feba0d6624c9a8fb948ab669abd1cfdba3af19bbcded280"},"trust:vault":{"data":"kLg6MvRVZcfFxlzQoEED5W+lscfxBoThMlD9LxCeUHZIoo9mcQp/4uKcNiPRvw2ySGnLe3cflNttI2E0hzMcnckKW3aQE0VuDH4f2hCHsIG9r+uXILqRN5qQlMPH2GiEtMi5+YBM7J0LRNqtes3vE3IYjl3y3bDNoa24l+WFU7Dw6G883Qc=","iv":"ngwjYPZYg4pAQtGQKJfc7g==","salt":"hy31Q6pn9oEfzTkX6YD6BgixlEkBj0i5pmRbEk9d4sM="}}`

var selfTestWallet = []byte(selfTestWalletJSON)

const selfTestPassword = "Cyclone!"
const selfTestPlaintext = "tell priority insane episode hamster click list gym juice valve damp swamp"

func selfTestVault() (vault, error) {
	samples, err := parseVaults(selfTestWallet)
	if err != nil {
		return vault{}, fmt.Errorf("invalid sample wallet: %w", err)
	}
	if len(samples) != 1 {
		return vault{}, fmt.Errorf("invalid sample wallet count: %d", len(samples))
	}
	return samples[0], nil
}

func checkSelfTest(v vault, dk []byte) error {
	if !verifyMAC(v, dk) {
		return fmt.Errorf("sample MAC mismatch")
	}
	plain, err := decrypt(v, dk)
	if err != nil {
		return err
	}
	if !bytes.Equal(plain, []byte(selfTestPlaintext)) {
		return fmt.Errorf("sample plaintext mismatch")
	}
	return nil
}

func testCPU(v vault) error {
	dk, err := cpuDerive(v, []byte(selfTestPassword))
	if err != nil {
		return err
	}
	return checkSelfTest(v, dk)
}

func testGPU(v vault, d gpuDevice) error {
	g, err := openGPU(d.id, v.n, v.p, 1)
	if err != nil {
		return err
	}
	defer g.close()
	dks, err := gpuDeriveBatch(v, [][]byte{[]byte(selfTestPassword)}, g, 2048)
	if err != nil {
		return err
	}
	if len(dks) != 1 {
		return fmt.Errorf("sample returned %d keys", len(dks))
	}
	return checkSelfTest(v, dks[0])
}

// verify all active backends before processing candidates
func selfTestResults(cpuRequested bool, gpuRequested bool, devices []gpuDevice) (bool, []gpuDevice, string) {
	return selfTestResultsTuned(cpuRequested, gpuRequested, devices, 0)
}

// The real Trust Wallet fixture is scrypt N=16384,r=8,p=4 with trust:pbkdf2.
// When an explicit workgroup is requested, check all candidates in one full
// workgroup rather than inadvertently testing only the runtime-selected tail.
func testGPUWithWorkgroup(v vault, d gpuDevice, workgroup int) error {
	if workgroup == 0 {
		return testGPU(v, d)
	}
	count := workgroup / gcdInt(workgroup, v.p)
	if count > 256 {
		return fmt.Errorf("self-test workgroup %d requires %d candidate checks; choose a smaller workgroup", workgroup, count)
	}
	if count < 1 {
		count = 1
	}
	g, err := openGPUWorkgroup(d.id, v.n, v.p, count, workgroup)
	if err != nil {
		return err
	}
	defer g.close()
	passwords := make([][]byte, count)
	passwords[0] = []byte(selfTestPassword)
	for i := 1; i < count; i++ {
		passwords[i] = []byte(fmt.Sprintf("trustwallet-workgroup-test-%d", i))
	}
	dks, err := gpuDeriveBatchTuned(v, passwords, g, 2048, count)
	if err != nil {
		return err
	}
	if len(dks) != count {
		return fmt.Errorf("GPU returned %d keys for %d candidates", len(dks), count)
	}
	if err := checkSelfTest(v, dks[0]); err != nil {
		return err
	}
	for i := 1; i < count; i++ {
		cpuKey, err := cpuDerive(v, passwords[i])
		if err != nil {
			return err
		}
		if !bytes.Equal(cpuKey, dks[i]) {
			return fmt.Errorf("self-test workgroup mismatch at candidate %d", i)
		}
	}
	return nil
}

func selfTestResultsTuned(cpuRequested bool, gpuRequested bool, devices []gpuDevice, workgroup int) (bool, []gpuDevice, string) {
	sample, err := selfTestVault()
	if err != nil {
		return false, nil, "FAIL (" + err.Error() + ")"
	}
	var wg sync.WaitGroup
	var cpuErr error
	gpuErrors := make([]error, len(devices))
	if cpuRequested {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cpuErr = testCPU(sample)
		}()
	}
	if gpuRequested {
		for i, d := range devices {
			wg.Add(1)
			go func(i int, d gpuDevice) {
				defer wg.Done()
				gpuErrors[i] = testGPUWithWorkgroup(sample, d, workgroup)
			}(i, d)
		}
	}
	wg.Wait()

	var results []string
	cpuOK := false
	if cpuRequested {
		if cpuErr != nil {
			results = append(results, "CPU FAIL ("+cpuErr.Error()+")")
		} else {
			cpuOK = true
			results = append(results, "CPU PASS")
		}
	}
	var healthy []gpuDevice
	if gpuRequested {
		for i, d := range devices {
			if gpuErrors[i] != nil {
				results = append(results, fmt.Sprintf("GPU %d FAIL (%v)", d.id, gpuErrors[i]))
			} else {
				healthy = append(healthy, d)
				results = append(results, fmt.Sprintf("GPU %d PASS", d.id))
			}
		}
	}
	return cpuOK, healthy, strings.Join(results, "; ")
}

// verifyLoadedVaultGPU checks the actual user's KDF parameters using only
// synthetic candidate passwords. No unknown recovery password is needed.
// In production, this is run once per GPU and wallet before consuming input.
// Full-batch verification is separate from the production startup self-test.
func verifyLoadedVaultGPU(v vault, g *gpuBackend, workgroup, prepareThreads, capacity int) error {
	count := 2
	if workgroup > 0 {
		count = workgroup / gcdInt(workgroup, v.p)
	}
	if count > capacity {
		count = capacity
	}
	if count < 1 {
		return fmt.Errorf("invalid GPU test capacity")
	}
	passwords := make([][]byte, count)
	for i := range passwords {
		passwords[i] = []byte("tw-gpu-kdf-check-" + strconv.Itoa(i))
	}
	derived, err := gpuDeriveBatchTuned(v, passwords, g, 4096, prepareThreads)
	if err != nil {
		return err
	}
	if len(derived) != count {
		return fmt.Errorf("KDF test expected %d keys, got %d", count, len(derived))
	}
	indices := []int{0, count - 1}
	for _, i := range indices {
		expected, err := cpuDerive(v, passwords[i])
		if err != nil {
			return fmt.Errorf("CPU reference candidate %d: %w", i, err)
		}
		if !bytes.Equal(expected, derived[i]) {
			return fmt.Errorf("KDF mismatch at candidate %d (N=%d r=%d p=%d pre=%v)", i, v.n, v.r, v.p, v.presalt != nil)
		}
	}
	return nil
}
