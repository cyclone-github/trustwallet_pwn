package main

import (
	"bytes"
	"fmt"
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
				gpuErrors[i] = testGPU(sample, d)
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
