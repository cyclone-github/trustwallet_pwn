package main

import (
	"strings"
	"testing"
)

func TestRepoSampleSelfTest(t *testing.T) {
	v, err := selfTestVault()
	if err != nil {
		t.Fatal(err)
	}
	if err := testCPU(v); err != nil {
		t.Fatalf("GitHub README sample: %v", err)
	}
	cpuOK, healthy, result := selfTestResults(true, false, nil)
	if !cpuOK || len(healthy) != 0 || result != "CPU PASS" {
		t.Fatalf("CPU self-test: %v, %v, %q", cpuOK, healthy, result)
	}
}

func TestRepoSampleTamper(t *testing.T) {
	v, err := selfTestVault()
	if err != nil {
		t.Fatal(err)
	}
	dk, err := cpuDerive(v, []byte(selfTestPassword))
	if err != nil {
		t.Fatal(err)
	}
	v.mac[0] ^= 1
	if err := checkSelfTest(v, dk); err == nil || !strings.Contains(err.Error(), "MAC mismatch") {
		t.Fatalf("tampered sample not rejected: %v", err)
	}
}
