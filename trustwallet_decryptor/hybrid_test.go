package main

import (
	"testing"
)

func TestBackendPriority(t *testing.T) {
	cases := []struct {
		name                                       string
		cpuFlag, gpuFlag, hybridFlag, gpuOK, cpuOK bool
		want                                       executionMode
		fail                                       bool
	}{
		{name: "default hybrid", gpuOK: true, cpuOK: true, want: modeHybrid},
		{name: "default gpu fallback", gpuOK: true, cpuOK: false, want: modeGPU},
		{name: "default cpu fallback", gpuOK: false, cpuOK: true, want: modeCPU},
		{name: "no backend", fail: true},
		{name: "force CPU", cpuFlag: true, gpuOK: true, cpuOK: true, want: modeCPU},
		{name: "force GPU", gpuFlag: true, gpuOK: true, cpuOK: true, want: modeGPU},
		{name: "force hybrid", hybridFlag: true, gpuOK: true, cpuOK: true, want: modeHybrid},
		{name: "force hybrid error", hybridFlag: true, gpuOK: false, cpuOK: true, fail: true},
		{name: "force GPU error", gpuFlag: true, gpuOK: false, cpuOK: true, fail: true},
		{name: "exclusive", cpuFlag: true, gpuFlag: true, gpuOK: true, cpuOK: true, fail: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := chooseBackend(tc.cpuFlag, tc.gpuFlag, tc.hybridFlag, tc.gpuOK, tc.cpuOK)
			if (err != nil) != tc.fail || (!tc.fail && got != tc.want) {
				t.Fatalf("got %q err=%v, want %q fail=%t", got, err, tc.want, tc.fail)
			}
		})
	}
}
func TestAutoHybridThreads(t *testing.T) {
	for _, tc := range []struct{ n, want int }{{1, 1}, {8, 8}, {56, 56}, {128, 128}} {
		if got := autoHybridThreads(tc.n); got != tc.want {
			t.Errorf("n=%d got %d want %d", tc.n, got, tc.want)
		}
	}
}
