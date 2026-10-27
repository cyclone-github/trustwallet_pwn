package main

import "testing"

func TestAutoBatchMemory(t *testing.T) {
	// 4090 memory estimate is 64 mib per candidate
	d := gpuDevice{mem: 24 * 1024 * MiB, maxAlloc: 6 * 1024 * MiB, free: 23 * 1024 * MiB}
	got := batchForDevice(d, 16384, 8, 4, 92)
	if got < 300 || got > 353 {
		t.Fatalf("4090 auto batch = %d; expected to target >75%% and <=92%% VRAM", got)
	}
	if uint64(got)*64*MiB > d.mem*92/100 {
		t.Fatal("exceeds configured GPU memory target")
	}
	d.free = 10 * 1024 * MiB
	got = batchForDevice(d, 16384, 8, 4, 92)
	if uint64(got)*64*MiB > d.free-512*MiB {
		t.Fatal("exceeds free memory estimate")
	}
	// zero reported free memory means unknown on nvidia
	d.free = 0
	d.maxAlloc = 6 * 1024 * MiB
	got = batchForDevice(d, 16384, 8, 4, 92)
	if got < 300 || got > 353 {
		t.Fatalf("unknown-free NVIDIA batch = %d, expected usable auto allocation", got)
	}
	d.free = 8 * 1024
	got = batchForDevice(d, 16384, 8, 4, 92)
	if got < 300 || got > 353 {
		t.Fatalf("tiny advisory free memory suppressed auto mode: %d", got)
	}
	d.free = 0
	d.maxAlloc = 256 * MiB
	got = batchForDevice(d, 16384, 8, 4, 92)
	if got > 30 {
		t.Fatalf("expected reduced batch for single-allocation limits, got %d", got)
	}
}
func TestSelectedDevices(t *testing.T) {
	ds := []gpuDevice{{id: 0, name: "A"}, {id: 1, name: "B"}, {id: 2, name: "C"}}
	got, err := selectedDevices(ds, "2,0,2")
	if err != nil || len(got) != 2 || got[0].id != 2 || got[1].id != 0 {
		t.Fatalf("selection got=%v err=%v", got, err)
	}
	got, err = selectedDevices(ds, "all")
	if err != nil || len(got) != 3 {
		t.Fatal("all selection failed")
	}
	if _, err = selectedDevices(ds, "4"); err == nil {
		t.Fatal("missing device should fail")
	}
}
