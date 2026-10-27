//go:build !linux || !cgo

package main

import "errors"

// cpu-only build support
var errNoOpenCL = errors.New("OpenCL GPU support is available on Linux with cgo")

type gpuDevice struct {
	id           int
	name         string
	mem          uint64
	free         uint64
	maxAlloc     uint64
	computeUnits uint32
}

func gpuDevices() ([]gpuDevice, error) { return nil, errNoOpenCL }

type gpuBackend struct{ n, p int }

func openGPU(deviceID, n, p, batch int) (*gpuBackend, error)   { return nil, errNoOpenCL }
func (g *gpuBackend) close()                                   {}
func (g *gpuBackend) romix(data []byte, lanes, step int) error { return errNoOpenCL }
func (g *gpuBackend) name() string                             { return "" }
