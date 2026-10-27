//go:build linux && cgo

package main

/*
#cgo LDFLAGS: -l:libOpenCL.so.1
#include <stdlib.h>
#include "bridge.h"
*/
import "C"
import (
	_ "embed"
	"fmt"
	"strings"
	"unsafe"
)

//go:embed romix.cl
var kernelSource string

type gpuDevice struct {
	id           int
	name         string
	mem          uint64
	free         uint64
	maxAlloc     uint64
	computeUnits uint32
}

func gpuDevices() ([]gpuDevice, error) {
	var infos [64]C.twgpu_info
	errbuf := make([]byte, 16384)
	count := int(C.twgpu_list(&infos[0], C.int(len(infos)), (*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf))))
	if count < 0 {
		return nil, fmt.Errorf("%s", cstring(errbuf))
	}
	out := make([]gpuDevice, 0, count)
	for i := 0; i < count; i++ {
		d := infos[i]
		out = append(out, gpuDevice{id: int(d.index), name: strings.TrimSpace(C.GoString(&d.name[0])), mem: uint64(d.global_mem), free: uint64(d.free_mem), maxAlloc: uint64(d.max_alloc), computeUnits: uint32(d.compute_units)})
	}
	return out, nil
}

type gpuBackend struct {
	gpu         *C.twgpu
	batch, p, n int
}

func openGPU(deviceID, n, p, batch int) (*gpuBackend, error) {
	if n < 2 || n&(n-1) != 0 || p < 1 || batch < 1 {
		return nil, fmt.Errorf("invalid n,p,batch")
	}
	src := C.CString(kernelSource)
	defer C.free(unsafe.Pointer(src))
	errbuf := make([]byte, 16384)
	g := C.twgpu_open(src, C.int(deviceID), C.int(batch*p), C.int(n), (*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(len(errbuf)))
	if g == nil {
		return nil, fmt.Errorf("%s", cstring(errbuf))
	}
	return &gpuBackend{gpu: g, batch: batch, p: p, n: n}, nil
}
func (g *gpuBackend) close() {
	if g != nil && g.gpu != nil {
		C.twgpu_close(g.gpu)
		g.gpu = nil
	}
}
func (g *gpuBackend) name() string { return C.GoString(C.twgpu_name(g.gpu)) }
func (g *gpuBackend) romix(data []byte, lanes, step int) error {
	if len(data) != lanes*1024 {
		return fmt.Errorf("invalid r=8 B size: %d", len(data))
	}
	if len(data) == 0 {
		return nil
	}
	buf := make([]byte, 16384)
	if C.twgpu_romix(g.gpu, (*C.uchar)(unsafe.Pointer(&data[0])), C.int(lanes), C.int(step), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))) != 0 {
		return fmt.Errorf("%s", cstring(buf))
	}
	return nil
}
func cstring(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
