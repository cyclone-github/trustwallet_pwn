package main

import "testing"

func TestGPUHostStateBufferReuse(t *testing.T) {
	g := &gpuBackend{}
	a := g.batchStateBuffer(8)
	if len(a) != 8192 {
		t.Fatal(len(a))
	}
	a[0] = 0x7f
	b := g.batchStateBuffer(4)
	if len(b) != 4096 || &a[0] != &b[0] || b[0] != 0x7f {
		t.Fatal("buffer not reused")
	}
	c := g.batchStateBuffer(16)
	if len(c) != 16384 {
		t.Fatal(len(c))
	}
	d := g.batchStateBuffer(8)
	if &c[0] != &d[0] {
		t.Fatal("grown buffer not reused")
	}
}
