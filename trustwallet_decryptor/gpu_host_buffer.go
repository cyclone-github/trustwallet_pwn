package main

// batchStateBuffer is private to a gpuBackend and its single synchronous
// worker. The returned slice must not be retained after the next call.
func (g *gpuBackend) batchStateBuffer(lanes int) []byte {
	need := lanes * 1024 // ROMix r=8: 128 * r bytes per lane.
	if cap(g.hostB) < need {
		g.hostB = make([]byte, need)
	}
	return g.hostB[:need]
}

// batchTransformedBuffer is owned by the synchronous GPU worker. Each
// presalted password occupies exactly 1026 bytes until finalization returns.
func (g *gpuBackend) batchTransformedBuffer(count int) []byte {
	need := count * presaltPassLen
	if cap(g.hostPass) < need {
		g.hostPass = make([]byte, need)
	}
	return g.hostPass[:need]
}
