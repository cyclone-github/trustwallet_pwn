package main

import "golang.org/x/crypto/sha3"

// keccak256Parts hashes two existing slices without concatenating them. The
// output is written into the fixed array rather than allocating a digest slice.
func keccak256Parts(a, b []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(a)
	_, _ = h.Write(b)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func keccak256(data []byte) [32]byte {
	return keccak256Parts(data, nil)
}
