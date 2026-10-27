package main

import "golang.org/x/crypto/sha3"

// original legacy keccak from golang.org/x/crypto
func keccak256(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
