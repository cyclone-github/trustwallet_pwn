package main

import (
	"crypto/hmac"
	"errors"
	"hash"
)

// pbkdf2KeyInto writes RFC 8018 PBKDF2 output into key, matching golang.org/x/crypto/pbkdf2.Key
// for the same password bytes, salt, iteration count, and hash constructor.
// u and t must each have length at least the hash output size.
func pbkdf2KeyInto(key []byte, password, salt []byte, iter int, h func() hash.Hash, u, t []byte) error {
	if iter < 1 {
		return errors.New("invalid PBKDF2 iteration count")
	}
	if len(key) < 1 {
		return errors.New("invalid PBKDF2 output length")
	}
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	if len(u) < hashLen || len(t) < hashLen {
		return errors.New("invalid PBKDF2 workspace")
	}
	u = u[:hashLen]
	t = t[:hashLen]
	numBlocks := (len(key) + hashLen - 1) / hashLen
	var block [4]byte
	for blockNum := 1; blockNum <= numBlocks; blockNum++ {
		block[0] = byte(blockNum >> 24)
		block[1] = byte(blockNum >> 16)
		block[2] = byte(blockNum >> 8)
		block[3] = byte(blockNum)
		prf.Reset()
		prf.Write(salt)
		prf.Write(block[:])
		sum := prf.Sum(t[:0])
		copy(u, sum)
		copy(t, sum)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			sum = prf.Sum(u[:0])
			copy(u, sum)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		start := (blockNum - 1) * hashLen
		end := start + hashLen
		if end > len(key) {
			end = len(key)
		}
		copy(key[start:end], t[:end-start])
	}
	return nil
}
