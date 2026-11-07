package main

import (
	"bytes"
	"crypto/subtle"
	"testing"
)

func TestKeccakPartsEquivalentToConcatenation(t *testing.T) {
	for _, n := range []int{0, 1, 16, 32, 135, 136, 137, 512, 4096} {
		for _, split := range []int{0, n / 2, n} {
			data := make([]byte, n)
			for i := range data {
				data[i] = byte(i*71 + 3)
			}
			got := keccak256Parts(data[:split], data[split:])
			want := keccak256(data)
			if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				t.Fatalf("mismatch at len=%d split=%d", n, split)
			}
		}
	}
	var v vault
	v.ciphertext = bytes.Repeat([]byte{0xab}, 150)
	dk := bytes.Repeat([]byte{0x42}, 48)
	v.mac = make([]byte, 32)
	original := append(append([]byte(nil), dk[16:]...), v.ciphertext...)
	mac := keccak256(original)
	copy(v.mac, mac[:])
	if !verifyMAC(v, dk) {
		t.Fatal("valid MAC rejected")
	}
	v.mac[0] ^= 1
	if verifyMAC(v, dk) {
		t.Fatal("incorrect MAC accepted")
	}
}
