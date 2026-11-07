package main

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// These tests require no GPU. They compare the pre- and post-ROMix PBKDF2
// stages to the existing library implementation and exercise ownership.
func TestGPUHostPreparationReferenceAndLifetime(t *testing.T) {
	for _, presalted := range []bool{false, true} {
		v := vault{kdf: "scrypt", n: 16384, r: 8, p: 4, dklen: 32, salt: []byte("gpu-prep-test-salt")}
		if presalted {
			v.presalt = []byte("trust:pbkdf2-test-presalt")
		}
		g := &gpuBackend{n: v.n, p: v.p}
		scratch := acquireCPUScratch()
		defer releaseCPUScratch(scratch)
		passwords := [][]byte{[]byte("first!"), []byte("second-longer-password"), []byte("third#")}
		threads := 1
		if presalted {
			threads = 3
		}
		passes, B, blocklen, err := gpuPrepareBatch(v, passwords, g, threads, scratch)
		if err != nil {
			t.Fatal(err)
		}
		if blocklen != v.p*128*v.r {
			t.Fatalf("blocklen=%d", blocklen)
		}
		for i, pw := range passwords {
			transformed, err := transformedPassword(v, pw)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(passes[i], transformed) {
				t.Fatalf("pass mismatch presalt=%v i=%d", presalted, i)
			}
			want, err := pbkdf2Key(transformed, v.salt, 1, blocklen, false)
			if err != nil {
				t.Fatal(err)
			}
			got := B[i*blocklen : (i+1)*blocklen]
			if !bytes.Equal(got, want) {
				t.Fatalf("initial PBKDF2 mismatch presalt=%v i=%d", presalted, i)
			}
		}
		// Simulate GPU ROMix output in place and verify final PBKDF2.
		for i := range B {
			B[i] ^= 0x3a
		}
		dks, err := gpuFinalizeBatch(v, passes, B, blocklen, scratch)
		if err != nil {
			t.Fatal(err)
		}
		for i, pass := range passes {
			block := B[i*blocklen : (i+1)*blocklen]
			want, err := pbkdf2Key(pass, block, 1, v.dklen, false)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(dks[i], want) {
				t.Fatalf("final PBKDF2 mismatch presalt=%v i=%d", presalted, i)
			}
		}
		first := bytes.Clone(dks[0])
		// Reusing the backend's buffers cannot mutate previously returned keys.
		if _, _, _, err := gpuPrepareBatch(v, [][]byte{[]byte("another-candidate")}, g, threads, scratch); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dks[0], first) {
			t.Fatal("previous key changed after buffer reuse")
		}
		if err := pbkdf2KeyInto(make([]byte, 32), []byte("pw"), []byte("salt"), 1, sha256.New, scratch.pbkdf2U[:], scratch.pbkdf2T[:]); err != nil {
			t.Fatal(err)
		}
	}
}
