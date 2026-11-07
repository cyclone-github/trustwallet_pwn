package main

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/scrypt"
)

func TestCPUScryptKeyMatchesLibrary(t *testing.T) {
	samples := []struct {
		pass, salt      string
		n, r, p, keyLen int
	}{
		{"password", "salt", 16, 1, 1, 32},
		{"second", "another-salt", 128, 1, 2, 32},
		{"longer candidate", "salty", 1024, 8, 2, 32},
		{"benchmark-wrong-password", "salt", 16384, 8, 4, 32},
	}
	scratch := acquireCPUScratch()
	defer releaseCPUScratch(scratch)
	for _, tc := range samples {
		pw, salt := []byte(tc.pass), []byte(tc.salt)
		want, err := scrypt.Key(pw, salt, tc.n, tc.r, tc.p, tc.keyLen)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			got, err := cpuScryptKey(scratch, pw, salt, tc.n, tc.r, tc.p, tc.keyLen)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("scrypt mismatch N=%d r=%d p=%d", tc.n, tc.r, tc.p)
			}
		}
	}
}

func TestCPUScryptRejectsInvalidParameters(t *testing.T) {
	scratch := acquireCPUScratch()
	defer releaseCPUScratch(scratch)
	for _, tc := range []struct{ n, r, p, k int }{
		{0, 8, 4, 32}, {16, 0, 4, 32}, {16, 8, 0, 32},
		{16, 8, -1, 32}, {16, 8, 4, 0}, {17, 8, 4, 32},
	} {
		if _, err := cpuScryptKey(scratch, []byte("pw"), []byte("salt"), tc.n, tc.r, tc.p, tc.k); err == nil {
			t.Errorf("accepted invalid scrypt parameters %+v", tc)
		}
	}
}

func TestCPUScratchOutputLifetime(t *testing.T) {
	scratch := acquireCPUScratch()
	defer releaseCPUScratch(scratch)
	original, err := cpuScryptKey(scratch, []byte("candidate-a"), []byte("salt"), 128, 1, 2, 32)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := bytes.Clone(original)
	if _, err := cpuScryptKey(scratch, []byte("candidate-b"), []byte("salt"), 128, 1, 2, 32); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, snapshot) {
		t.Fatal("returned derived key aliases reusable scratch")
	}
}
