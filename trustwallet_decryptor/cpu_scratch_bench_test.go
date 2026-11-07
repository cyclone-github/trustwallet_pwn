package main

import (
	"golang.org/x/crypto/scrypt"
	"testing"
)

func BenchmarkScryptLibrary(b *testing.B) {
	pw, salt := []byte("benchmark-wrong-password"), []byte("test-salt")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := scrypt.Key(pw, salt, 16384, 8, 4, 32); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkScryptWorkerScratch(b *testing.B) {
	pw, salt := []byte("benchmark-wrong-password"), []byte("test-salt")
	s := newCPUWorkerScratch()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := cpuScryptKey(s, pw, salt, 16384, 8, 4, 32); err != nil {
			b.Fatal(err)
		}
	}
}
