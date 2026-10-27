package main

import (
	"encoding/hex"
	"testing"
)

func TestKeccak(t *testing.T) {
	got := keccak256(nil)
	want := "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("legacy Keccak-256 empty input: got %x want %s", got, want)
	}
}
