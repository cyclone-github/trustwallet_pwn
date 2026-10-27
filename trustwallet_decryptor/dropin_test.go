package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatusExactlyUpstream(t *testing.T) {
	got := formatStatus(61*time.Minute, 0, 1, 527991, 0)
	want := "Decrypted: 0/1 144.26 h/s 01h:01m:00s ETA: --"
	if got != want {
		t.Fatalf("status got %q, want %q", got, want)
	}
	if got := formatStatus(45*time.Minute, 0, 1, 389502, 0); got != "Decrypted: 0/1 144.26 h/s 00h:45m:00s ETA: --" {
		t.Fatalf("unexpected status: %q", got)
	}
}

func TestDecodeHEX(t *testing.T) {
	if got := decodedCandidate([]byte("$HEX[41422121]")); !bytes.Equal(got, []byte("AB!!")) {
		t.Fatalf("got %q", got)
	}
	if got := decodedCandidate([]byte("Cyclone!2")); !bytes.Equal(got, []byte("Cyclone!2")) {
		t.Fatal("plain line changed")
	}
	if got := decodedCandidate([]byte("$HEX[zz]")); len(got) != 0 {
		t.Fatalf("original HEX cleanup behavior changed: %x", got)
	}
}

func TestPBKDF2AndCBCFallback(t *testing.T) {
	password := []byte("Cyclone!123")
	salt := []byte("test-salt-abcdefghijklmnopqrstuvw")
	iv := []byte("1234567890abcdef")
	dk, err := pbkdf2Derive(password, salt, 1000, 32, false)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(dk[:16])
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("cyclone synthetic test plaintext")
	padded := append([]byte{}, plain...)
	pad := 16 - len(plain)%16
	padded = append(padded, bytes.Repeat([]byte{byte(pad)}, pad)...)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	msg := append(append([]byte{}, dk[16:]...), ciphertext...)
	mac := keccak256(msg)
	doc := map[string]any{"crypto": map[string]any{
		"cipher": "aes-128-cbc", "ciphertext": hex.EncodeToString(ciphertext), "cipherparams": map[string]any{"iv": hex.EncodeToString(iv)},
		"kdf": "pbkdf2", "kdfparams": map[string]any{"c": 1000, "dklen": 32, "salt": hex.EncodeToString(salt)}, "mac": fmt.Sprintf("%x", mac),
	}}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "pbkdf2.json")
	if err = os.WriteFile(f, data, 0600); err != nil {
		t.Fatal(err)
	}
	vs, err := loadVaults(f)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := cpuDerive(vs[0], password)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyMAC(vs[0], derived) {
		t.Fatal("MAC mismatch")
	}
	got, err := decrypt(vs[0], derived)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("plaintext got %q", got)
	}
	if err := gpuEligible(vs); err == nil || !strings.Contains(err.Error(), "unsupported GPU") {
		t.Fatalf("PBKDF2 should CPU-fallback: %v", err)
	}
}

func TestETA(t *testing.T) {
	cases := []struct {
		name             string
		elapsed          time.Duration
		processed, count uint64
		matches          int
		want             string
	}{
		{"full wordlist", 10 * time.Second, 100, 1000, 0, "ETA: 00h:01m:30s"},
		{"chunk range", 10 * time.Second, 100, 300, 0, "ETA: 00h:00m:20s"},
		{"complete", 10 * time.Second, 300, 300, 0, "ETA: 00h:00m:00s"},
		{"recovered", 10 * time.Second, 100, 300, 1, "ETA: 00h:00m:00s"},
		{"no progress", 10 * time.Second, 0, 300, 0, "ETA: --"},
		{"stdin", 10 * time.Second, 100, 0, 0, "ETA: --"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatStatus(tc.elapsed, tc.matches, 1, tc.processed, tc.count)
			if !strings.HasSuffix(got, tc.want) {
				t.Fatalf("status %q should end with %q", got, tc.want)
			}
		})
	}
}
