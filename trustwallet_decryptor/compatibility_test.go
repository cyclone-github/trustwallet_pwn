package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestOriginalCheckForHexBytes(t *testing.T) {
	tests := []struct {
		input     string
		decoded   []byte
		corrected int
	}{
		{"Cyclone!", []byte("Cyclone!"), 0},
		{"$HEX[4379636c6f6e6521]", []byte("Cyclone!"), 0},
		{"$HEX[4379636c6f6e6521", []byte("Cyclone!"), 1},
		{"$HEX[41xx4243]", []byte("ABC"), 1},
		{"$HEX[414]", []byte{0x04, 0x14}, 1},
	}
	for _, tt := range tests {
		got, _, corrected := checkForHexBytes([]byte(tt.input))
		if !bytes.Equal(got, tt.decoded) || corrected != tt.corrected {
			t.Errorf("%q decoded %x corrected %d; want %x corrected %d", tt.input, got, corrected, tt.decoded, tt.corrected)
		}
	}
}

func TestSkipMalformedVaultPreservesValidWallet(t *testing.T) {
	input := append([]byte("not json\n"), selfTestWallet...)
	input = append(input, []byte("\n{\"crypto\": {\"cipher\": \"not-a-cipher\"}}\n")...)
	vs, err := parseVaults(input)
	if err != nil || len(vs) != 1 {
		t.Fatalf("valid cyclone wallet was lost: count %d error %v", len(vs), err)
	}
	if vs[0].vaultData == "" || len(vs[0].presalt) == 0 {
		t.Fatal("extension metadata not preserved")
	}
}

func TestOriginalTrustVaultFallback(t *testing.T) {
	v := vault{vaultData: base64.StdEncoding.EncodeToString([]byte("Cyclone!"))}
	got := fallbackPlaintext(v, []byte{0xff, 0xfe})
	if string(got) != "Cyclone!" {
		t.Fatalf("trust:vault fallback changed: %q", got)
	}
	got = fallbackPlaintext(v, []byte("tell priority insane"))
	if !strings.HasPrefix(string(got), "tell priority") {
		t.Fatalf("UTF-8 plaintext must be kept: %q", got)
	}
}
