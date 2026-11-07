package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

func TestPbkdf2KeyIntoMatchesLibrary(t *testing.T) {
	cases := []struct {
		pw, salt []byte
		iter     int
		size     int
		sha512   bool
	}{
		{[]byte("password"), []byte("salt"), 1, 32, false},
		{[]byte("Cyclone!"), []byte("presalt-bytes"), 20000, 512, true},
		{[]byte("wrong-candidate-password"), []byte{1, 2, 3, 4}, 1, 4096, false},
	}
	for i, tc := range cases {
		want, err := pbkdf2Key(tc.pw, tc.salt, tc.iter, tc.size, tc.sha512)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		got := make([]byte, tc.size)
		var u, tb [64]byte
		if tc.sha512 {
			if err := pbkdf2KeyInto(got, tc.pw, tc.salt, tc.iter, sha512.New, u[:], tb[:]); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := pbkdf2KeyInto(got, tc.pw, tc.salt, tc.iter, sha256.New, u[:], tb[:]); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: pbkdf2KeyInto mismatch", i)
		}
	}
}
