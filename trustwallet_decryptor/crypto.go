package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

type walletJSON struct {
	Crypto struct {
		Cipher       string `json:"cipher"`
		Ciphertext   string `json:"ciphertext"`
		CipherParams struct {
			IV string `json:"iv"`
		} `json:"cipherparams"`
		KDF       string `json:"kdf"`
		KDFParams struct {
			N, R, P, Dklen, C int
			Salt              string `json:"salt"`
		} `json:"kdfparams"`
		Mac string `json:"mac"`
	} `json:"crypto"`
	Pre *struct {
		Salt string `json:"salt"`
	} `json:"trust:pbkdf2"`
	TrustVault *struct {
		Data string `json:"data"`
	} `json:"trust:vault"`
}
type vault struct {
	cipher, kdf                        string
	ciphertext, iv, salt, mac, presalt []byte
	n, r, p, dklen, c                  int
	vaultData                          string
}

func loadVaults(path string) ([]vault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseVaults(raw)
}

func parseVaults(raw []byte) ([]vault, error) {
	var err error
	var lines [][]byte
	var single walletJSON
	if err := json.Unmarshal(raw, &single); err == nil && single.Crypto.Cipher != "" {
		lines = append(lines, raw)
	} else {
		for _, line := range bytes.Split(raw, []byte{'\n'}) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 || bytes.HasPrefix(line, []byte("//")) {
				continue
			}
			lines = append(lines, line)
		}
	}
	var out []vault
	for i, line := range lines {
		var w walletJSON
		if err := json.Unmarshal(line, &w); err != nil {
			log.Printf("vault line %d skipped: %v", i+1, err)
			continue
		}
		var v vault
		v.cipher = w.Crypto.Cipher
		v.kdf = w.Crypto.KDF
		if (v.cipher != "aes-128-ctr" && v.cipher != "aes-128-cbc" && v.cipher != "aes-256-ctr" && v.cipher != "aes-256-cbc") || (v.kdf != "scrypt" && v.kdf != "pbkdf2") {
			log.Printf("vault line %d skipped: unsupported cipher or KDF", i+1)
			continue
		}
		v.n = w.Crypto.KDFParams.N
		v.r = w.Crypto.KDFParams.R
		v.p = w.Crypto.KDFParams.P
		v.dklen = w.Crypto.KDFParams.Dklen
		v.c = w.Crypto.KDFParams.C
		if v.dklen < 32 || (v.kdf == "scrypt" && (v.n < 2 || v.n&(v.n-1) != 0 || v.r < 1 || v.p < 1)) {
			log.Printf("vault line %d skipped: invalid KDF params", i+1)
			continue
		}
		if v.salt, err = hex.DecodeString(w.Crypto.KDFParams.Salt); err != nil {
			log.Printf("vault line %d skipped: bad salt: %v", i+1, err)
			continue
		}
		if v.iv, err = hex.DecodeString(w.Crypto.CipherParams.IV); err != nil {
			log.Printf("vault line %d skipped: bad IV: %v", i+1, err)
			continue
		}
		if v.ciphertext, err = hex.DecodeString(w.Crypto.Ciphertext); err != nil {
			log.Printf("vault line %d skipped: bad ciphertext: %v", i+1, err)
			continue
		}
		if v.mac, err = hex.DecodeString(w.Crypto.Mac); err != nil {
			log.Printf("vault line %d skipped: bad MAC: %v", i+1, err)
			continue
		}
		if len(v.salt) == 0 || len(v.iv) != 16 || len(v.ciphertext) == 0 || len(v.mac) != 32 || (strings.HasSuffix(v.cipher, "-cbc") && len(v.ciphertext)%16 != 0) {
			log.Printf("vault line %d skipped: missing or invalid data", i+1)
			continue
		}
		if w.Pre != nil {
			v.presalt, err = hex.DecodeString(strings.TrimPrefix(w.Pre.Salt, "0x"))
			if err != nil {
				log.Printf("vault line %d skipped: bad presalt: %v", i+1, err)
				continue
			}
		}
		if w.TrustVault != nil {
			v.vaultData = w.TrustVault.Data
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, errors.New("no usable vaults in file")
	}
	return out, nil
}

// pbkdf2 uses the original pure-go derivation
func pbkdf2Key(pw, salt []byte, rounds, size int, sha512Mode bool) ([]byte, error) {
	if rounds < 1 || size < 1 {
		return nil, errors.New("invalid PBKDF2 parameters")
	}
	if sha512Mode {
		return pbkdf2.Key(pw, salt, rounds, size, sha512.New), nil
	}
	return pbkdf2.Key(pw, salt, rounds, size, sha256.New), nil
}

// preserve existing helper interface for gpu preprocessing
func pbkdf2Derive(pw, salt []byte, rounds, size int, sha512Mode bool) ([]byte, error) {
	return pbkdf2Key(pw, salt, rounds, size, sha512Mode)
}

func transformedPassword(v vault, pw []byte) ([]byte, error) {
	if v.presalt == nil {
		return pw, nil
	}
	intermediate, err := pbkdf2Derive(pw, v.presalt, 20000, 512, true)
	if err != nil {
		return nil, err
	}
	pass := make([]byte, 2+hex.EncodedLen(len(intermediate)))
	copy(pass, []byte("0x"))
	hex.Encode(pass[2:], intermediate)
	return pass, nil
}
func cpuDerive(v vault, pw []byte) ([]byte, error) {
	transformed, err := transformedPassword(v, pw)
	if err != nil {
		return nil, err
	}
	switch v.kdf {
	case "scrypt":
		return scrypt.Key(transformed, v.salt, v.n, v.r, v.p, v.dklen)
	case "pbkdf2":
		count := v.c
		if count == 0 {
			count = 100000
		}
		return pbkdf2Key(transformed, v.salt, count, v.dklen, false)
	default:
		return nil, fmt.Errorf("unsupported KDF %s", v.kdf)
	}
}
func verifyMAC(v vault, dk []byte) bool {
	if len(dk) < 32 {
		return false
	}
	msg := make([]byte, len(dk)-16+len(v.ciphertext))
	copy(msg, dk[16:])
	copy(msg[len(dk)-16:], v.ciphertext)
	digest := keccak256(msg)
	return subtle.ConstantTimeCompare(digest[:], v.mac) == 1
}
func decrypt(v vault, dk []byte) ([]byte, error) {
	keylen := 16
	if strings.HasPrefix(v.cipher, "aes-256-") {
		keylen = 32
	}
	if len(dk) < keylen {
		return nil, errors.New("derived key too short")
	}
	block, err := aes.NewCipher(dk[:keylen])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(v.ciphertext))
	if strings.HasSuffix(v.cipher, "-ctr") {
		cipher.NewCTR(block, v.iv).XORKeyStream(out, v.ciphertext)
		return fallbackPlaintext(v, out), nil
	}
	if len(v.ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("CBC requires block-aligned ciphertext")
	}
	cipher.NewCBCDecrypter(block, v.iv).CryptBlocks(out, v.ciphertext)
	if len(out) == 0 {
		return nil, errors.New("empty CBC plaintext")
	}
	pad := int(out[len(out)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(out) {
		return nil, errors.New("invalid CBC padding")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, errors.New("invalid CBC padding")
		}
	}
	return fallbackPlaintext(v, out[:len(out)-pad]), nil
}

func fallbackPlaintext(v vault, plain []byte) []byte {
	if utf8.Valid(plain) || v.vaultData == "" {
		return plain
	}
	if original, err := base64.StdEncoding.DecodeString(v.vaultData); err == nil {
		return original
	}
	return plain
}

// gpu scrypt supports r=8 and p>=1
func gpuDeriveBatch(v vault, passwords [][]byte, g *gpuBackend, steps int) ([][]byte, error) {
	if v.r != 8 {
		return nil, fmt.Errorf("GPU ROMix currently supports only r=8 (got %d)", v.r)
	}
	if g.n != v.n || g.p != v.p {
		return nil, errors.New("GPU scrypt parameters mismatch")
	}
	blocklen := 128 * v.r
	B := make([]byte, len(passwords)*v.p*blocklen)
	transformed := make([][]byte, len(passwords))
	for i, pw := range passwords {
		pass, err := transformedPassword(v, pw)
		if err != nil {
			return nil, err
		}
		transformed[i] = pass
		blocks, err := pbkdf2Derive(pass, v.salt, 1, v.p*blocklen, false)
		if err != nil {
			return nil, err
		}
		copy(B[i*v.p*blocklen:], blocks)
	}
	if err := g.romix(B, len(passwords)*v.p, steps); err != nil {
		return nil, err
	}
	derived := make([][]byte, len(passwords))
	for i, pass := range transformed {
		var err error
		derived[i], err = pbkdf2Derive(pass, B[i*v.p*blocklen:(i+1)*v.p*blocklen], 1, v.dklen, false)
		if err != nil {
			return nil, err
		}
	}
	return derived, nil
}
