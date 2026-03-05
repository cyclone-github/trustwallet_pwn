package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
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
	"golang.org/x/crypto/sha3"
)

// TrustWallet vault entry
type Vault struct {
	Cipher     string
	IV         []byte
	Ciphertext []byte
	KDF        string
	Salt       []byte
	Dklen      int
	N          int // scrypt
	R          int // scrypt
	P          int // scrypt
	C          int // pbkdf2 iteration count
	Mac        string
	PreSalt    []byte // pre-PBKDF2 salt, nil if not applicable
	VaultData  string // trust:vault base64 data, empty if not applicable
	Decrypted  int32
	VaultText  string
}

// JSON parsing types
type keyFile struct {
	Crypto      cryptoParams `json:"crypto"`
	TrustPBKDF2 *pbkdf2Trust `json:"trust:pbkdf2,omitempty"`
	TrustVault  *vaultTrust  `json:"trust:vault,omitempty"`
}

type pbkdf2Trust struct {
	Salt string `json:"salt"`
}

type vaultTrust struct {
	Data string `json:"data"`
}

type cryptoParams struct {
	Cipher       string `json:"cipher"`
	CipherParams struct {
		IV string `json:"iv"`
	} `json:"cipherparams"`
	Ciphertext string    `json:"ciphertext"`
	KDF        string    `json:"kdf"`
	KDFParams  kdfParams `json:"kdfparams"`
	Mac        string    `json:"mac"`
}

type kdfParams struct {
	Dklen int    `json:"dklen"`
	Salt  string `json:"salt"`
	N     int    `json:"n,omitempty"`
	R     int    `json:"r,omitempty"`
	P     int    `json:"p,omitempty"`
	C     int    `json:"c,omitempty"`
}

func hexify(b []byte) string { return hex.EncodeToString(b) }

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("invalid padding size")
	}
	pad := int(data[len(data)-1])
	if pad <= 0 || pad > aes.BlockSize {
		return nil, errors.New("invalid padding")
	}
	for _, v := range data[len(data)-pad:] {
		if int(v) != pad {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-pad], nil
}

// isValid function as placeholder, always returning true
func isValid(s []byte) bool {
	return true
}

// decryptVault decrypts a TrustWallet vault entry with the given password
func decryptVault(vault *Vault, password []byte) ([]byte, error) {
	pw := string(password)

	// pre-PBKDF2 derivation if applicable
	if vault.PreSalt != nil {
		pre := pbkdf2.Key([]byte(pw), vault.PreSalt, 20000, 512, sha512.New)
		pw = "0x" + hexify(pre)
	}

	// key derivation
	var dk []byte
	var err error
	switch vault.KDF {
	case "scrypt":
		dk, err = scrypt.Key([]byte(pw), vault.Salt, vault.N, vault.R, vault.P, vault.Dklen)
	case "pbkdf2":
		count := vault.C
		if count == 0 {
			count = 100000
		}
		dk = pbkdf2.Key([]byte(pw), vault.Salt, count, vault.Dklen, sha256.New)
	default:
		return nil, fmt.Errorf("unsupported KDF: %s", vault.KDF)
	}
	if err != nil {
		return nil, err
	}

	// MAC validation
	macData := append(dk[16:], vault.Ciphertext...)
	if hexify(keccak256(macData)) != vault.Mac {
		return nil, errors.New("MAC mismatch")
	}

	// decrypt
	keyLen := 32
	if strings.HasPrefix(vault.Cipher, "aes-128-") {
		keyLen = 16
	}
	block, err := aes.NewCipher(dk[:keyLen])
	if err != nil {
		return nil, err
	}

	var plain []byte
	switch {
	case strings.HasSuffix(vault.Cipher, "-ctr"):
		stream := cipher.NewCTR(block, vault.IV)
		plain = make([]byte, len(vault.Ciphertext))
		stream.XORKeyStream(plain, vault.Ciphertext)
	case strings.HasSuffix(vault.Cipher, "-cbc"):
		mode := cipher.NewCBCDecrypter(block, vault.IV)
		tmp := make([]byte, len(vault.Ciphertext))
		mode.CryptBlocks(tmp, vault.Ciphertext)
		plain, err = pkcs7Unpad(tmp)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported cipher mode: %s", vault.Cipher)
	}

	if utf8.Valid(plain) {
		return plain, nil
	}
	// fallback vault
	if vault.VaultData != "" {
		vd, err := base64.StdEncoding.DecodeString(vault.VaultData)
		if err == nil {
			return vd, nil
		}
	}
	return plain, nil
}

// parse TrustWallet vault file
func readVaultData(filePath string) ([]Vault, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var vaults []Vault
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var kf keyFile
		if err := json.Unmarshal([]byte(line), &kf); err != nil {
			log.Printf("Error parsing JSON: %v\n", err)
			continue
		}

		// sanity checks for TrustWallet vault
		if kf.Crypto.Cipher == "" ||
			(kf.Crypto.KDF != "scrypt" && kf.Crypto.KDF != "pbkdf2") ||
			kf.Crypto.Ciphertext == "" ||
			kf.Crypto.KDFParams.Salt == "" ||
			kf.Crypto.Mac == "" {
			log.Printf("Invalid or incomplete data encountered in JSON: %v\n", line)
			continue
		}

		iv, err := hex.DecodeString(kf.Crypto.CipherParams.IV)
		if err != nil {
			log.Printf("Error decoding IV: %v\n", err)
			continue
		}
		ciphertext, err := hex.DecodeString(kf.Crypto.Ciphertext)
		if err != nil {
			log.Printf("Error decoding ciphertext: %v\n", err)
			continue
		}
		salt, err := hex.DecodeString(kf.Crypto.KDFParams.Salt)
		if err != nil {
			log.Printf("Error decoding salt: %v\n", err)
			continue
		}

		vault := Vault{
			Cipher:     kf.Crypto.Cipher,
			IV:         iv,
			Ciphertext: ciphertext,
			KDF:        kf.Crypto.KDF,
			Salt:       salt,
			Dklen:      kf.Crypto.KDFParams.Dklen,
			N:          kf.Crypto.KDFParams.N,
			R:          kf.Crypto.KDFParams.R,
			P:          kf.Crypto.KDFParams.P,
			C:          kf.Crypto.KDFParams.C,
			Mac:        kf.Crypto.Mac,
			VaultText:  line,
		}

		if kf.TrustPBKDF2 != nil {
			saltHex := strings.TrimPrefix(kf.TrustPBKDF2.Salt, "0x")
			preSalt, err := hex.DecodeString(saltHex)
			if err != nil {
				log.Printf("Error decoding pre-PBKDF2 salt: %v\n", err)
				continue
			}
			vault.PreSalt = preSalt
		}

		if kf.TrustVault != nil {
			vault.VaultData = kf.TrustVault.Data
		}

		vaults = append(vaults, vault)
	}

	return vaults, nil
}
