package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// extract trust wallet json crypto parameters
func hashFromJSON(raw []byte) (string, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("invalid wallet JSON: %w", err)
	}
	if doc == nil {
		return "", fmt.Errorf("expected a JSON object containing crypto")
	}

	cryptoRaw := doc["crypto"]
	if len(cryptoRaw) == 0 {
		// legacy v3 keystores may use uppercase crypto
		cryptoRaw = doc["Crypto"]
	}
	if len(cryptoRaw) == 0 {
		return "", fmt.Errorf("no crypto object in wallet JSON")
	}

	var c struct {
		Cipher       string `json:"cipher"`
		Ciphertext   string `json:"ciphertext"`
		CipherParams struct {
			IV string `json:"iv"`
		} `json:"cipherparams"`
		KDF       string `json:"kdf"`
		KDFParams struct {
			N     int    `json:"n"`
			R     int    `json:"r"`
			P     int    `json:"p"`
			DKLen int    `json:"dklen"`
			C     int    `json:"c"`
			Salt  string `json:"salt"`
		} `json:"kdfparams"`
		MAC string `json:"mac"`
	}
	if err := json.Unmarshal(cryptoRaw, &c); err != nil {
		return "", fmt.Errorf("invalid crypto object: %w", err)
	}

	// validate supported decryptor formats
	switch c.Cipher {
	case "aes-128-ctr", "aes-128-cbc", "aes-256-ctr", "aes-256-cbc":
	default:
		return "", fmt.Errorf("unsupported cipher %q", c.Cipher)
	}
	switch c.KDF {
	case "scrypt":
		if c.KDFParams.N < 2 || c.KDFParams.N&(c.KDFParams.N-1) != 0 || c.KDFParams.R < 1 || c.KDFParams.P < 1 {
			return "", fmt.Errorf("unsupported scrypt parameters")
		}
	case "pbkdf2":
		// decryptor uses fallback when pbkdf2 rounds are zero
	default:
		return "", fmt.Errorf("unsupported KDF %q", c.KDF)
	}
	if c.KDFParams.DKLen < 32 {
		return "", fmt.Errorf("invalid dklen")
	}
	salt, saltErr := hex.DecodeString(c.KDFParams.Salt)
	iv, ivErr := hex.DecodeString(c.CipherParams.IV)
	ciphertext, ctErr := hex.DecodeString(c.Ciphertext)
	mac, macErr := hex.DecodeString(c.MAC)
	if saltErr != nil || ivErr != nil || ctErr != nil || macErr != nil ||
		len(salt) == 0 || len(iv) != 16 || len(ciphertext) == 0 || len(mac) != 32 ||
		(c.Cipher[len(c.Cipher)-3:] == "cbc" && len(ciphertext)%16 != 0) {
		return "", fmt.Errorf("missing or invalid ciphertext, IV, salt, or MAC")
	}

	output := map[string]json.RawMessage{"crypto": cryptoRaw}
	for _, k := range []string{"trust:pbkdf2", "trust:vault"} {
		if v, exists := doc[k]; exists {
			output[k] = v
		}
	}
	compact, err := json.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("cannot encode wallet hash: %w", err)
	}
	return string(compact), nil
}

func processJSONFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	hash, err := hashFromJSON(raw)
	if err != nil {
		return err
	}
	fmt.Println(hash)
	return nil
}
