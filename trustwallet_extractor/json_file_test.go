package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONHash(t *testing.T) {
	// use sample wallet from the decryptor self-test
	example := []byte(cycloneTestWalletJSON)
	out, err := hashFromJSON(example)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if len(v) != 3 || len(v["crypto"]) == 0 || len(v["trust:pbkdf2"]) == 0 || len(v["trust:vault"]) == 0 {
		t.Fatalf("unexpected keys: %v", v)
	}
	var orig map[string]json.RawMessage
	if err := json.Unmarshal(example, &orig); err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err := json.Unmarshal(v["crypto"], &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(orig["crypto"], &b); err != nil {
		t.Fatal(err)
	}
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(aa) != string(bb) {
		t.Fatal("crypto object changed")
	}
}
func TestRejectedJSON(t *testing.T) {
	for _, s := range []string{
		`null`, `{}`, `not json`,
		`{"crypto":{"cipher":"aes-128-ctr","kdf":"argon2id"}}`,
		`{"crypto":{"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"n":16384,"r":8,"p":4,"dklen":32,"salt":""}}}`,
	} {
		if _, err := hashFromJSON([]byte(s)); err == nil {
			t.Fatalf("accepted invalid %q", s)
		}
	}
}
func TestUppercaseCryptoAndExtensionFields(t *testing.T) {
	raw := []byte(cycloneTestWalletJSON)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["Crypto"] = doc["crypto"]
	delete(doc, "crypto")
	upper, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	out, err := hashFromJSON(upper)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `"Crypto"`) || !strings.Contains(out, `"crypto"`) || !strings.Contains(out, `"trust:pbkdf2"`) || !strings.Contains(out, `"trust:vault"`) {
		t.Fatal(out)
	}
}

func TestJSONFileOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cyclone-wallet.json")
	if err := os.WriteFile(path, []byte(cycloneTestWalletJSON), 0600); err != nil {
		t.Fatal(err)
	}
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writeEnd
	err = processJSONFile(path)
	writeEnd.Close()
	os.Stdout = original
	defer readEnd.Close()
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(readEnd)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) < 3 || output[0] != '{' || output[len(output)-1] != '\n' {
		t.Fatalf("expected a single JSON hash line, got %q", output)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(output), &value); err != nil {
		t.Fatal(err)
	}
	if len(value["crypto"]) == 0 {
		t.Fatal("missing crypto")
	}
}

// cyclone test fixture
const cycloneTestWalletJSON = `{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"8cc8cf025dab07940b2fb5594c65a39d"},"ciphertext":"a45b57056b2fab289b44d18f54af43ed5e523505009a8f35ad57496d74fb43f6d6248926a49b6c2e1df1debad6ea532f826ad637f65cc831d7cbf46c38490f07d9d1691c67aa02a4c7ca","kdf":"scrypt","kdfparams":{"dklen":32,"n":16384,"p":4,"r":8,"salt":"c302622d54247a7eeef2b33e2925c0875a89c52d6c9a5856694f6d262ae7f18e"},"mac":"acef4b2b49067c235693661964520773a4d910d3e061f7c314f4e4ac07970a1b"},"trust:pbkdf2":{"salt":"0x39c0f6ce6c2559f91feba0d6624c9a8fb948ab669abd1cfdba3af19bbcded280"},"trust:vault":{"data":"kLg6MvRVZcfFxlzQoEED5W+lscfxBoThMlD9LxCeUHZIoo9mcQp/4uKcNiPRvw2ySGnLe3cflNttI2E0hzMcnckKW3aQE0VuDH4f2hCHsIG9r+uXILqRN5qQlMPH2GiEtMi5+YBM7J0LRNqtes3vE3IYjl3y3bDNoa24l+WFU7Dw6G883Qc=","iv":"ngwjYPZYg4pAQtGQKJfc7g==","salt":"hy31Q6pn9oEfzTkX6YD6BgixlEkBj0i5pmRbEk9d4sM="}}`
