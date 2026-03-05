package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/table"
)

/*
Cyclone's TrustWallet Vault Extractor
https://github.com/cyclone-github/trustwallet_pwn
POC tool to extract TrustWallet vaults

GNU General Public License v2.0
https://github.com/cyclone-github/trustwallet_pwn/blob/main/LICENSE

version history
v0.1.0; 2025-03-04;
	initial release
v0.2.0; 2026-03-05;
	github release
*/

// clear screen function
func clearScreen() {
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

// version func
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's TrustWallet Vault Extractor v0.2.0; 2026-03-05\nhttps://github.com/cyclone-github/trustwallet_pwn\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:
./trustwallet_extractor.bin [-version] [-help] [trustwallet_vault_dir]
./trustwallet_extractor.bin egjidjbpglichdcondbcbdnbeeppgdph/

Default TrustWallet vault locations for Chrome extensions:

Linux:
/home/$USER/.config/google-chrome/Default/Local\ Extension\ Settings/egjidjbpglichdcondbcbdnbeeppgdph/

Mac:
Library>Application Support>Google>Chrome>Default>Local Extension Settings>egjidjbpglichdcondbcbdnbeeppgdph

Windows:
C:\Users\$USER\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\egjidjbpglichdcondbcbdnbeeppgdph\`
	fmt.Fprintln(os.Stderr, str)
}

// print welcome screen
func printWelcomeScreen() {
	fmt.Println(" ------------------------------------------------------- ")
	fmt.Println("|       Cyclone's TrustWallet Vault Hash Extractor      |")
	fmt.Println("|       Use TrustWallet Vault Decryptor to decrypt      |")
	fmt.Println("|   https://github.com/cyclone-github/trustwallet_pwn   |")
	fmt.Println(" ------------------------------------------------------- ")
}

func extractBalancedJSON(raw string, start int) (string, int, bool) {
	depth := 0
	inString := false
	escape := false
	for i := start; i < len(raw); i++ {
		ch := raw[i]
		if escape {
			escape = false
			continue
		}
		if ch == '\\' && inString {
			escape = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		if ch == '{' {
			depth++
		} else if ch == '}' {
			depth--
			if depth == 0 {
				return raw[start : i+1], i, true
			}
		}
	}
	return "", 0, false
}

func extractCryptoFromJSON(jsonStr string) (json.RawMessage, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
		return nil, false
	}
	cryptoRaw, hasCrypto := obj["crypto"]
	if !hasCrypto {
		return nil, false
	}

	var crypto map[string]json.RawMessage
	if err := json.Unmarshal(cryptoRaw, &crypto); err != nil {
		return nil, false
	}
	for _, key := range []string{"cipher", "ciphertext", "kdf", "kdfparams", "mac"} {
		if _, ok := crypto[key]; !ok {
			return nil, false
		}
	}

	return cryptoRaw, true
}

func buildVaultHash(cryptoRaw, trustPBKDF2, trustVault json.RawMessage) (string, bool) {
	out := map[string]json.RawMessage{
		"crypto": cryptoRaw,
	}
	if len(trustPBKDF2) > 0 {
		out["trust:pbkdf2"] = trustPBKDF2
	}
	if len(trustVault) > 0 {
		out["trust:vault"] = trustVault
	}

	b, err := json.Marshal(out)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func unquoteJSON(raw []byte) json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 1 && trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err == nil {
			return json.RawMessage(s)
		}
	}
	return json.RawMessage(trimmed)
}

func printVaultHash(data []byte, trustPBKDF2, trustVault json.RawMessage, seen map[string]bool) {
	raw := string(data)
	if !strings.Contains(raw, `"crypto"`) || !strings.Contains(raw, `"ciphertext"`) {
		return
	}

	offset := 0
	for offset < len(raw) {
		idx := strings.IndexByte(raw[offset:], '{')
		if idx < 0 {
			break
		}
		pos := offset + idx

		jsonStr, end, ok := extractBalancedJSON(raw, pos)
		if !ok {
			offset = pos + 1
			continue
		}

		cryptoRaw, ok := extractCryptoFromJSON(jsonStr)
		if ok {
			var obj map[string]json.RawMessage
			json.Unmarshal([]byte(jsonStr), &obj)
			pbkdf2 := trustPBKDF2
			vault := trustVault
			if existing, ok := obj["trust:pbkdf2"]; ok {
				pbkdf2 = existing
			}
			if existing, ok := obj["trust:vault"]; ok {
				vault = existing
			}

			if hash, ok := buildVaultHash(cryptoRaw, pbkdf2, vault); ok {
				if !seen[hash] {
					seen[hash] = true
					fmt.Println(hash)
				}
			}
		}

		offset = end + 1
	}
}

func processLevelDB(db *leveldb.DB) {
	var trustPBKDF2 json.RawMessage
	var trustVault json.RawMessage
	var vaultValues [][]byte

	iter := db.NewIterator(nil, nil)
	for iter.Next() {
		key := string(iter.Key())
		val := iter.Value()

		switch key {
		case "trust:pbkdf2":
			trustPBKDF2 = unquoteJSON(val)
		case "trust:vault":
			trustVault = unquoteJSON(val)
		default:
			if bytes.Contains(val, []byte(`"crypto"`)) && bytes.Contains(val, []byte(`"ciphertext"`)) {
				v := make([]byte, len(val))
				copy(v, val)
				vaultValues = append(vaultValues, v)
			}
		}
	}
	iter.Release()

	seen := make(map[string]bool)
	for _, val := range vaultValues {
		printVaultHash(val, trustPBKDF2, trustVault, seen)
	}
}

func filterPrintableBytes(data []byte) []byte {
	printable := make([]rune, 0, len(data))
	for _, b := range data {
		if unicode.IsPrint(rune(b)) {
			printable = append(printable, rune(b))
		} else {
			printable = append(printable, '.')
		}
	}
	return []byte(string(printable))
}

func dumpRawLDBFiles(dirPath string) error {
	var trustPBKDF2, trustVault json.RawMessage
	var vaultValues [][]byte

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Failed to access path %s: %v", path, err)
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".ldb") {
			return nil
		}
		collectRawLDBFile(path, &trustPBKDF2, &trustVault, &vaultValues)
		return nil
	})
	if err != nil {
		return err
	}

	seen := make(map[string]bool)
	for _, val := range vaultValues {
		printVaultHash(filterPrintableBytes(val), trustPBKDF2, trustVault, seen)
	}
	return nil
}

func collectRawLDBFile(filePath string, trustPBKDF2, trustVault *json.RawMessage, vaultValues *[][]byte) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Failed to open file %s: %v", filePath, err)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Failed to get file info %s: %v", filePath, err)
		return
	}

	reader, err := table.NewReader(file, fileInfo.Size(), storage.FileDesc{Type: storage.TypeTable, Num: 0}, nil, nil, &opt.Options{})
	if err != nil {
		log.Printf("Failed to create table reader %s: %v", filePath, err)
		return
	}
	defer reader.Release()

	iter := reader.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		value := iter.Value()
		filtered := filterPrintableBytes(value)

		switch {
		case strings.Contains(key, "trust:pbkdf2") || strings.Contains(string(filtered), `"salt":"0x`):
			if len(*trustPBKDF2) == 0 {
				raw := string(filtered)
				if idx := strings.Index(raw, `{"salt":"0x`); idx >= 0 {
					if j, _, ok := extractBalancedJSON(raw, idx); ok {
						*trustPBKDF2 = json.RawMessage(j)
					}
				} else {
					p := unquoteJSON(filtered)
					if json.Valid(p) {
						*trustPBKDF2 = p
					}
				}
			}
		case strings.Contains(key, "trust:vault") || (strings.Contains(string(filtered), `"data"`) && strings.Contains(string(filtered), `"iv"`)):
			if len(*trustVault) == 0 {
				raw := string(filtered)
				if idx := strings.Index(raw, `{"data":"`); idx >= 0 {
					if j, _, ok := extractBalancedJSON(raw, idx); ok {
						if strings.Contains(j, `"iv"`) && strings.Contains(j, `"salt"`) {
							*trustVault = json.RawMessage(j)
						}
					}
				} else {
					v := unquoteJSON(filtered)
					if json.Valid(v) {
						*trustVault = v
					}
				}
			}
		default:
			if bytes.Contains(filtered, []byte(`"crypto"`)) && bytes.Contains(filtered, []byte(`"ciphertext"`)) {
				v := make([]byte, len(filtered))
				copy(v, filtered)
				*vaultValues = append(*vaultValues, v)
			}
		}
	}
}

// main
func main() {
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version")
	helpFlag := flag.Bool("help", false, "Program usage instructions")
	flag.Parse()

	clearScreen()

	// run sanity checks for special flags
	if *versionFlag {
		versionFunc()
		os.Exit(0)
	}
	if *cycloneFlag {
		line := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		str, _ := base64.StdEncoding.DecodeString(line)
		fmt.Println(string(str))
		os.Exit(0)
	}
	if *helpFlag {
		helpFunc()
		os.Exit(0)
	}

	ldbDir := flag.Arg(0)
	if ldbDir == "" {
		fmt.Fprintln(os.Stderr, "Error: TrustWallet vault directory is required")
		helpFunc()
		os.Exit(1)
	}

	printWelcomeScreen()

	db, err := leveldb.OpenFile(ldbDir, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error opening Vault:", err)
		fmt.Println("Attempting to dump raw .ldb files...")
		err = dumpRawLDBFiles(ldbDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to dump raw .ldb files: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	defer db.Close()

	processLevelDB(db)
}

// end code
