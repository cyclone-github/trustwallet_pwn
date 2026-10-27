[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=trustwallet_pwn&theme=gruvbox)](https://github.com/cyclone-github/trustwallet_pwn/)

[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/trustwallet_pwn.svg)](https://github.com/cyclone-github/trustwallet_pwn/issues)
[![License](https://img.shields.io/github/license/cyclone-github/trustwallet_pwn.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/trustwallet_pwn.svg)](https://github.com/cyclone-github/trustwallet_pwn/releases)

# trustwallet_pwn

### Install trustwallet_extractor
```
go install github.com/cyclone-github/trustwallet_pwn/trustwallet_extractor@main
```

### Install trustwallet_decryptor
```
go install github.com/cyclone-github/trustwallet_pwn/trustwallet_decryptor@main
```

---

### Toolset to recover, extract and decrypt TrustWallet vaults

_This toolset extracts and decrypts Chrome-based TrustWallet browser extension wallets and compatible Trust Wallet V3 JSON keystores._

- Contact me at https://forum.hashpwn.net/user/cyclone if you need help recovering your TrustWallet password or seed phrase

---

# TrustWallet vault location for Chrome extensions

### Linux
```
/home/$USER/.config/google-chrome/Default/Local\ Extension\ Settings/egjidjbpglichdcondbcbdnbeeppgdph/
```

### Mac
```
Library>Application Support>Google>Chrome>Default>Local Extension Settings>egjidjbpglichdcondbcbdnbeeppgdph
```

### Windows
```
C:\Users\$USER\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\egjidjbpglichdcondbcbdnbeeppgdph\
```

---

# Extractor usage example

Example test wallet with password: `Cyclone!`

```
./trustwallet_extractor.bin egjidjbpglichdcondbcbdnbeeppgdph/

 ------------------------------------------------------- 
|       Cyclone's TrustWallet Vault Hash Extractor      |
|       Use TrustWallet Vault Decryptor to decrypt      |
|   https://github.com/cyclone-github/trustwallet_pwn   |
 ------------------------------------------------------- 
{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"8cc8cf025dab07940b2fb5594c65a39d"},"ciphertext":"a45b57056b2fab289b44d18f54af43ed5e523505009a8f35ad57496d74fb43f6d6248926a49b6c2e1df1debad6ea532f826ad637f65cc831d7cbf46c38490f07d9d1691c67aa02a4c7ca","kdf":"scrypt","kdfparams":{"dklen":32,"n":16384,"p":4,"r":8,"salt":"c302622d54247a7eeef2b33e2925c0875a89c52d6c9a5856694f6d262ae7f18e"},"mac":"acef4b2b49067c235693661964520773a4d910d3e061f7c314f4e4ac07970a1b"},"trust:pbkdf2":{"salt":"0x39c0f6ce6c2559f91feba0d6624c9a8fb948ab669abd1cfdba3af19bbcded280"},"trust:vault":{"data":"kLg6MvRVZcfFxlzQoEED5W+lscfxBoThMlD9LxCeUHZIoo9mcQp/4uKcNiPRvw2ySGnLe3cflNttI2E0hzMcnckKW3aQE0VuDH4f2hCHsIG9r+uXILqRN5qQlMPH2GiEtMi5+YBM7J0LRNqtes3vE3IYjl3y3bDNoa24l+WFU7Dw6G883Qc=","iv":"ngwjYPZYg4pAQtGQKJfc7g==","salt":"hy31Q6pn9oEfzTkX6YD6BgixlEkBj0i5pmRbEk9d4sM="}}
```

### Extract from a Trust Wallet JSON file

```
./trustwallet_extractor.bin wallet.json
```

---

# Decryptor usage example

```
./trustwallet_decryptor.bin -h trustwallet.txt -w wordlist.txt

 --------------------------------------------------- 
|       Cyclone's TrustWallet Vault Decryptor       |
| https://github.com/cyclone-github/trustwallet_pwn |
 --------------------------------------------------- 

Vault file:     trustwallet.txt
Valid Vaults:   1
CPU Threads:    16
GPU:            1 (NVIDIA GeForce RTX 4090)
Wordlist:       wordlist.txt
Backend:        Hybrid/GPU+CPU (16 CPU workers)
Self-test:      CPU PASS; GPU 0 PASS
2026/10/27 12:10:49 Working...
Password: Cyclone!
Decrypted: tell priority insane episode hamster click list gym juice valve damp swamp
2026/10/27 12:11:48 Finished
2026/10/27 12:11:48 Decrypted: 1/1 815.93 h/s 00h:00m:59s ETA: 00h:00m:00s
```

---

# Decryptor supported options

```
-w {wordlist} (omit -w to read from stdin)
-h {trustwallet_hash_file}
-o {output} (omit -o to write to stdout)
-t {cpu threads}
-s {print status every nth sec}

-cpu                CPU only
-gpu                OpenCL GPU only (Linux with cgo)
-hybrid             CPU + GPU workers (Linux with cgo)
-gpu-list           list OpenCL devices
-gpu-devices 0,1    select GPU indices (default all)
-gpu-mem 92         target GPU VRAM percentage
-gpu-batch 0        batch size (default auto)
-gpu-step 0         kernel step (default auto)
-gpu-verbose        print GPU tuning
-chunk k/n          contiguous wordlist partition

-version (version info)
-help (usage instructions)
```

Examples:

```bash
./trustwallet_decryptor.bin -h trustwallet.txt -w wordlist.txt -o cracked.txt -t 16 -s 10

cat wordlist | ./trustwallet_decryptor.bin -h trustwallet.txt

./trustwallet_decryptor.bin -h trustwallet.txt -w wordlist.txt -chunk 1/4
```

The elapsed time and ETA are reported for wordlist files (or the selected chunk). ETA is unavailable with stdin input. On Linux with an available OpenCL GPU, the default backend preference is hybrid, GPU, then CPU. On other platforms, CPU mode is available.

---

# Compile from source

This assumes Go and Git are installed. Linux GPU builds additionally need a C compiler and the OpenCL ICD loader.

```bash
git clone https://github.com/cyclone-github/trustwallet_pwn.git
```

### trustwallet_extractor

```bash
cd trustwallet_pwn/trustwallet_extractor
go mod tidy
go build -ldflags="-s -w" .
go install -ldflags="-s -w" .
```

### trustwallet_decryptor

```bash
cd trustwallet_pwn/trustwallet_decryptor
go mod tidy
go build -ldflags="-s -w" .
go install -ldflags="-s -w" .
```

CPU-only builds on Windows or macOS:

```bash
CGO_ENABLED=0 go build -o trustwallet_decryptor .
```

On Linux with GPU support:

```bash
CGO_ENABLED=1 go build -o trustwallet_decryptor.bin .
```

---

### Compile from source guide

```
https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
```

---

### Source credits

- [GoLevelDB](https://github.com/syndtr/goleveldb) by syndtr (BSD-2-Clause) and [Snappy](https://github.com/golang/snappy) (BSD-3-Clause) for extension extraction
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto), the original Go crypto dependency, for scrypt and PBKDF2
- [Khronos OpenCL](https://registry.khronos.org/OpenCL/) for the GPU API; `bridge.c` uses the system OpenCL ICD loader
- [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914), the scrypt ROMix/BlockMix algorithm by Colin Percival, used by the OpenCL kernel in `romix.cl`
- [Keccak team](https://keccak.team/) specification for legacy Keccak-256 MAC verification

The `romix.cl` and OpenCL bridge code in this package were developed for this project. See [LICENSE](LICENSE) for the project's license info.