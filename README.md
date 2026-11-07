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

> **Windows users:** For GPU acceleration (OpenCL), download the latest [precompiled release](https://github.com/cyclone-github/trustwallet_pwn/releases) or follow the manual compilation instructions at the bottom of this README.
>
> Windows GPU builds require CGO, a compatible C compiler, and OpenCL linking dependencies. The standard `go install` command does not configure these dependencies automatically. With CGO disabled, it installs a CPU-only version; without the required build dependencies, installation may fail. Linux users with the required OpenCL dependencies can install GPU support directly using the `go install` command below.
```bash
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
~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/egjidjbpglichdcondbcbdnbeeppgdph/
```

### Windows
```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\egjidjbpglichdcondbcbdnbeeppgdph\
```

---

# Extractor usage example

Example test wallet with password: `Cyclone1!`

```
./trustwallet_extractor.bin egjidjbpglichdcondbcbdnbeeppgdph/

 ------------------------------------------------------- 
|       Cyclone's TrustWallet Vault Hash Extractor      |
|       Use TrustWallet Vault Decryptor to decrypt      |
|   https://github.com/cyclone-github/trustwallet_pwn   |
 ------------------------------------------------------- 
{"crypto":{"ciphertext":"cc14f10a70fc179c9677510de4b8d3ac9997b691b43ae0df4b9f60a230b8e1d492e8eec9e18ad36ab956a222270fbb9263eaa7a6227815681f016066495e8d765be877a21ae088b2a8d453c8","cipherparams":{"iv":"b4b1db828f3e48aa997869d6e548bd75"},"kdf":"scrypt","kdfparams":{"r":8,"p":4,"n":16384,"dklen":32,"salt":"e7fd82a22a61bb84e8b52b1d95e52b28d06bce1d54452363d81e63f5e2736265"},"mac":"6b7ff48ce83f22d665ce1012dad0f4c8c05594e6c939d6f988b82920f01861b6","cipher":"aes-128-ctr"}}
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
CPU Threads:    56
GPU:            2 (2 x NVIDIA GeForce RTX 4090)
Wordlist:       wordlist.txt
Backend:        Hybrid/GPU+CPU (56 CPU workers)
Self-test:      CPU PASS; GPU 0 PASS; GPU 1 PASS
GPU 0 auto-tune (cache): N=16384 p=4 batch=346 workgroup=8 (ROMix 1351.3 candidates/s; CPU prep threads=1)
GPU 1 auto-tune (cache): N=16384 p=4 batch=346 workgroup=8 (ROMix 1351.3 candidates/s; CPU prep threads=1)
2026/11/07 12:10:49 Working...
Password: Cyclone1!
Decrypted: brush lobster receive image embody rate whip moral cheese vintage vault slot
2026/11/07 12:11:48 Finished
2026/11/07 12:11:48 Decrypted: 1/1 2689.50 h/s 00h:00m:59s ETA: 00h:00m:00s
```

---

# Decryptor supported options

```
-w {wordlist} (omit -w to read from stdin)
-h {trustwallet_hash_file}
-o {output} (omit -o to write to stdout)
-t {cpu threads}
-s {print status every nth sec}

-cpu                 CPU only
-gpu                 OpenCL GPU only (Linux/Windows amd64 with cgo)
-hybrid              CPU + GPU workers (Linux/Windows amd64 with cgo)
-gpu-list            list OpenCL devices
-gpu-devices 0,1     select GPU indices (default all)
-gpu-mem 92          target GPU VRAM percentage
-gpu-batch 0         batch size (default auto)
-gpu-step 0          kernel step (default auto)
-gpu-workgroup -1    workgroup size (-1=auto, 0=driver default)
-gpu-prethreads 0    GPU CPU preparation threads (default auto)
-gpu-pipeline        CPU/GPU pipeline overlap (enabled by default)
-gpu-pipeline=false  disable CPU/GPU pipeline overlap
-gpu-verbose         print GPU tuning
-chunk k/n           contiguous wordlist partition
-wordlist-reindex    rebuild cached wordlist index

-version (version info)
-help (usage instructions)
```

Examples:

```bash
./trustwallet_decryptor.bin -h trustwallet.txt -w wordlist.txt -o cracked.txt -t 16 -s 10

cat wordlist | ./trustwallet_decryptor.bin -h trustwallet.txt

./trustwallet_decryptor.bin -h trustwallet.txt -w wordlist.txt -chunk 1/4
```

The elapsed time and ETA are reported for wordlist files (or the selected chunk). ETA is unavailable with stdin input. On Linux or Windows amd64 with cgo and an available OpenCL GPU, the default backend preference is hybrid, GPU, then CPU, with automatic GPU preference for wallets requiring `trust:pbkdf2` preprocessing. On other platforms, CPU mode is available.

---

### Tested hash rates

> CPU
- `AMD Ryzen 7 3700X: 60 h/s` (cyclone, v0.3.8)
- `Intel Core i5-12600K: 85 h/s` (64_nickel, v0.3.5)
- `2x Intel Xeon E5-2690 v4: 156 h/s` (cyclone, v0.3.8)
- `AMD Threadripper 3960X: 186 h/s` (64_nickel, v0.3.5)

> GPU
- `RTX 4090: 1311 h/s` (cyclone, v0.3.8)
- `RTX 5090: 1601 h/s` (64_nickel, v0.3.6)

> CPU+GPU (hybrid - default mode)
- `Intel Core i9-14900HX + RTX 4090 Laptop GPU: 256 h/s` (64_nickel, v0.3.5)
- `AMD Threadripper 3960X + RTX 3090: 459 h/s` (64_nickel, v0.3.6)
- `2x Intel Xeon + 2x RTX 4090: 2689 h/s` (cyclone, v0.3.8)

---

# Compile from source

Requires Go 1.27.2 or newer, Git, and GNU Make. GPU builds additionally require a compatible C compiler and OpenCL dependencies.

```bash
git clone https://github.com/cyclone-github/trustwallet_pwn.git
cd trustwallet_pwn
```

### Install build dependencies

**Linux (Debian/Ubuntu):**

```bash
sudo apt install make gcc libopencl1
```

To also cross-compile Windows GPU binaries from Linux:

```bash
sudo apt install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64
```

**Windows:**

Install [MSYS2](https://www.msys2.org/) and open the **UCRT64 shell** with Go available on `PATH`.

```bash
pacman -S --needed make mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-binutils
```

### Build extractor and decryptor

Run from the repository root:

```bash
make all          # Linux/Windows x64 with GPU/OpenCL
make linux        # Linux x64 with GPU/OpenCL
make windows      # Windows x64 with GPU/OpenCL
make linux-cpu    # Linux x64 CPU-only
make windows-cpu  # Windows x64 CPU-only
```

Each command compiles **both the extractor and decryptor**, with binaries saved to `dist/linux_amd64/` or `dist/windows_amd64/`.

GPU builds automatically check for the required compiler and build dependencies, reporting missing tools when necessary. The Windows GPU build also generates the required OpenCL import library automatically.

CPU-only builds require only Go and GNU Make. GPU acceleration requires a compatible GPU, installed drivers, and an OpenCL runtime on the target system.

**Note:** The `make windows` target supports native Windows compilation and cross-compilation from Linux when MinGW-w64 is installed. Linux GPU builds are recommended on native Linux.

---

### Source credits

- [GoLevelDB](https://github.com/syndtr/goleveldb) by syndtr (BSD-2-Clause) and [Snappy](https://github.com/golang/snappy) (BSD-3-Clause) for extension extraction
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) for cryptographic functionality, including scrypt and PBKDF2
- [The Go Authors](https://go.googlesource.com/crypto/) for the adapted scrypt implementation with reusable scratch memory; see [THIRD_PARTY_SCRYPT_LICENSE.txt](trustwallet_decryptor/THIRD_PARTY_SCRYPT_LICENSE.txt)
- [Khronos OpenCL](https://registry.khronos.org/OpenCL/) for the GPU API; `bridge.c` uses the system OpenCL ICD loader
- [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914), the scrypt ROMix/BlockMix algorithm by Colin Percival, used by the OpenCL kernel in `romix.cl`
- [Keccak team](https://keccak.team/) specification for legacy Keccak-256 MAC verification

The `romix.cl` and OpenCL bridge code in this package were developed for this project. See [LICENSE](LICENSE) for the project's license info.
