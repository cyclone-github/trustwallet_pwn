<!--
[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=trustwallet_pwn&theme=gruvbox)](https://github.com/cyclone-github/trustwallet_pwn/)

[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/trustwallet_pwn.svg)](https://github.com/cyclone-github/trustwallet_pwn/issues)
[![License](https://img.shields.io/github/license/cyclone-github/trustwallet_pwn.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/trustwallet_pwn.svg)](https://github.com/cyclone-github/trustwallet_pwn/releases)
-->

# trustwallet_pwn
Toolset to extract and decrypt trustwallet crypto vaults
- Contact me at https://forum.hashpwn.net/user/cyclone if you need help recovering your trustwallet password or seed phrase

# trustwallet Vault Hash Extractor
Tool to extract trustwallet vaults to JSON

### Info:
- trustwallet JSON vaults can be decrypted with https://github.com/cyclone-github/trustwallet_pwn

### trustwallet Vault location for Chrome extensions:
- Linux: `/home/$USER/.config/google-chrome/Default/Local\ Extension\ Settings/egjidjbpglichdcondbcbdnbeeppgdph/`
- Mac: `Library>Application Support>Google>Chrome>Default>Local Extension Settings>egjidjbpglichdcondbcbdnbeeppgdph`
- Windows `C:\Users\$USER\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\egjidjbpglichdcondbcbdnbeeppgdph`

### Usage:
- Linux: `./trustwallet_extractor.bin {trustwallet_vault_dir}`
- Windows: `trustwallet_extractor.exe {trustwallet_vault_dir}`

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/trustwallet_pwn.git`  # clone repo
  - `cd trustwallet_pwn/trustwallet_extractor`                            # enter project directory
  - `go mod init trustwallet_extractor`                                # initialize Go module (skips if go.mod exists)
  - `go mod tidy`                                                   # download dependencies
  - `go build -ldflags="-s -w" .`                                   # compile binary in current directory
  - `go install -ldflags="-s -w" .`                                 # compile binary and install to $GOPATH
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt

# trustwallet Vault Decryptor
### POC tool to decrypt trustwallet vault wallets
_**This tool is proudly the first publicly released trustwallet Vault decryptor / cracker to support trustwallets.**_
```
./trustwallet_decryptor_amd64.bin -h trustwallet_json.txt -w wordlist.txt
 --------------------------------------- 
| Cyclone's Trustwallet Vault Decryptor |
 --------------------------------------- 

Vault file:     trustwallet_json.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
Working...

Decrypted: 0/1  5430.89 h/s     00h:01m:00s
```
### Info:
- If you need help extracting trustwallet vaults, use `trustwallet_extractor` https://github.com/cyclone-github/trustwallet_pwn

### Example vaults supported:
- vault format: `{"data": "","iv": "","salt": ""}`

### Usage example:
- `./trustwallet_decryptor.bin -h {wallet_json} -w {wordlist}`

### Output example:
If the tool successfully decrypts the vault, tool will print the vault json, seed phrase and vault password
```
Decrypted Vault: '{}'
Seed Phrase:    ''
Vault Password: ''
```

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/trustwallet_pwn.git`  # clone repo
  - `cd trustwallet_pwn/trustwallet_decryptor`                            # enter project directory
  - `go mod init trustwallet_decryptor`                                # initialize Go module (skips if go.mod exists)
  - `go mod tidy`                                                   # download dependencies
  - `go build -ldflags="-s -w" .`                                   # compile binary in current directory
  - `go install -ldflags="-s -w" .`                                 # compile binary and install to $GOPATH
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
