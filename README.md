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

_This toolset extracts and decrypts Chrome-based TrustWallet browser extension wallets._

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

---

# Decryptor usage example

```
./trustwallet_decryptor.bin -h trustwallet.txt -w wordlist.txt

 -------------------------------------------------- 
|      Cyclone's TrustWallet Vault Decryptor       |
| https://github.com/cyclone-github/trustwallet_pwn |
 -------------------------------------------------- 

Vault file:     trustwallet.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
2026/03/05 09:19:08 Working...
Password: Cyclone!
Decrypted: tell priority insane episode hamster click list gym juice valve damp swamp
2026/03/05 09:19:09 Decrypted: 1/1 12.87 h/s 00h:00m:01s

2026/03/05 09:19:09 Finished

```

---

# Decryptor supported options

```
-w {wordlist} (omit -w to read from stdin)
-h {trustwallet_hash_file}
-o {output} (omit -o to write to stdout)
-t {cpu threads}
-s {print status every nth sec}

-version (version info)
-help (usage instructions)
```

Example:

```
./trustwallet_decryptor.bin -h trustwallet.txt -w wordlist.txt -o cracked.txt -t 16 -s 10

cat wordlist | ./trustwallet_decryptor.bin -h trustwallet.txt

./trustwallet_decryptor.bin -h trustwallet.txt -w wordlist.txt -o output.txt
```

---

# Compile from source

This assumes Go and Git are installed.

```
git clone https://github.com/cyclone-github/trustwallet_pwn.git
```

### trustwallet_extractor

```
cd trustwallet_pwn/trustwallet_extractor
go mod init trustwallet_extractor
go mod tidy
go build -ldflags="-s -w" .
go install -ldflags="-s -w" .
```

### trustwallet_decryptor

```
cd trustwallet_pwn/trustwallet_decryptor
go mod init trustwallet_decryptor
go mod tidy
go build -ldflags="-s -w" .
go install -ldflags="-s -w" .
```

---

### Compile from source guide

```
https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
```