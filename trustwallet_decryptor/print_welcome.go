package main

import (
	"fmt"
	"log"
	"os"
)

// version func
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's TrustWallet Vault Decryptor v0.2.0; 2026-03-05\nhttps://github.com/cyclone-github/trustwallet_pwn\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:

-w {wordlist} (omit -w to read from stdin)
-h {trustwallet_vault_hash}
-o {output} (omit -o to write to stdout)
-t {cpu threads}
-s {print status every nth sec}

-version (version info)
-help (usage instructions)

./trustwallet_decryptor.bin -h {trustwallet_vault_hash} -w {wordlist} -o {output} -t {cpu threads} -s {print status every nth sec}

./trustwallet_decryptor.bin -h trustwallet.txt -w wordlist.txt -o cracked.txt -t 16 -s 10

cat wordlist | ./trustwallet_decryptor.bin -h trustwallet.txt

./trustwallet_decryptor.bin -h trustwallet.txt -w wordlist.txt -o output.txt`
	fmt.Fprintln(os.Stderr, str)
}

// print welcome screen
func printWelcomeScreen(vaultFileFlag, wordlistFileFlag *string, validVaultCount, numThreads int) {
	fmt.Fprintln(os.Stderr, " -------------------------------------------------- ")
	fmt.Fprintln(os.Stderr, "|      Cyclone's TrustWallet Vault Decryptor       |")
	fmt.Fprintln(os.Stderr, "| https://github.com/cyclone-github/trustwallet_pwn |")
	fmt.Fprintln(os.Stderr, " -------------------------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Vault file:\t%s\n", *vaultFileFlag)
	fmt.Fprintf(os.Stderr, "Valid Vaults:\t%d\n", validVaultCount)
	fmt.Fprintf(os.Stderr, "CPU Threads:\t%d\n", numThreads)

	if *wordlistFileFlag == "" {
		fmt.Fprintf(os.Stderr, "Wordlist:\tReading stdin\n")
	} else {
		fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", *wordlistFileFlag)
	}

	log.Println("Working...")
}
