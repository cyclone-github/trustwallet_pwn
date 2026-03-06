package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

/*
Cyclone's TrustWallet Vault Decryptor
https://github.com/cyclone-github/trustwallet_pwn
POC tool to decrypt TrustWallet vaults

GNU General Public License v2.0
https://github.com/cyclone-github/trustwallet_pwn/blob/main/LICENSE

version history
v0.1.0; 2025-03-04
	initial release
v0.2.0; 2026-03-06
	github release
*/

// main func
func main() {
	wordlistFileFlag := flag.String("w", "", "Input file to process (omit -w to read from stdin)")
	vaultFileFlag := flag.String("h", "", "Vault File")
	outputFile := flag.String("o", "", "Output file to write hashes to (omit -o to print to console)")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version:")
	helpFlag := flag.Bool("help", false, "Prints help:")
	threadFlag := flag.Int("t", runtime.NumCPU(), "CPU threads to use (optional)")
	statsIntervalFlag := flag.Int("s", 60, "Interval in seconds for printing stats. Defaults to 60.")
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

	if *vaultFileFlag == "" {
		fmt.Fprintln(os.Stderr, "-h (vault file) flag is required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	startTime := time.Now()

	// set CPU threads
	numThreads := setNumThreads(*threadFlag)

	// variables
	var (
		crackedCount   int32
		linesProcessed int32
		wg             sync.WaitGroup
	)

	// channels
	stopChan := make(chan struct{})

	// goroutine to watch for ctrl+c
	handleGracefulShutdown(stopChan)

	// read vaults
	vaults, err := readVaultData(*vaultFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading vault file:", err)
		os.Exit(1)
	}
	validVaultCount := len(vaults)

	// print welcome screen
	printWelcomeScreen(vaultFileFlag, wordlistFileFlag, validVaultCount, numThreads)

	// monitor status of workers
	wg.Add(1)
	go monitorPrintStats(&crackedCount, &linesProcessed, stopChan, startTime, validVaultCount, &wg, *statsIntervalFlag)

	// start the processing logic
	startProc(*wordlistFileFlag, *outputFile, numThreads, vaults, &crackedCount, &linesProcessed, stopChan)

	// close stop channel to signal all workers to stop
	closeStopChannel(stopChan)

	// wait for monitorPrintStats to finish
	wg.Wait()
}

// end code
