package main

import (
	"fmt"
	"log"
	"os"
	"strings"
)

func printWelcome(vaultPath, wordPath string, total, threads int, gpuLabel, backend, chunkLabel, testLabel string) {
	fmt.Fprintln(os.Stderr, " --------------------------------------------------- ")
	fmt.Fprintln(os.Stderr, "|       Cyclone's TrustWallet Vault Decryptor       |")
	fmt.Fprintln(os.Stderr, "| https://github.com/cyclone-github/trustwallet_pwn |")
	fmt.Fprintln(os.Stderr, " --------------------------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Vault file:\t%s\nValid Vaults:\t%d\nCPU Threads:\t%d\nGPU:\t\t%s\n", vaultPath, total, threads, gpuLabel)
	if wordPath == "" {
		fmt.Fprintln(os.Stderr, "Wordlist:\tReading stdin")
	} else {
		fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", wordPath)
	}
	if chunkLabel != "" {
		fmt.Fprintf(os.Stderr, "Chunk:\t\t%s\n", chunkLabel)
	}
	fmt.Fprintf(os.Stderr, "Backend:\t%s\n", backend)
	fmt.Fprintf(os.Stderr, "Self-test:\t%s\n", testLabel)
	log.Println("Working...")
}

// print each gpu name once

func gpuSummary(devices []gpuDevice) string {
	if len(devices) == 0 {
		return "0 (none active)"
	}
	counts := make(map[string]int)
	var order []string
	for _, d := range devices {
		if counts[d.name] == 0 {
			order = append(order, d.name)
		}
		counts[d.name]++
	}
	var entries []string
	for _, name := range order {
		if counts[name] > 1 {
			entries = append(entries, fmt.Sprintf("%d x %s", counts[name], name))
		} else {
			entries = append(entries, name)
		}
	}
	return fmt.Sprintf("%d (%s)", len(devices), strings.Join(entries, ", "))
}

func helpText() {
	fmt.Fprintln(os.Stderr, "Cyclone's TrustWallet Vault Decryptor "+version)
	fmt.Fprintln(os.Stderr, "https://github.com/cyclone-github/trustwallet_pwn")
	fmt.Fprintln(os.Stderr, `
-w {wordlist}        (omit to read stdin)
-h {trustwallet_hash}  (wallet input; JSONL or single JSON)
-o {output}          (omit to write to stdout)
-t {threads}         CPU threads
-s {seconds}         print status every N seconds, default 60

-cpu                 force CPU-only backend
-gpu                 force OpenCL GPU-only backend
-hybrid              force GPU + CPU concurrent workers
(no backend flag)    prefer hybrid, then GPU-only, then CPU-only
-gpu-list            list detected GPUs
-gpu-devices 0,1     GPU device selection (default all)
-gpu-mem 92          max percentage of VRAM (default 92)
-gpu-batch 0         automatic per-GPU batch (0=auto)
-gpu-step 0          automatic per-GPU kernel step (0=auto)
-gpu-verbose         print GPU device and autotuning details
-t {threads}         CPU workers (default all logical CPUs, also in hybrid)
-chunk k/n           process 1-based contiguous wordlist partition k/n; requires -w
ETA                 shown for regular wordlists, unavailable for stdin

-version -help

Example:
cat wordlist | ./trustwallet_decryptor.bin -h trustwallet.txt
./trustwallet_decryptor.bin -cpu -h trustwallet.txt -w wordlist.txt -t 16 -s 10`)
}
