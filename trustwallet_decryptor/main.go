package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
v0.3.1; 2026-10-27
	enable gpu support (-gpu)
	add chunking support (-chunk nth/nth)
	add ETA for -w
    add JSON-compatible recovery
*/

const version = "v0.3.1"

func main() {
	wordPath := flag.String("w", "", "Wordlist file (default stdin)")
	vaultPath := flag.String("h", "", "Vault file")
	outPath := flag.String("o", "", "Output file")
	threads := flag.Int("t", runtime.NumCPU(), "CPU threads")
	statsSec := flag.Int("s", 60, "Status interval seconds")
	chunkSpec := flag.String("chunk", "", "Process 1-based wordlist chunk k/n; requires -w")
	gpuFlag := flag.Bool("gpu", false, "Force GPU-only backend")
	cpuFlag := flag.Bool("cpu", false, "Force CPU-only backend")
	hybridFlag := flag.Bool("hybrid", false, "Force concurrent GPU and CPU workers")
	gpuIDs := flag.String("gpu-devices", "all", "OpenCL GPU IDs")
	gpuList := flag.Bool("gpu-list", false, "List OpenCL GPUs")
	gpuMem := flag.Int("gpu-mem", 92, "Target GPU VRAM percentage")
	gpuBatch := flag.Int("gpu-batch", 0, "GPU batch 0=auto")
	gpuStep := flag.Int("gpu-step", 0, "GPU kernel step 0=auto")
	gpuDiag := flag.Bool("gpu-verbose", false, "Print GPU tuning information")
	helpFlag := flag.Bool("help", false, "Help")
	versionFlag := flag.Bool("version", false, "Version")
	cycloneFlag := flag.Bool("cyclone", false, "")
	flag.Parse()
	gpuVerbose = *gpuDiag
	if *versionFlag {
		fmt.Fprintf(os.Stderr, "Cyclone's TrustWallet Vault Decryptor %s\n", version)
		return
	}
	if *cycloneFlag {
		b, _ := base64.StdEncoding.DecodeString("Q29kZWQgYnkgY3ljbG9uZSA7KQo=")
		fmt.Print(string(b))
		return
	}
	if *helpFlag {
		helpText()
		return
	}
	if boolInt(*cpuFlag)+boolInt(*gpuFlag)+boolInt(*hybridFlag) > 1 {
		log.Fatal("-cpu, -gpu and -hybrid are mutually exclusive")
	}
	if *gpuMem < 50 || *gpuMem > 96 || *gpuBatch < 0 || *gpuStep < 0 || *statsSec < 0 {
		log.Fatal("invalid tuning or status flag")
	}
	if *threads < 1 || *threads > runtime.NumCPU() {
		*threads = runtime.NumCPU()
	}
	// use all logical cpu threads by default
	if *gpuList {
		ds, err := gpuDevices()
		if err != nil {
			log.Fatal(err)
		}
		for _, d := range ds {
			free := "unknown"
			if d.free > 0 {
				free = fmt.Sprintf("%.0f MiB", float64(d.free)/float64(MiB))
			}
			fmt.Printf("GPU %d: %s | total=%.0f MiB free=%s max-alloc=%.0f MiB compute-units=%d\n", d.id, d.name, float64(d.mem)/float64(MiB), free, float64(d.maxAlloc)/float64(MiB), d.computeUnits)
		}
		return
	}
	if *chunkSpec != "" && *wordPath == "" {
		log.Fatal("-chunk requires a seekable -w wordlist file, not stdin")
	}
	if *vaultPath == "" {
		log.Fatal("-h (vault file) flag is required; try -help")
	}
	vaults, err := loadVaults(*vaultPath)
	if err != nil {
		log.Fatal("Error reading vault file: ", err)
	}
	var input io.Reader = os.Stdin
	if *wordPath != "" {
		f, err := os.Open(*wordPath)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		input = f
	}
	var chunkStart, chunkEnd, totalLines, attackLines uint64
	if *wordPath != "" {
		file := input.(*os.File)
		info, err := file.Stat()
		if err != nil {
			log.Fatal(err)
		}
		if *chunkSpec != "" && !info.Mode().IsRegular() {
			log.Fatal("-chunk requires a regular wordlist file")
		}
		if info.Mode().IsRegular() {
			totalLines, err = countWordlistLines(file)
			if err != nil {
				log.Fatalf("wordlist count: %v", err)
			}
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				log.Fatalf("wordlist seek: %v", err)
			}
			attackLines = totalLines
		}
	}
	if *chunkSpec != "" {
		chunkStart, chunkEnd, err = resolveChunkRange(*chunkSpec, totalLines)
		if err != nil {
			log.Fatalf("-chunk: %v", err)
		}
		if chunkStart == chunkEnd {
			log.Fatalf("-chunk %s: empty range", *chunkSpec)
		}
		attackLines = chunkEnd - chunkStart
	}

	output := os.Stdout
	if *outPath != "" {
		f, err := os.OpenFile(*outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		output = f
	}
	writer := bufio.NewWriterSize(output, 64*1024)
	defer writer.Flush()

	// auto backend order is hybrid then gpu then cpu
	var devices []gpuDevice
	if !*cpuFlag {
		if err := gpuEligible(vaults); err != nil {
			if *gpuFlag || *hybridFlag {
				log.Fatal("GPU forced but: ", err)
			}
		} else if all, err := gpuDevices(); err == nil && len(all) > 0 {
			devices, err = selectedDevices(all, *gpuIDs)
			if err != nil {
				log.Fatal(err)
			}
		} else if *gpuFlag || *hybridFlag {
			log.Fatalf("GPU requested but none available: %v", err)
		}
	}
	cpuOK, healthy, testLabel := selfTestResults(!*gpuFlag, !*cpuFlag, devices)
	gpuOK := len(healthy) > 0
	if strings.Contains(testLabel, "FAIL") {
		fmt.Fprintf(os.Stderr, "Self-test:\t%s\n", testLabel)
	}
	if *gpuFlag && len(healthy) != len(devices) {
		log.Fatal("GPU self-test failed")
	}
	if *hybridFlag && (!cpuOK || len(healthy) != len(devices) || !gpuOK) {
		log.Fatal("hybrid self-test failed")
	}
	// skip devices with failed self-tests
	runGPUIDs := make([]string, 0, len(healthy))
	for _, d := range healthy {
		runGPUIDs = append(runGPUIDs, strconv.Itoa(d.id))
	}
	runGPUDevices := strings.Join(runGPUIDs, ",")
	mode, modeErr := chooseBackend(*cpuFlag, *gpuFlag, *hybridFlag, gpuOK, cpuOK)
	if modeErr != nil {
		log.Fatal(modeErr)
	}
	useGPU := mode == modeGPU || mode == modeHybrid
	hybridThreads := 0
	if mode == modeHybrid {
		hybridThreads = *threads
	}
	backend := string(mode)
	if mode == modeHybrid {
		backend = fmt.Sprintf("Hybrid/GPU+CPU (%d CPU workers)", hybridThreads)
	}
	activeCPUThreads := *threads
	if mode == modeHybrid {
		activeCPUThreads = hybridThreads
	}
	if mode == modeGPU {
		activeCPUThreads = 0
	}
	// show unique gpu names
	gpuLabel := "0 (none active)"
	if useGPU {
		gpuLabel = gpuSummary(healthy)
	}
	var chunkLabel string
	if *chunkSpec != "" {
		chunkLabel = fmt.Sprintf("%s (lines %d-%d of %d, 1-based)", *chunkSpec, chunkStart+1, chunkEnd, totalLines)
	}
	printWelcome(*vaultPath, *wordPath, len(vaults), activeCPUThreads, gpuLabel, backend, chunkLabel, testLabel)

	var outputMu sync.Mutex
	var processed, matched atomic.Uint64
	found := make([]atomic.Bool, len(vaults))
	alreadyCracked := func(vi int) bool { return found[vi].Load() }
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	emit := func(vi int, v vault, pw, dk []byte) {
		if !found[vi].CompareAndSwap(false, true) {
			return
		}
		outputMu.Lock()
		fmt.Fprintf(writer, "Password: %s\n", pw)
		plain, err := decrypt(v, dk)
		if err != nil {
			fmt.Fprintf(writer, "Decryption error: %v\n", err)
		} else {
			fmt.Fprintf(writer, "Decrypted: %s\n", plain)
		}
		writer.Flush()
		outputMu.Unlock()
		if matched.Add(1) == uint64(len(vaults)) {
			stop()
		}
	}
	start := time.Now()
	done := make(chan struct{})
	var statusWG sync.WaitGroup
	if *statsSec > 0 {
		statusWG.Add(1)
		go func() {
			defer statusWG.Done()
			tick := time.NewTicker(time.Duration(*statsSec) * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-tick.C:
					log.Print(formatStatus(time.Since(start), int(matched.Load()), len(vaults), processed.Load(), attackLines))
				case <-done:
					return
				}
			}
		}()
	}
	scan := bufio.NewScanner(input)
	scan.Buffer(make([]byte, 4096), 16*1024*1024)
	var candidates candidateSource = scan
	if *chunkSpec != "" {
		candidates = newChunkScanner(scan, chunkStart, chunkEnd)
	}
	var runErr error
	if useGPU {
		runErr = runGPUs(ctx, stop, candidates, vaults, runGPUDevices, *gpuMem, *gpuBatch, *gpuStep, hybridThreads, cpuOK && !*gpuFlag && !*hybridFlag, &processed, emit, alreadyCracked)
		if runErr != nil && errors.Is(runErr, errGPUInitialization) && !*gpuFlag && !*hybridFlag {
			log.Printf("GPU initialization failed (%v); falling back to CPU", runErr)
			log.Println("Backend:\tCPU (fallback)")
			useGPU = false
			runErr = runCPU(ctx, candidates, vaults, *threads, &processed, emit, alreadyCracked)
		}
	} else {
		runErr = runCPU(ctx, candidates, vaults, *threads, &processed, emit, alreadyCracked)
	}
	close(done)
	statusWG.Wait()
	log.Println("Finished")
	log.Print(formatStatus(time.Since(start), int(matched.Load()), len(vaults), processed.Load(), attackLines))
	if runErr != nil {
		log.Printf("Error: %v", runErr)
		os.Exit(1)
	}
}

type emitFn func(int, vault, []byte, []byte)
