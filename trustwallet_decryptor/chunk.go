package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// one-based contiguous wordlist partitions
func resolveChunkRange(chunkSpec string, total uint64) (start, end uint64, err error) {
	if total == 0 {
		return 0, 0, fmt.Errorf("total candidates is zero")
	}
	parts := strings.Split(chunkSpec, "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid chunk format %q, expected k/n", chunkSpec)
	}
	k64, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || k64 == 0 {
		return 0, 0, fmt.Errorf("invalid chunk index %q", parts[0])
	}
	n64, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || n64 == 0 {
		return 0, 0, fmt.Errorf("invalid chunk count %q", parts[1])
	}
	if k64 > n64 {
		return 0, 0, fmt.Errorf("chunk index %d out of range (1..%d)", k64, n64)
	}
	chunkIndex := k64 - 1
	baseSize := total / n64
	remainder := total % n64
	var chunkSize uint64
	if chunkIndex < remainder {
		chunkSize = baseSize + 1
		start = chunkIndex * chunkSize
	} else {
		chunkSize = baseSize
		start = remainder*(baseSize+1) + (chunkIndex-remainder)*baseSize
	}
	end = start + chunkSize
	if end > total {
		end = total
	}
	return start, end, nil
}

// count final wordlist lines without trailing newline
func countWordlistLines(file *os.File) (uint64, error) {
	buf := make([]byte, 256*1024)
	var total uint64
	var last byte
	seen := false
	for {
		n, err := file.Read(buf)
		if n > 0 {
			seen = true
			total += uint64(bytes.Count(buf[:n], []byte{'\n'}))
			last = buf[n-1]
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return total, err
		}
	}
	if seen && last != '\n' {
		total++
	}
	return total, nil
}

type candidateSource interface {
	Scan() bool
	Bytes() []byte
	Err() error
}

type chunkScanner struct {
	scan              candidateSource
	start, end, index uint64
}

func newChunkScanner(scan candidateSource, start, end uint64) *chunkScanner {
	return &chunkScanner{scan: scan, start: start, end: end}
}

func (c *chunkScanner) Scan() bool {
	for c.index < c.end && c.scan.Scan() {
		index := c.index
		c.index++
		if index >= c.start {
			return true
		}
	}
	return false
}
func (c *chunkScanner) Bytes() []byte { return c.scan.Bytes() }
func (c *chunkScanner) Err() error    { return c.scan.Err() }

var _ candidateSource = (*bufio.Scanner)(nil)
var _ candidateSource = (*chunkScanner)(nil)
var _ io.Reader = (*os.File)(nil)

func mustChunkParts(spec string) uint64 {
	parts := strings.Split(spec, "/")
	if len(parts) != 2 {
		return 0
	}
	n, _ := strconv.ParseUint(parts[1], 10, 64)
	return n
}
