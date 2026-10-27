package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestChunkRange(t *testing.T) {
	for _, tc := range []struct {
		total uint64
		n     uint64
	}{
		{total: 1, n: 1}, {total: 3, n: 2}, {total: 10, n: 3}, {total: 10, n: 4},
		{total: 11, n: 5}, {total: 1023, n: 16}, {total: 3, n: 5}, {total: 1000001, n: 17},
	} {
		used := make([]uint8, tc.total)
		var priorEnd uint64
		for k := uint64(1); k <= tc.n; k++ {
			start, end, err := resolveChunkRange(fmt.Sprintf("%d/%d", k, tc.n), tc.total)
			if err != nil {
				t.Fatal(err)
			}
			if start != priorEnd {
				t.Fatalf("%d lines %d chunks: discontinuity at %d start=%d previous=%d", tc.total, tc.n, k, start, priorEnd)
			}
			if end < start || end > tc.total {
				t.Fatalf("bad range %d-%d", start, end)
			}
			for i := start; i < end; i++ {
				used[i]++
			}
			priorEnd = end
		}
		if priorEnd != tc.total {
			t.Fatalf("last end=%d total=%d", priorEnd, tc.total)
		}
		for i, v := range used {
			if v != 1 {
				t.Fatalf("total %d chunks %d: line %d counted %d times", tc.total, tc.n, i, v)
			}
		}
	}
}

func TestInvalidChunkRanges(t *testing.T) {
	for _, str := range []string{"1", "0/3", "1/0", "4/3", "foo/3", "1/foo", "1/3/4", "-1/2", "1/2 ", "/4"} {
		if _, _, err := resolveChunkRange(str, 10); err == nil {
			t.Errorf("expected invalid chunk %q", str)
		}
	}
	if _, _, err := resolveChunkRange("1/2", 0); err == nil {
		t.Fatal("expected no-candidates error")
	}
}

func TestChunkScannerExactLines(t *testing.T) {
	for _, trailingNewline := range []bool{true, false} {
		t.Run(fmt.Sprint("trailing_newline=", trailingNewline), func(t *testing.T) {
			const lines = 11
			var expected []string
			for i := 0; i < lines; i++ {
				expected = append(expected, fmt.Sprintf("candidate_%d", i))
			}
			input := strings.Join(expected, "\n")
			if trailingNewline {
				input += "\n"
			}
			fileName := filepath.Join(t.TempDir(), "input.txt")
			if err := os.WriteFile(fileName, []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(fileName)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			count, err := countWordlistLines(f)
			if err != nil || count != lines {
				t.Fatalf("count=%d err=%v", count, err)
			}
			seen := make(map[string]int)
			for k := 1; k <= 4; k++ {
				start, end, err := resolveChunkRange(fmt.Sprintf("%d/4", k), count)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.Seek(0, 0); err != nil {
					t.Fatal(err)
				}
				scan := bufio.NewScanner(f)
				scan.Buffer(make([]byte, 4096), 16*1024*1024)
				chunk := newChunkScanner(scan, start, end)
				var got []string
				for chunk.Scan() {
					got = append(got, string(chunk.Bytes()))
					seen[string(chunk.Bytes())]++
				}
				if err := chunk.Err(); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, expected[start:end]) {
					t.Fatalf("chunk %d got %q expected %q", k, got, expected[start:end])
				}
			}
			if len(seen) != lines {
				t.Fatalf("seen only %d lines", len(seen))
			}
			for _, l := range expected {
				if seen[l] != 1 {
					t.Fatalf("line %q occurrences %d", l, seen[l])
				}
			}
		})
	}
}

func TestGPUSummary(t *testing.T) {
	cases := []struct {
		ds   []gpuDevice
		want string
	}{
		{nil, "0 (none active)"},
		{[]gpuDevice{{name: "NVIDIA RTX 4090"}}, "1 (NVIDIA RTX 4090)"},
		{[]gpuDevice{{name: "RTX 4090"}, {name: "RTX 4090"}}, "2 (2 x RTX 4090)"},
		{[]gpuDevice{{name: "RTX 4090"}, {name: "RTX 3090"}, {name: "RTX 4090"}}, "3 (2 x RTX 4090, RTX 3090)"},
	}
	for _, tc := range cases {
		if got := gpuSummary(tc.ds); got != tc.want {
			t.Errorf("got %q want %q", got, tc.want)
		}
	}
}
