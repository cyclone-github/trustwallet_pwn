package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func checkIndexedChunks(t *testing.T, f *os.File, idx wordlistIndex, expected []string, chunkCounts []uint64) {
	t.Helper()
	for _, partitions := range chunkCounts {
		indexes := []uint64{1, 2, partitions / 2, partitions - 1, partitions}
		for _, k := range indexes {
			if k == 0 || k > partitions {
				continue
			}
			begin, end, err := resolveChunkRange(fmt.Sprintf("%d/%d", k, partitions), idx.TotalLines)
			if err != nil {
				t.Fatal(err)
			}
			if err := seekWordlistLine(f, idx, begin); err != nil {
				t.Fatalf("seek %d/%d: %v", k, partitions, err)
			}
			scan := bufio.NewScanner(f)
			scan.Buffer(make([]byte, 4096), 16*1024*1024)
			chunk := newChunkScanner(scan, 0, end-begin)
			var got []string
			for chunk.Scan() {
				got = append(got, string(chunk.Bytes()))
			}
			if err := chunk.Err(); err != nil {
				t.Fatal(err)
			}
			want := expected[int(begin):int(end)]
			if len(got) != len(want) {
				t.Fatalf("chunk %d/%d got %d lines want %d", k, partitions, len(got), len(want))
			}
			for j := range want {
				if got[j] != want[j] {
					t.Fatalf("chunk %d/%d line %d: got %q, want %q", k, partitions, j, got[j], want[j])
				}
			}
		}
	}
}

func TestWordlistIndexAndCache(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	cases := []struct {
		name, content string
		want          []string
	}{
		{"one_no_newline", "password", []string{"password"}},
		{"lf", "abc\ndef\nthird\n", []string{"abc", "def", "third"}},
		{"no_final_lf", "abc\ndef\nthird", []string{"abc", "def", "third"}},
		{"crlf", "abc\r\ndef\r\nthird\r\n", []string{"abc", "def", "third"}},
		{"empty_lines", "\nabc\n\n", []string{"", "abc", ""}},
		{"empty", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "words")
			if err := os.WriteFile(name, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			info, _ := f.Stat()
			idx, hit, err := loadOrBuildWordlistIndex(f, info, false)
			if err != nil || hit {
				t.Fatalf("first hit=%v err=%v", hit, err)
			}
			if idx.TotalLines != uint64(len(tc.want)) {
				t.Fatalf("lines %d want %d", idx.TotalLines, len(tc.want))
			}
			idx2, hit, err := loadOrBuildWordlistIndex(f, info, false)
			if err != nil || !hit {
				t.Fatalf("cached hit=%v err=%v", hit, err)
			}
			if idx2.TotalLines != idx.TotalLines {
				t.Fatal("cached count changed")
			}
			if len(tc.want) > 0 {
				checkIndexedChunks(t, f, idx2, tc.want, []uint64{1, 2, 3})
			}
			idx3, hit, err := loadOrBuildWordlistIndex(f, info, true)
			if err != nil || hit || idx3.TotalLines != idx.TotalLines {
				t.Fatalf("forced rebuild hit=%v err=%v", hit, err)
			}
		})
	}
}

func TestLargeWordlistSparseCheckpoints(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	total := int(wordlistIndexStride*2 + 113)
	var data bytes.Buffer
	expected := make([]string, total)
	for i := 0; i < total; i++ {
		expected[i] = strconv.Itoa(i)
		data.WriteString(expected[i])
		if i != total-1 {
			data.WriteByte('\n')
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "large-wordlist-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(data.Bytes()); err != nil {
		t.Fatal(err)
	}
	info, _ := f.Stat()
	idx, _, err := loadOrBuildWordlistIndex(f, info, false)
	if err != nil {
		t.Fatal(err)
	}
	if idx.TotalLines != uint64(total) || len(idx.Offsets) != 3 {
		t.Fatalf("idx %d lines %d offsets", idx.TotalLines, len(idx.Offsets))
	}
	for n, off := range idx.Offsets {
		pos := uint64(n) * wordlistIndexStride
		if pos == 0 {
			if off != 0 {
				t.Fatalf("offset0=%d", off)
			}
			continue
		}
		if err := seekWordlistLine(f, idx, pos); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(f)
		line, e := reader.ReadString('\n')
		if e != nil && e != io.EOF {
			t.Fatal(e)
		}
		if strings.TrimSuffix(line, "\n") != expected[pos] {
			t.Fatalf("checkpoint %d got %q", n, line)
		}
	}
	checkIndexedChunks(t, f, idx, expected, []uint64{2, 7, 1000})
	path, _ := wordlistCacheFile(f.Name())
	if err := os.WriteFile(path, []byte("invalid JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	_, hit, err := loadOrBuildWordlistIndex(f, info, false)
	if err != nil || hit {
		t.Fatalf("corrupted cache reused: %v %v", hit, err)
	}
}

func TestWordlistCacheInvalidation(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	name := filepath.Join(t.TempDir(), "changed")
	os.WriteFile(name, []byte("alpha\nbeta\n"), 0600)
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, _ := f.Stat()
	_, _, err = loadOrBuildWordlistIndex(f, info, false)
	if err != nil {
		t.Fatal(err)
	}
	// Same length and same mtime, but fingerprint must invalidate cache.
	err = os.WriteFile(name, []byte("alpha beta\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(name, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	info2, _ := f.Stat()
	idx, hit, err := loadOrBuildWordlistIndex(f, info2, false)
	if err != nil || hit || idx.TotalLines != 1 {
		t.Fatalf("cache after same-size change: hit=%v lines=%d err=%v", hit, idx.TotalLines, err)
	}
	_ = os.Chtimes(name, time.Now(), time.Now())
	info3, _ := f.Stat()
	_, hit, err = loadOrBuildWordlistIndex(f, info3, false)
	if err != nil || hit {
		t.Fatalf("mtime change cache hit=%v err=%v", hit, err)
	}
}

func BenchmarkLineCounter(b *testing.B) {
	name := filepath.Join(b.TempDir(), "bench.txt")
	f, err := os.Create(name)
	if err != nil {
		b.Fatal(err)
	}
	// Approximately 16 MiB of data.
	data := bytes.Repeat([]byte("test-password-1\n"), 1<<20)
	f.Write(data)
	f.Close()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		file, err := os.Open(name)
		if err != nil {
			b.Fatal(err)
		}
		count, err := countWordlistLines(file)
		file.Close()
		if err != nil || count != 1<<20 {
			b.Fatalf("count=%d err=%v", count, err)
		}
	}
}

func BenchmarkIndexedFirstPass(b *testing.B) {
	name := filepath.Join(b.TempDir(), "bench.txt")
	f, err := os.Create(name)
	if err != nil {
		b.Fatal(err)
	}
	data := bytes.Repeat([]byte("test-password-1\n"), 1<<20)
	if _, err := f.Write(data); err != nil {
		b.Fatal(err)
	}
	info, _ := f.Stat()
	sig, err := wordlistSignature(f, info.Size())
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx, err := buildWordlistIndex(f, info, sig)
		if err != nil || idx.TotalLines != 1<<20 {
			b.Fatalf("count=%d err=%v", idx.TotalLines, err)
		}
	}
}

func BenchmarkIndexedCacheHit(b *testing.B) {
	b.Setenv("XDG_CACHE_HOME", b.TempDir())
	name := filepath.Join(b.TempDir(), "bench.txt")
	f, err := os.Create(name)
	if err != nil {
		b.Fatal(err)
	}
	data := bytes.Repeat([]byte("test-password-1\n"), 1<<20)
	if _, err := f.Write(data); err != nil {
		b.Fatal(err)
	}
	info, _ := f.Stat()
	if _, _, err := loadOrBuildWordlistIndex(f, info, false); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx, hit, err := loadOrBuildWordlistIndex(f, info, false)
		if err != nil || !hit || idx.TotalLines != 1<<20 {
			b.Fatalf("hit=%v count=%d err=%v", hit, idx.TotalLines, err)
		}
	}
}
