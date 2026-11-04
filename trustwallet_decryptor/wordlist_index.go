package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// A sparse line index costs around eight bytes per 262144 input lines.
// Positions are byte offsets immediately after the indexed newline.
const (
	wordlistIndexVersion          = 1
	wordlistIndexStride    uint64 = 1 << 18
	wordlistReadBuffer            = 4 << 20
	wordlistSignatureBytes int64  = 64 << 10
)

var newlineByte = []byte{'\n'}

type wordlistIndex struct {
	Version     int     `json:"version"`
	Size        int64   `json:"size"`
	ModTimeNS   int64   `json:"mtime_ns"`
	Signature   string  `json:"signature"`
	Stride      uint64  `json:"stride"`
	Newlines    uint64  `json:"newlines"`
	TotalLines  uint64  `json:"total_lines"`
	EndsNewline bool    `json:"ends_newline"`
	Offsets     []int64 `json:"offsets"`
}

// nthNewlineEnd returns the exclusive byte offset of the nth newline.
// Count 64 KiB at a time using the optimized bytes.Count routine; locate
// individual newline bytes only inside the last (small) block.
func nthNewlineEnd(data []byte, nth uint64) (int, error) {
	if nth == 0 {
		return 0, errors.New("zero newline rank")
	}
	for start := 0; start < len(data); {
		end := start + (64 << 10)
		if end > len(data) {
			end = len(data)
		}
		count := uint64(bytes.Count(data[start:end], newlineByte))
		if nth > count {
			nth -= count
			start = end
			continue
		}
		for nth > 0 {
			at := bytes.IndexByte(data[start:end], '\n')
			if at < 0 {
				return 0, errors.New("missing newline")
			}
			start += at + 1
			nth--
		}
		return start, nil
	}
	return 0, errors.New("missing newline")
}

func buildWordlistIndex(f *os.File, info os.FileInfo, signature string) (wordlistIndex, error) {
	idx := wordlistIndex{Version: wordlistIndexVersion, Size: info.Size(), ModTimeNS: info.ModTime().UnixNano(), Signature: signature, Stride: wordlistIndexStride, Offsets: []int64{0}}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return idx, err
	}
	buf := make([]byte, wordlistReadBuffer)
	var position int64
	nextCheckpoint := idx.Stride
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			block := buf[:n]
			// Count each byte only once in 64 KiB slices. Sparse
			// checkpoint lookups only rescan the slice containing a
			// boundary, rather than repeatedly searching the 4 MiB block.
			for at := 0; at < n; at += 64 << 10 {
				end := at + (64 << 10)
				if end > n {
					end = n
				}
				slice := block[at:end]
				found := uint64(bytes.Count(slice, newlineByte))
				for nextCheckpoint <= idx.Newlines+found {
					rank := nextCheckpoint - idx.Newlines
					pos, err := nthNewlineEnd(slice, rank)
					if err != nil {
						return idx, err
					}
					idx.Offsets = append(idx.Offsets, position+int64(at+pos))
					nextCheckpoint += idx.Stride
				}
				idx.Newlines += found
			}
			idx.EndsNewline = block[len(block)-1] == '\n'
			position += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return idx, readErr
		}
		if n == 0 {
			return idx, io.ErrNoProgress
		}
	}
	if position != info.Size() {
		return idx, errors.New("wordlist changed size while indexing")
	}
	idx.TotalLines = idx.Newlines
	if position > 0 && !idx.EndsNewline {
		idx.TotalLines++
	}
	if current, err := f.Stat(); err != nil {
		return idx, err
	} else if current.Size() != idx.Size || current.ModTime().UnixNano() != idx.ModTimeNS {
		return idx, errors.New("wordlist modified while indexing")
	}
	return idx, nil
}

// A bounded fingerprint guards against stale caches when size and mtime
// match. For adversarial changes to a file that preserve all sampled regions
// and timestamps, force a rebuild with -wordlist-reindex.
func wordlistSignature(f *os.File, size int64) (string, error) {
	h := sha256.New()
	if size == 0 {
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	offsets := []int64{0, size/2 - wordlistSignatureBytes/2, size - wordlistSignatureBytes}
	buf := make([]byte, wordlistSignatureBytes)
	for _, at := range offsets {
		if at < 0 {
			at = 0
		}
		length := size - at
		if length > wordlistSignatureBytes {
			length = wordlistSignatureBytes
		}
		if _, err := f.ReadAt(buf[:int(length)], at); err != nil {
			return "", err
		}
		h.Write(buf[:int(length)])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func wordlistCacheFile(name string) (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		abs = resolved
	}
	key := sha256.Sum256([]byte(abs))
	return filepath.Join(dir, "trustwallet_pwn", "wordlists", hex.EncodeToString(key[:])+".json"), nil
}

func validWordlistIndex(idx wordlistIndex, info os.FileInfo, signature string) bool {
	if idx.Version != wordlistIndexVersion || idx.Stride != wordlistIndexStride || idx.Size != info.Size() || idx.ModTimeNS != info.ModTime().UnixNano() || idx.Signature != signature || len(idx.Offsets) == 0 || idx.Offsets[0] != 0 {
		return false
	}
	want := idx.Newlines/idx.Stride + 1
	if uint64(len(idx.Offsets)) != want {
		return false
	}
	if idx.TotalLines != idx.Newlines && idx.TotalLines != idx.Newlines+1 {
		return false
	}
	if (idx.TotalLines == idx.Newlines) != (idx.Size == 0 || idx.EndsNewline) {
		return false
	}
	for j := 1; j < len(idx.Offsets); j++ {
		if idx.Offsets[j] <= idx.Offsets[j-1] || idx.Offsets[j] > idx.Size {
			return false
		}
	}
	return true
}

func saveWordlistIndex(path string, idx wordlistIndex) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".wordlist-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0600); err == nil {
		err = json.NewEncoder(temp).Encode(idx)
	}
	if err == nil {
		err = temp.Close()
	} else {
		_ = temp.Close()
	}
	if err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

// loadOrBuildWordlistIndex returns the exact line count plus sparse seek
// positions. Cache failures are nonfatal: the correct count is rebuilt.
func loadOrBuildWordlistIndex(f *os.File, info os.FileInfo, force bool) (wordlistIndex, bool, error) {
	var empty wordlistIndex
	signature, err := wordlistSignature(f, info.Size())
	if err != nil {
		return empty, false, err
	}
	path, pathErr := wordlistCacheFile(f.Name())
	if !force && pathErr == nil {
		if blob, err := os.ReadFile(path); err == nil {
			var cached wordlistIndex
			if json.Unmarshal(blob, &cached) == nil && validWordlistIndex(cached, info, signature) {
				return cached, true, nil
			}
		}
	}
	idx, err := buildWordlistIndex(f, info, signature)
	if err != nil {
		return empty, false, err
	}
	if pathErr == nil {
		// The on-disk index is an optional acceleration, not a prerequisite.
		_ = saveWordlistIndex(path, idx)
	}
	return idx, false, nil
}

// seekWordlistLine jumps to the nearest sparse checkpoint, then uses raw byte
// scanning to find the exact start of a requested 0-based line. It never
// tokenizes or allocates strings for skipped candidates.
func seekWordlistLine(f *os.File, idx wordlistIndex, line uint64) error {
	if line > idx.TotalLines {
		return fmt.Errorf("wordlist line %d beyond %d", line, idx.TotalLines)
	}
	if line == idx.TotalLines {
		_, err := f.Seek(idx.Size, io.SeekStart)
		return err
	}
	checkpoint := line / idx.Stride
	if checkpoint >= uint64(len(idx.Offsets)) {
		return errors.New("wordlist index checkpoint missing")
	}
	offset := idx.Offsets[int(checkpoint)]
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	remain := line - checkpoint*idx.Stride
	if remain == 0 {
		return nil
	}
	buf := make([]byte, 1<<20)
	for remain > 0 {
		n, err := f.Read(buf)
		if n > 0 {
			count := uint64(bytes.Count(buf[:n], newlineByte))
			if count >= remain {
				pos, findErr := nthNewlineEnd(buf[:n], remain)
				if findErr != nil {
					return findErr
				}
				_, seekErr := f.Seek(offset+int64(pos), io.SeekStart)
				return seekErr
			}
			remain -= count
			offset += int64(n)
		}
		if err != nil {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
