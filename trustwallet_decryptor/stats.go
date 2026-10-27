package main

import (
	"fmt"
	"math"
	"time"
)

func formatStatus(elapsed time.Duration, matches, total int, processed, wordlistSize uint64) string {
	if elapsed < time.Microsecond {
		elapsed = time.Microsecond
	}
	seconds := int64(elapsed / time.Second)
	rate := float64(processed) / elapsed.Seconds()
	status := fmt.Sprintf("Decrypted: %d/%d %.2f h/s %02dh:%02dm:%02ds", matches, total, rate, seconds/3600, (seconds/60)%60, seconds%60)
	if wordlistSize == 0 {
		return status + " ETA: --"
	}
	if processed >= wordlistSize || matches == total {
		return status + " ETA: 00h:00m:00s"
	}
	if rate <= 0 {
		return status + " ETA: --"
	}
	remaining := math.Ceil(float64(wordlistSize-processed) / rate)
	if remaining > float64(math.MaxInt64) {
		return status + " ETA: --"
	}
	eta := int64(remaining)
	return fmt.Sprintf("%s ETA: %02dh:%02dm:%02ds", status, eta/3600, (eta/60)%60, eta%60)
}
