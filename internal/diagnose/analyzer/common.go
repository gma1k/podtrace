package analyzer

import (
	"fmt"

	"github.com/podtrace/podtrace/internal/config"
)

// Percentile returns the p-th percentile (0-100) of an ascending-sorted slice
// using linear interpolation between closest ranks (method R-7, as used by
// NumPy/Excel). Plain integer indexing floored the rank and systematically
// under-reported P95/P99.
func Percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n == 1 || p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[n-1]
	}
	rank := (p / 100) * float64(n-1)
	lo := int(rank)
	if lo+1 >= n {
		return sorted[n-1]
	}
	frac := rank - float64(lo)
	return sorted[lo] + frac*(sorted[lo+1]-sorted[lo])
}

func FormatBytes(bytes uint64) string {
	if bytes < config.KB {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < config.MB {
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(config.KB))
	} else if bytes < config.GB {
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(config.MB))
	} else {
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(config.GB))
	}
}

type TargetCount struct {
	Target string
	Count  int
}
