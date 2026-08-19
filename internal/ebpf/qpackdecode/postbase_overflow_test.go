package qpackdecode

import (
	"math"
	"testing"
)

func TestPostBaseOverflows(t *testing.T) {
	cases := []struct {
		base, index uint64
		want        bool
	}{
		{1, 2, false},
		{0, math.MaxUint64, false},
		{math.MaxUint64, 0, false},
		{math.MaxUint64, 1, true},
		{1 << 63, 1 << 63, true},
		{1 << 63, (1 << 63) - 1, false},
	}
	for _, c := range cases {
		if got := postBaseOverflows(c.base, c.index); got != c.want {
			t.Errorf("postBaseOverflows(%d,%d)=%v want %v", c.base, c.index, got, c.want)
		}
	}
}
