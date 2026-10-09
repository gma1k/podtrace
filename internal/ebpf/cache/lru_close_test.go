package cache

import (
	"testing"
	"time"
)

func TestClosingTheCacheTwiceIsSafe(t *testing.T) {
	c := NewLRUCache(8, time.Minute)
	c.Close()
	c.Close()
}
