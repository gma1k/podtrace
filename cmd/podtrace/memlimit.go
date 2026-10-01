package main

import "github.com/gma1k/podtrace/internal/memlimit"

// Every role this binary runs, CLI, agent, operator and session Job, gets the
// Go soft memory limit from its container before it starts work.
func init() {
	memlimit.Apply()
}
