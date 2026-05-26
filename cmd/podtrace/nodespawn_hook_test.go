package main

import "testing"

func TestSpawnControlFlags_PinsTheStrippedSet(t *testing.T) {
	wantStripped := []string{
		"local",
		"image",
		"spawn-namespace",
		"service-account",
		"dynamic-spawn",
		"keep-spawn-pod",
		"namespace",
		"namespaces",
		"pods",
		"pod-selector",
		"all-in-namespace",
	}
	for _, name := range wantStripped {
		if _, ok := spawnControlFlags[name]; !ok {
			t.Errorf("flag %q must be in spawnControlFlags so it is stripped from the spawn pod's argv reconstruction; "+
				"workstation-only flags forwarded to the spawn pod break against any image that doesn't recognise them", name)
		}
	}
}