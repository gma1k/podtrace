package probes

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestFindLibcPath(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
		expectEmpty bool
	}{
		{"empty container ID", "", false},
		{"non-empty container ID", "test-container", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindLibcPath(tt.containerID)
			if tt.expectEmpty && result != "" {
				t.Errorf("Expected empty path, got %q", result)
			}
		})
	}
}

func TestFindLibcInContainer(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
	}{
		{"empty container ID", ""},
		{"non-existent container", "nonexistent-container-id"},
		{"valid format container ID", "abc123def456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindLibcInContainer(tt.containerID)
			if result == nil {
				t.Error("FindLibcInContainer should return non-nil slice")
			}
		})
	}
}

func TestAttachDNSProbes(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	tests := []struct {
		name        string
		containerID string
	}{
		{"empty container ID", ""},
		{"non-empty container ID", "test-container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := AttachDNSProbes(coll, tt.containerID)
			if links != nil {
				t.Logf("AttachDNSProbes returned %d links", len(links))
			}
		})
	}
}

func TestAttachSyncProbes(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	tests := []struct {
		name        string
		containerID string
	}{
		{"empty container ID", ""},
		{"non-empty container ID", "test-container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := AttachSyncProbes(coll, tt.containerID)
			if links != nil {
				t.Logf("AttachSyncProbes returned %d links", len(links))
			}
		})
	}
}

func TestAttachDBProbes(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	tests := []struct {
		name        string
		containerID string
	}{
		{"empty container ID", ""},
		{"non-empty container ID", "test-container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := AttachDBProbes(coll, tt.containerID)
			if links != nil {
				t.Logf("AttachDBProbes returned %d links", len(links))
			}
		})
	}
}

func TestAttachProbes_EmptyCollection(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: make(map[string]*ebpf.Program),
	}

	links, err := AttachProbes(coll)
	if err != nil {
		t.Logf("AttachProbes returned error (expected for empty collection): %v", err)
	}
	if links != nil {
		t.Logf("AttachProbes returned %d links", len(links))
	}
}

