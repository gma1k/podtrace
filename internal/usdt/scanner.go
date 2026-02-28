// Package usdt provides ELF USDT (Userspace Statically Defined Tracing) probe
// discovery by parsing .note.stapsdt sections in ELF binaries.
package usdt

import (
	"debug/elf"
	"fmt"
)

// Probe represents a single USDT probe found in an ELF binary.
type Probe struct {
	Provider string
	Name     string
	PC       uint64 // probe PC address
	SemAddr  uint64 // semaphore address (0 if none)
}

// Scan parses the .note.stapsdt section of exePath and returns all USDT probes.
// Returns nil, nil when no USDT probes are present.
func Scan(exePath string) ([]Probe, error) {
	f, err := elf.Open(exePath)
	if err != nil {
		return nil, fmt.Errorf("usdt: open %q: %w", exePath, err)
	}
	defer func() { _ = f.Close() }()

	section := f.Section(".note.stapsdt")
	if section == nil {
		return nil, nil
	}

	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("usdt: read .note.stapsdt: %w", err)
	}

	order := f.ByteOrder
	var probes []Probe
	offset := 0

	for offset+12 <= len(data) {
		nameLen := int(order.Uint32(data[offset:]))
		descLen := int(order.Uint32(data[offset+4:]))
		noteType := order.Uint32(data[offset+8:])
		offset += 12

		namePad := align4(nameLen)
		descPad := align4(descLen)
		if offset+namePad+descPad > len(data) {
			break
		}

		rawName := data[offset : offset+nameLen]
		if nameLen > 0 && rawName[nameLen-1] == 0 {
			rawName = rawName[:nameLen-1]
		}
		offset += namePad

		desc := data[offset : offset+descLen]
		offset += descPad

		// NT_STAPSDT = 3; section name must be "stapsdt"
		if noteType != 3 || string(rawName) != "stapsdt" {
			continue
		}
		// Descriptor layout: pc(8) base(8) semaphore(8) provider\0name\0argdesc\0
		if len(desc) < 24 {
			continue
		}

		pc := order.Uint64(desc[0:])
		semAddr := order.Uint64(desc[16:])

		strs := desc[24:]
		provider, rest, ok := cstring(strs)
		if !ok {
			continue
		}
		probeName, _, ok := cstring(rest)
		if !ok {
			continue
		}

		probes = append(probes, Probe{
			Provider: provider,
			Name:     probeName,
			PC:       pc,
			SemAddr:  semAddr,
		})
	}

	return probes, nil
}

func align4(n int) int {
	return (n + 3) &^ 3
}

func cstring(b []byte) (string, []byte, bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", nil, false
}
