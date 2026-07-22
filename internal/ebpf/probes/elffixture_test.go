package probes

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
)

type fixtureSection struct {
	name string
	typ  uint32
	data []byte
}

func buildELFWithSections(secs []fixtureSection) []byte {
	le := binary.LittleEndian
	const ehsize = 64
	const shentsize = 64

	shstr := []byte{0}
	nameOff := make([]uint32, len(secs))
	for i, s := range secs {
		nameOff[i] = uint32(len(shstr))
		shstr = append(shstr, s.name...)
		shstr = append(shstr, 0)
	}
	shstrtabNameOff := uint32(len(shstr))
	shstr = append(shstr, ".shstrtab"...)
	shstr = append(shstr, 0)

	var buf bytes.Buffer
	buf.Write(make([]byte, ehsize))
	dataOff := make([]uint64, len(secs))
	for i, s := range secs {
		dataOff[i] = uint64(buf.Len())
		buf.Write(s.data)
	}
	shstrOff := uint64(buf.Len())
	buf.Write(shstr)
	for buf.Len()%8 != 0 {
		buf.WriteByte(0)
	}
	shoff := uint64(buf.Len())

	writeSH := func(no, typ uint32, off, size uint64) {
		h := make([]byte, shentsize)
		le.PutUint32(h[0:], no)
		le.PutUint32(h[4:], typ)
		le.PutUint64(h[24:], off)
		le.PutUint64(h[32:], size)
		le.PutUint64(h[48:], 1)
		buf.Write(h)
	}
	buf.Write(make([]byte, shentsize))
	for i, s := range secs {
		writeSH(nameOff[i], s.typ, dataOff[i], uint64(len(s.data)))
	}
	writeSH(shstrtabNameOff, 3, shstrOff, uint64(len(shstr)))

	out := buf.Bytes()
	copy(out[0:], []byte{0x7f, 'E', 'L', 'F'})
	out[4] = 2
	out[5] = 1
	out[6] = 1
	le.PutUint16(out[16:], 2)
	le.PutUint16(out[18:], 0x3e)
	le.PutUint32(out[20:], 1)
	le.PutUint16(out[52:], ehsize)
	nsec := len(secs) + 2
	le.PutUint64(out[40:], shoff)
	le.PutUint16(out[58:], shentsize)
	le.PutUint16(out[60:], uint16(nsec))
	le.PutUint16(out[62:], uint16(nsec-1))
	return out
}

func elfFromSections(secs []fixtureSection) (*elf.File, error) {
	return elf.NewFile(bytes.NewReader(buildELFWithSections(secs)))
}

func emptyELF() (*elf.File, error) {
	return elfFromSections(nil)
}
