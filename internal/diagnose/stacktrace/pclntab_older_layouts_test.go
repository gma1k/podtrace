package stacktrace

import (
	"bytes"
	"debug/gosym"
	"encoding/binary"
	"testing"

	"github.com/gma1k/podtrace/internal/safeconv"
)

type olderFunc struct {
	entry, end uint64
	name       string
}

type olderLayout struct {
	order   binary.ByteOrder
	magic   uint32
	ptrSize byte
}

func (l olderLayout) put(buf []byte, at int, v uint64) {
	if l.ptrSize == 8 {
		l.order.PutUint64(buf[at:], v)
	} else {
		l.order.PutUint32(buf[at:], safeconv.Uint64ToUint32(v))
	}
}

func olderPCLN(l olderLayout, funcs []olderFunc) []byte {
	p := int(l.ptrSize)
	buf := make([]byte, 4096)
	l.order.PutUint32(buf, l.magic)
	buf[6], buf[7] = 1, l.ptrSize
	l.put(buf, 8, safeconv.IntToUint64(len(funcs)))

	var nameTab, functabAt, funcdata int
	if l.magic == go116PCLnTabMagic {
		nameTab = 8 + 7*p
		functabAt = 512
		funcdata = functabAt
		for w := 1; w < 7; w++ {
			l.put(buf, 8+w*p, safeconv.IntToUint64(nameTab))
		}
		l.put(buf, 8+1*p, 0)
		l.put(buf, 8+2*p, safeconv.IntToUint64(nameTab))
		l.put(buf, 8+6*p, safeconv.IntToUint64(functabAt))
	} else {
		functabAt = 8 + p
		nameTab = 2048
	}

	nameOff := make([]int, len(funcs))
	at := nameTab + 1
	for i, f := range funcs {
		nameOff[i] = at - nameTab
		at += copy(buf[at:], f.name) + 1
	}

	functabLen := (2*len(funcs) + 1) * p
	records := functabAt + functabLen + 8
	for i, f := range funcs {
		rec := records + i*(p+40)
		l.put(buf, functabAt+2*i*p, f.entry)
		l.put(buf, functabAt+(2*i+1)*p, safeconv.IntToUint64(rec-funcdata))
		l.put(buf, rec, f.entry)
		l.order.PutUint32(buf[rec+p:], safeconv.IntToUint32(nameOff[i]))
	}
	l.put(buf, functabAt+2*len(funcs)*p, funcs[len(funcs)-1].end)
	if l.magic == go12PCLnTabMagic {
		fileoff := 3072
		l.order.PutUint32(buf[functabAt+functabLen:], safeconv.IntToUint32(fileoff))
		l.order.PutUint32(buf[fileoff:], 1)
	}
	return buf
}

func TestOlderPclntabLayoutsNameEveryFunctionExactlyAsGosymDoes(t *testing.T) {
	funcs := []olderFunc{
		{0x401000, 0x401040, "main.main"},
		{0x401040, 0x401100, "net/http.(*conn).serve"},
		{0x401100, 0x401104, "runtime.goexit"},
	}
	for _, l := range []olderLayout{
		{binary.LittleEndian, go116PCLnTabMagic, 8},
		{binary.BigEndian, go116PCLnTabMagic, 8},
		{binary.LittleEndian, go116PCLnTabMagic, 4},
		{binary.LittleEndian, go12PCLnTabMagic, 8},
		{binary.BigEndian, go12PCLnTabMagic, 4},
	} {
		data := olderPCLN(l, funcs)
		oracle, err := gosym.NewTable(nil, gosym.NewLineTable(data, 0x401000))
		if err != nil || len(oracle.Funcs) != len(funcs) {
			t.Fatalf("%#x/%d/%v: gosym read %d functions, %v; the fixture is not a valid table", l.magic, l.ptrSize, l.order, len(oracle.Funcs), err)
		}
		idx, ok := parsePCLNIndex(bytes.NewReader(data), 0, safeconv.IntToUint64(len(data)), 0x401000)
		if !ok {
			t.Fatalf("%#x/%d/%v: the index refused a table gosym reads", l.magic, l.ptrSize, l.order)
		}
		for _, fn := range oracle.Funcs {
			for _, pc := range []uint64{fn.Entry, (fn.Entry + fn.End) / 2, fn.End - 1} {
				if got := idx.name(bytes.NewReader(data), pc); got != fn.Name {
					t.Errorf("%#x/%d/%v: name(%#x) = %q, gosym says %q", l.magic, l.ptrSize, l.order, pc, got, fn.Name)
				}
			}
		}
		for _, pc := range []uint64{0x400fff, 0x401104, 0} {
			if got := idx.name(bytes.NewReader(data), pc); got != "" {
				t.Errorf("%#x/%d/%v: name(%#x) = %q outside the functions", l.magic, l.ptrSize, l.order, pc, got)
			}
		}
	}
}

func TestAnOlderFunctionRecordOffsetPastTheSectionYieldsNothing(t *testing.T) {
	l := olderLayout{binary.LittleEndian, go116PCLnTabMagic, 8}
	data := olderPCLN(l, []olderFunc{{0x401000, 0x401040, "main.main"}})
	l.put(data, 512+8, 1<<63)
	idx, ok := parsePCLNIndex(bytes.NewReader(data), 0, safeconv.IntToUint64(len(data)), 0)
	if !ok {
		t.Fatal("the header was refused")
	}
	if got := idx.name(bytes.NewReader(data), 0x401010); got != "" {
		t.Errorf("name = %q from a record offset of 2^63", got)
	}
	l.put(data, 512+8, safeconv.IntToUint64(len(data)-8))
	if got := idx.name(bytes.NewReader(data), 0x401010); got != "" {
		t.Errorf("name = %q from a record whose name offset is past the section", got)
	}
}

func TestAGo12FunctionTablePastTheSectionIsRefused(t *testing.T) {
	l := olderLayout{binary.LittleEndian, go12PCLnTabMagic, 8}
	data := olderPCLN(l, []olderFunc{{0x401000, 0x401040, "main.main"}})
	l.put(data, 8, 255)
	if _, ok := parsePCLNIndex(bytes.NewReader(data), 0, safeconv.IntToUint64(len(data)), 0); ok {
		t.Error("a function table running past the section was accepted")
	}
}
