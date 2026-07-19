package usdt

import (
	"runtime"
	"strconv"
	"strings"
)

// MaxArgs bounds how many decoded operands are carried per probe.
const MaxArgs = 4

// ArgKind classifies how a decoded USDT operand yields its value at probe time.
type ArgKind uint8

const (
	ArgUnsupported ArgKind = 0
	ArgReg         ArgKind = 1
	ArgMem         ArgKind = 2
	ArgConst       ArgKind = 3
)

// Arg is a single decoded USDT operand from the stapsdt argument descriptor.
type Arg struct {
	Size   int8
	Kind   ArgKind
	RegOff uint16
	Disp   int64
}

// parseArgDesc decodes a stapsdt argument descriptor, a space-separated list
// of `N@operand` specs in AT&T syntax, into at most MaxArgs operands.
func parseArgDesc(desc string) []Arg {
	desc = strings.TrimSpace(desc)
	if desc == "" {
		return nil
	}
	regs := ptRegsOffsets()
	var args []Arg
	for _, tok := range strings.Fields(desc) {
		if len(args) >= MaxArgs {
			break
		}
		args = append(args, parseArgToken(tok, regs))
	}
	return args
}

// parseArgToken decodes one `N@operand` spec.
func parseArgToken(tok string, regs map[string]uint16) Arg {
	at := strings.IndexByte(tok, '@')
	if at <= 0 || at == len(tok)-1 {
		return Arg{Kind: ArgUnsupported}
	}
	size, err := strconv.ParseInt(tok[:at], 10, 8)
	if err != nil || size == 0 {
		return Arg{Kind: ArgUnsupported}
	}
	op := tok[at+1:]
	a := Arg{Size: int8(size), Kind: ArgUnsupported}

	switch {
	case strings.HasPrefix(op, "$"):
		if v, err := strconv.ParseInt(op[1:], 10, 64); err == nil {
			a.Kind = ArgConst
			a.Disp = v
		}
	case strings.HasPrefix(op, "%"):
		if off, ok := regs[strings.ToLower(op[1:])]; ok {
			a.Kind = ArgReg
			a.RegOff = off
		}
	case strings.Contains(op, "("):
		openIdx := strings.IndexByte(op, '(')
		closeIdx := strings.IndexByte(op, ')')
		if closeIdx > openIdx {
			inner := op[openIdx+1 : closeIdx]
			if !strings.ContainsAny(inner, ",") && strings.HasPrefix(inner, "%") {
				if off, ok := regs[strings.ToLower(inner[1:])]; ok {
					disp := int64(0)
					if d := strings.TrimSpace(op[:openIdx]); d != "" {
						if v, err := strconv.ParseInt(d, 10, 64); err == nil {
							disp = v
						} else {
							return a // malformed displacement
						}
					}
					a.Kind = ArgMem
					a.RegOff = off
					a.Disp = disp
				}
			}
		}
	}
	return a
}

// ptRegsOffsets maps register names (as they appear in stapsdt operands,
// including common sub-register aliases) to their byte offset within the
// running architecture's pt_regs.
func ptRegsOffsets() map[string]uint16 {
	switch runtime.GOARCH {
	case "amd64":
		return amd64Regs
	case "arm64":
		return arm64Regs
	default:
		return nil
	}
}

// amd64Regs mirrors the field order of the kernel's x86_64 struct pt_regs (each
// entry 8 bytes). Sub-register names (eax/ax/al ...) alias their 64-bit parent.
var amd64Regs = func() map[string]uint16 {
	base := []struct {
		off   uint16
		names []string
	}{
		{0, []string{"r15", "r15d", "r15w", "r15b"}},
		{8, []string{"r14", "r14d", "r14w", "r14b"}},
		{16, []string{"r13", "r13d", "r13w", "r13b"}},
		{24, []string{"r12", "r12d", "r12w", "r12b"}},
		{32, []string{"rbp", "ebp", "bp", "bpl"}},
		{40, []string{"rbx", "ebx", "bx", "bl"}},
		{48, []string{"r11", "r11d", "r11w", "r11b"}},
		{56, []string{"r10", "r10d", "r10w", "r10b"}},
		{64, []string{"r9", "r9d", "r9w", "r9b"}},
		{72, []string{"r8", "r8d", "r8w", "r8b"}},
		{80, []string{"rax", "eax", "ax", "al"}},
		{88, []string{"rcx", "ecx", "cx", "cl"}},
		{96, []string{"rdx", "edx", "dx", "dl"}},
		{104, []string{"rsi", "esi", "si", "sil"}},
		{112, []string{"rdi", "edi", "di", "dil"}},
		{128, []string{"rip"}},
		{152, []string{"rsp", "esp", "sp", "spl"}},
	}
	m := make(map[string]uint16)
	for _, r := range base {
		for _, n := range r.names {
			m[n] = r.off
		}
	}
	return m
}()

// arm64Regs mirrors struct user_pt_regs: regs[0..30] (x0..x30) then sp. wN names
// alias their 64-bit xN parent.
var arm64Regs = func() map[string]uint16 {
	m := make(map[string]uint16)
	for i := 0; i <= 30; i++ {
		off := uint16(i * 8)
		m["x"+strconv.Itoa(i)] = off
		m["w"+strconv.Itoa(i)] = off
	}
	m["sp"] = 31 * 8
	return m
}()
