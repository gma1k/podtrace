package usdt

import (
	"runtime"
	"testing"
)

func TestParseArgDesc_Registers(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("register offsets asserted for amd64; running on %s", runtime.GOARCH)
	}
	args := parseArgDesc("8@%rbx -4@%eax")
	if len(args) != 2 {
		t.Fatalf("got %d args, want 2", len(args))
	}
	if args[0].Kind != ArgReg || args[0].Size != 8 || args[0].RegOff != 40 {
		t.Errorf("arg0 = %+v, want reg size=8 off=40 (rbx)", args[0])
	}
	if args[1].Kind != ArgReg || args[1].Size != -4 || args[1].RegOff != 80 {
		t.Errorf("arg1 = %+v, want reg size=-4 off=80 (eax->rax)", args[1])
	}
}

func TestParseArgDesc_Constant(t *testing.T) {
	args := parseArgDesc("4@$5 -8@$-10")
	if len(args) != 2 {
		t.Fatalf("got %d args, want 2", len(args))
	}
	if args[0].Kind != ArgConst || args[0].Disp != 5 || args[0].Size != 4 {
		t.Errorf("arg0 = %+v, want const 5 size=4", args[0])
	}
	if args[1].Kind != ArgConst || args[1].Disp != -10 || args[1].Size != -8 {
		t.Errorf("arg1 = %+v, want const -10 size=-8", args[1])
	}
}

func TestParseArgDesc_Memory(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("register offsets asserted for amd64; running on %s", runtime.GOARCH)
	}
	args := parseArgDesc("8@-16(%rbp) 4@(%rdi)")
	if len(args) != 2 {
		t.Fatalf("got %d args, want 2", len(args))
	}
	if args[0].Kind != ArgMem || args[0].RegOff != 32 || args[0].Disp != -16 {
		t.Errorf("arg0 = %+v, want mem base=rbp(32) disp=-16", args[0])
	}
	// No displacement defaults to 0.
	if args[1].Kind != ArgMem || args[1].RegOff != 112 || args[1].Disp != 0 {
		t.Errorf("arg1 = %+v, want mem base=rdi(112) disp=0", args[1])
	}
}

func TestParseArgDesc_UnsupportedAndMalformed(t *testing.T) {
	args := parseArgDesc("8@-8(%rax,%rbx,4) 8@%notareg junk 0@%rax")
	if len(args) != 4 {
		t.Fatalf("got %d args, want 4 (each operand keeps a slot)", len(args))
	}
	for i, a := range args {
		if a.Kind != ArgUnsupported {
			t.Errorf("arg%d = %+v, want ArgUnsupported", i, a)
		}
	}
}

func TestParseArgDesc_CapAndEmpty(t *testing.T) {
	if got := parseArgDesc(""); got != nil {
		t.Errorf("empty descriptor = %v, want nil", got)
	}
	if got := parseArgDesc("   "); got != nil {
		t.Errorf("blank descriptor = %v, want nil", got)
	}
	args := parseArgDesc("4@$1 4@$2 4@$3 4@$4 4@$5 4@$6")
	if len(args) != MaxArgs {
		t.Errorf("got %d args, want cap %d", len(args), MaxArgs)
	}
}

func FuzzParseArgDesc(f *testing.F) {
	f.Add("8@%rbx -4@%eax 4@$5 8@-16(%rbp)")
	f.Add("8@-8(%rax,%rbx,4)")
	f.Add("")
	f.Add("@@@ 99@ @%rax 999999999999999999999@%rax")
	f.Fuzz(func(t *testing.T, desc string) {
		args := parseArgDesc(desc)
		if len(args) > MaxArgs {
			t.Fatalf("parseArgDesc(%q) returned %d args, exceeds cap %d", desc, len(args), MaxArgs)
		}
	})
}
