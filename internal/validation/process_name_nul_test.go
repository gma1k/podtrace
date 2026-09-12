package validation

import "testing"

func TestProcessNameStopsAtTheFirstNUL(t *testing.T) {
	if got := SanitizeProcessName("app\x00poolapp"); got != "app" {
		t.Errorf("SanitizeProcessName = %q, want \"app\".\n\nA comm is a C string in a "+
			"fixed-width buffer. Filtering the NUL out as an unprintable character "+
			"concatenates whatever followed it, inventing a process name that never "+
			"existed -- \"apppoolapp\" was reported for a workload whose only binary is "+
			"poolapp.", got)
	}
}

func TestProcessNameKeepsAnOrdinaryComm(t *testing.T) {
	for _, name := range []string{"poolapp", "nginx", "postgres", "java"} {
		if got := SanitizeProcessName(name); got != name {
			t.Errorf("SanitizeProcessName(%q) = %q, want it unchanged", name, got)
		}
	}
}

func TestProcessNameStillStripsControlCharacters(t *testing.T) {
	if got := SanitizeProcessName("po\x1b[31mol"); got != "po[31mol" {
		t.Errorf("SanitizeProcessName = %q; the escape byte must still be dropped so a "+
			"process name cannot repaint an operator's terminal", got)
	}
}

func TestProcessNameOfOnlyANULIsEmpty(t *testing.T) {
	if got := SanitizeProcessName("\x00garbage"); got != "" {
		t.Errorf("SanitizeProcessName = %q, want empty; a buffer whose first byte "+
			"terminates the string carries no name at all, and returning the trailing "+
			"bytes would attribute events to whatever was there before", got)
	}
}
