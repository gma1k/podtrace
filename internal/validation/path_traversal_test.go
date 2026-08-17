package validation

import (
	"strings"
	"testing"
)

func TestValidatePath_TraversalSegmentInsideBase(t *testing.T) {
	err := ValidatePath("..", "..")
	if err == nil {
		t.Fatal("expected error for a '..' segment")
	}
	if !strings.Contains(err.Error(), "traversal sequence") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateContainerPath_NullByte(t *testing.T) {
	err := ValidateContainerPath("etc/passwd\x00.txt", strings.Repeat("a", 64))
	if err == nil {
		t.Fatal("expected error for an embedded NUL byte")
	}
	if !strings.Contains(err.Error(), "null byte") {
		t.Errorf("unexpected error: %v", err)
	}
}
