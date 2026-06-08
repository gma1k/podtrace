package ldsoconf

import (
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

func TestOpenRoot_CachesAcrossCalls(t *testing.T) {
	withBase(t, t.TempDir())

	first, err := openRoot()
	if err != nil {
		t.Fatalf("first openRoot: %v", err)
	}
	second, err := openRoot()
	if err != nil {
		t.Fatalf("second openRoot: %v", err)
	}
	if first != second {
		t.Errorf("expected cached root to be reused, got distinct instances")
	}
	if first.Name() != config.LdSoConfBasePath {
		t.Errorf("root name = %q, want %q", first.Name(), config.LdSoConfBasePath)
	}
}

func TestOpenRoot_ErrorOnMissingBase(t *testing.T) {
	withBase(t, "/no/such/ldso/base")
	if _, err := openRoot(); err == nil {
		t.Fatal("expected error for missing base directory")
	}
}
