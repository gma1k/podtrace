package probes

import "testing"

func TestPoolExhaustionIsNotHookedForLibrariesWithoutAWaitPoint(t *testing.T) {
	for _, cfg := range databaseProbeConfigs() {
		if cfg.name != "postgresql" && cfg.name != "mysql" {
			continue
		}
		if cfg.exhaustSymbol != "" || cfg.exhaustProg != "" {
			t.Errorf("%s hooks %q as pool exhaustion, which reports the connection's age on every query",
				cfg.name, cfg.exhaustSymbol)
		}
	}
}
