package probes

import "testing"

func TestRustlsSymbolPatterns(t *testing.T) {
	match := []struct {
		name string
		sym  string
		pat  []string
	}{
		{"legacy write", "_ZN67_$LT$rustls..conn..connection..Writer$u20$as$u20$std..io..Write$GT$5write17h047145b15f069e6fE", rustlsWriteSymbolPattern},
		{"legacy read", "_ZN66_$LT$rustls..conn..connection..Reader$u20$as$u20$std..io..Read$GT$4read17h879fa3fd0b5fb779E", rustlsReadSymbolPattern},
		{"v0 write", "_RNvXs5_NtNtCs7J8aaykGygQ_6rustls4conn10connectionNtB5_6WriterNtNtCs94HoCtyTi6t_3std2io5Write5write", rustlsWriteSymbolPattern},
		{"v0 read", "_RNvXs2_NtNtCs7J8aaykGygQ_6rustls4conn10connectionNtB5_6ReaderNtNtCs94HoCtyTi6t_3std2io4Read4read", rustlsReadSymbolPattern},
	}
	for _, m := range match {
		if !nameContainsAll(m.sym, m.pat...) {
			t.Errorf("%s: expected match: %s", m.name, m.sym)
		}
	}

	noMatch := []struct {
		name string
		sym  string
		pat  []string
	}{
		{"legacy flush not write", "_ZN67_$LT$rustls..conn..connection..Writer$u20$as$u20$std..io..Write$GT$5flush17h14ac3a26f8f7ff71E", rustlsWriteSymbolPattern},
		{"legacy write_all not write", "_ZN67_$LT$rustls..conn..connection..Writer$u20$as$u20$std..io..Write$GT$9write_all17habcdef0123456789E", rustlsWriteSymbolPattern},
		{"v0 flush not write", "_RNvXs5_NtNtCs7J8aaykGygQ_6rustls4conn10connectionNtB5_6WriterNtNtCs94HoCtyTi6t_3std2io5Write5flush", rustlsWriteSymbolPattern},
		{"v0 write_all not write", "_RNvXs5_NtNtCs7J8aaykGygQ_6rustls4conn10connectionNtB5_6WriterNtNtCs94HoCtyTi6t_3std2io5Write9write_all", rustlsWriteSymbolPattern},
		{"read not write", "_ZN66_$LT$rustls..conn..connection..Reader$u20$as$u20$std..io..Read$GT$4read17h879fa3fd0b5fb779E", rustlsWriteSymbolPattern},
		{"non-rustls bufwriter", "_ZN3std2io8buffered9bufwriter18BufWriter$LT$W$GT$5write17hdeadbeefdeadbeefE", rustlsWriteSymbolPattern},
	}
	for _, m := range noMatch {
		if nameContainsAll(m.sym, m.pat...) {
			t.Errorf("%s: expected NO match: %s", m.name, m.sym)
		}
	}
}