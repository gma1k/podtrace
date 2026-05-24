package stacktrace

import "testing"

func TestKallsyms_BinarySearch(t *testing.T) {
	k := &kallsymsLookup{
		syms: []ksym{
			{Addr: 0xffffffff81000000, Name: "_text"},
			{Addr: 0xffffffff81234000, Name: "sys_open"},
			{Addr: 0xffffffff81234100, Name: "sys_close"},
			{Addr: 0xffffffff81fff000, Name: "_end"},
		},
		loaded:  true,
		maxAddr: 0xffffffff81fff000,
	}
	k.once.Do(func() {})

	tests := []struct {
		name string
		addr uint64
		want string
	}{
		{"first symbol exact", 0xffffffff81000000, "_text+0x0"},
		{"between sys_open and sys_close", 0xffffffff8123407f, "sys_open+0x7f"},
		{"sys_close exact", 0xffffffff81234100, "sys_close+0x0"},
		{"out of range", 0xffffffff82000000, ""},
		{"zero", 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := k.Resolve(tc.addr)
			if got != tc.want {
				t.Errorf("Resolve(0x%x) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

func TestIsKernelAddress(t *testing.T) {
	tests := map[uint64]bool{
		0x7fff12345678:     false, // user-space
		0xffff800000000000: true,  // kernel boundary
		0xffffffff81000000: true,  // typical x86_64 kernel
		0x0:                false,
	}
	for addr, want := range tests {
		if got := IsKernelAddress(addr); got != want {
			t.Errorf("IsKernelAddress(0x%x) = %v, want %v", addr, got, want)
		}
	}
}
