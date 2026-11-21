package tracer

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestDNSQueryStateMatchesTheCompiledObject(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(compiledObjectPath(t))
	if err != nil {
		t.Skipf("BPF object not built: %v", err)
	}
	var st *btf.Struct
	if err := spec.Types.TypeByName("dns_query_state", &st); err != nil {
		t.Fatal(err)
	}
	goFields := map[string]string{
		"ts_ns": "TsNS", "pid": "PID", "qtype": "QType", "server_ip": "ServerIP",
		"transport": "Transport", "multi_server": "MultiServer", "client_port": "ClientPort",
		"comm": "Comm", "name": "Name", "server_ip6": "ServerIP6", "last_ns": "LastNS",
	}
	typ := reflect.TypeOf(dnsQueryState{})
	if uintptr(st.Size) != typ.Size() {
		t.Fatalf("C size %d, Go size %d", st.Size, typ.Size())
	}
	for _, m := range st.Members {
		goName, ok := goFields[m.Name]
		if !ok {
			t.Errorf("C field %s has no Go mirror", m.Name)
			continue
		}
		f, _ := typ.FieldByName(goName)
		if uintptr(m.Offset.Bytes()) != f.Offset {
			t.Errorf("%s: C offset %d, Go offset %d", m.Name, m.Offset.Bytes(), f.Offset)
		}
	}
}
