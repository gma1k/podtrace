package h3decode

import (
	"encoding/binary"
	"testing"
)

// TestParseRecordAdapterJoinKeys covers the adapter_conn/adapter_stream
// extension: present in records from current BPF objects, zero for records
// from objects built before the fields existed.
func TestParseRecordAdapterJoinKeys(t *testing.T) {
	data := make([]byte, adapterExtSize)
	binary.LittleEndian.PutUint64(data[adapterConnOffset:], 0xdeadbeef)
	binary.LittleEndian.PutUint64(data[adapterConnOffset+8:], 12)

	txn, ok := ParseRecord(data)
	if !ok {
		t.Fatal("ParseRecord failed")
	}
	if txn.AdapterConn != 0xdeadbeef || txn.AdapterStream != 12 {
		t.Fatalf("join keys = %#x/%d, want 0xdeadbeef/12", txn.AdapterConn, txn.AdapterStream)
	}

	old, ok := ParseRecord(data[:recordSize])
	if !ok {
		t.Fatal("ParseRecord failed on pre-extension record")
	}
	if old.AdapterConn != 0 || old.AdapterStream != 0 {
		t.Fatalf("pre-extension record produced join keys: %+v", old)
	}
}
