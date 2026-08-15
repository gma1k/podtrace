package h2decode

import "testing"

func TestGrpcTrailerStatus_ClampedToCanonicalRange(t *testing.T) {
	cases := []struct {
		name      string
		status    string
		wantError int32
	}{
		{"internal", "13", 13},
		{"unauthenticated_highest_valid", "16", 16},
		{"one_past_range", "17", 0},
		{"hostile_large", "999999", 0},
		{"hostile_maxint", "2147483647", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := New()
			enc := newBlockEncoder()
			block := enc.encode(hf("grpc-status", c.status))
			ev := singleEvent(t, d.Ingest(rec(4, DirIngress, 0, 1, block)))
			if ev.Error != c.wantError {
				t.Fatalf("trailer grpc-status %q: Error = %d, want %d", c.status, ev.Error, c.wantError)
			}
		})
	}
}

func TestGrpcStatusInResponseHeaders_ClampedToCanonicalRange(t *testing.T) {
	cases := []struct {
		status    string
		wantError int32
	}{
		{"13", 13},
		{"999999", 0},
	}
	for _, c := range cases {
		d := New()
		enc := newBlockEncoder()
		block := enc.encode(hf(":status", "200"), hf("grpc-status", c.status))
		ev := singleEvent(t, d.Ingest(rec(4, DirIngress, 0, 1, block)))
		if ev.Error != c.wantError {
			t.Fatalf(":status 200 + grpc-status %q: Error = %d, want %d", c.status, ev.Error, c.wantError)
		}
	}
}
