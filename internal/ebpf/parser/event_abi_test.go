package parser

import (
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestBPFStructSizeMatchesV9Decoding(t *testing.T) {
	const bpfEventSize = 432
	const methodOffset = 424

	data := make([]byte, bpfEventSize)
	binary.LittleEndian.PutUint64(data[0:], 12345)
	binary.LittleEndian.PutUint32(data[8:], 99)
	binary.LittleEndian.PutUint32(data[12:], uint32(events.EventHTTPResp))
	data[methodOffset] = 3

	event := ParseEvent(data)
	if event == nil {
		t.Fatalf("ParseEvent returned nil for a %d-byte record; the compiled BPF struct is that "+
			"size, so every event from the kernel would be dropped", bpfEventSize)
	}
	if event.HTTPMethod != "POST" {
		t.Errorf("HTTPMethod = %q, want POST. The compiled bpf/podtrace.bpf.c reports "+
			"sizeof(struct event) == %d with http_method at offset %d; if the Go rawEventV9 "+
			"disagrees, records decode as V8 and the method is silently lost",
			event.HTTPMethod, bpfEventSize, methodOffset)
	}
}

func TestV9DecodeFailureReturnsNilRatherThanAPartialEvent(t *testing.T) {
	original := binaryRead
	binaryRead = func(io.Reader, binary.ByteOrder, any) error {
		return errors.New("short read")
	}
	defer func() { binaryRead = original }()

	if got := ParseEvent(make([]byte, 432)); got != nil {
		t.Errorf("ParseEvent returned %+v on a decode failure, want nil. The event came from a "+
			"pool, so handing back a half-filled one would leak the previous event's fields into "+
			"a caller that believes it read the kernel", got)
	}
}
