// Late-join tolerant HPACK block decoder.

package h2decode

import (
	"errors"

	"golang.org/x/net/http2/hpack"
)

const (
	hpackStaticTableSize = 61

	maxTrackedInserts = 1024

	maxDynamicIndex = hpackStaticTableSize + 8192

	maxFieldsPerBlock = 256
)

var (
	errHPACKTruncated       = errors.New("hpack: truncated block")
	errHPACKIntegerOverflow = errors.New("hpack: integer overflow")
	errHPACKZeroIndex       = errors.New("hpack: zero index")
	errHPACKIndexRange      = errors.New("hpack: index out of range")
	errHPACKTooManyFields   = errors.New("hpack: too many fields in block")
)

// tableEntry is one observed dynamic-table insertion.
type tableEntry struct {
	field       hpack.HeaderField
	unknownName bool
}

// lateJoinDecoder decodes HPACK header blocks tolerantly, resolving what the
// observed insertion window allows and skipping pre-attach references instead
// of failing the block.
type lateJoinDecoder struct {
	inserts []tableEntry
}

// resetEpoch discards the observed insertion window.
func (d *lateJoinDecoder) resetEpoch() {
	d.inserts = d.inserts[:0]
}

// decodeBlock decodes one complete header block. complete is false when one
// or more fields referenced pre-attach dynamic-table state and were skipped.
func (d *lateJoinDecoder) decodeBlock(block []byte) (fields []hpack.HeaderField, complete bool, err error) {
	complete = true
	pos := 0
	for pos < len(block) {
		if len(fields) >= maxFieldsPerBlock {
			return nil, false, errHPACKTooManyFields
		}
		b := block[pos]
		switch {
		case b&0x80 != 0:
			index, n, err := readInteger(block[pos:], 7)
			if err != nil {
				return nil, false, err
			}
			pos += n
			field, ok, err := d.resolveIndex(index)
			if err != nil {
				return nil, false, err
			}
			if ok {
				fields = append(fields, field)
			} else {
				complete = false
			}
		case b&0xc0 == 0x40:
			field, ok, n, err := d.readLiteral(block[pos:], 6)
			if err != nil {
				return nil, false, err
			}
			pos += n
			d.insert(tableEntry{field: field, unknownName: !ok})
			if ok {
				fields = append(fields, field)
			} else {
				complete = false
			}
		case b&0xe0 == 0x20:
			_, n, err := readInteger(block[pos:], 5)
			if err != nil {
				return nil, false, err
			}
			pos += n
		default:
			field, ok, n, err := d.readLiteral(block[pos:], 4)
			if err != nil {
				return nil, false, err
			}
			pos += n
			if ok {
				fields = append(fields, field)
			} else {
				complete = false
			}
		}
	}
	return fields, complete, nil
}

// readLiteral parses a literal header field representation whose name-index
// integer uses the given prefix width.
func (d *lateJoinDecoder) readLiteral(buf []byte, prefix uint8) (field hpack.HeaderField, ok bool, consumed int, err error) {
	nameIndex, n, err := readInteger(buf, prefix)
	if err != nil {
		return hpack.HeaderField{}, false, 0, err
	}
	pos := n

	name := ""
	nameOK := true
	if nameIndex == 0 {
		name, n, err = readString(buf[pos:])
		if err != nil {
			return hpack.HeaderField{}, false, 0, err
		}
		pos += n
	} else {
		var ref hpack.HeaderField
		ref, nameOK, err = d.resolveIndex(nameIndex)
		if err != nil {
			return hpack.HeaderField{}, false, 0, err
		}
		name = ref.Name
	}

	value, n, err := readString(buf[pos:])
	if err != nil {
		return hpack.HeaderField{}, false, 0, err
	}
	pos += n

	return hpack.HeaderField{Name: name, Value: value}, nameOK, pos, nil
}

// resolveIndex maps an HPACK index to a header field.
func (d *lateJoinDecoder) resolveIndex(index int) (hpack.HeaderField, bool, error) {
	switch {
	case index == 0:
		return hpack.HeaderField{}, false, errHPACKZeroIndex
	case index <= hpackStaticTableSize:
		return hpackStaticTable[index-1], true, nil
	case index > maxDynamicIndex:
		return hpack.HeaderField{}, false, errHPACKIndexRange
	}
	ordinal := index - hpackStaticTableSize
	if ordinal > len(d.inserts) {
		return hpack.HeaderField{}, false, nil
	}
	entry := d.inserts[len(d.inserts)-ordinal]
	if entry.unknownName {
		return hpack.HeaderField{}, false, nil
	}
	return entry.field, true, nil
}

func (d *lateJoinDecoder) insert(entry tableEntry) {
	d.inserts = append(d.inserts, entry)
	if len(d.inserts) > maxTrackedInserts {
		n := copy(d.inserts, d.inserts[len(d.inserts)-maxTrackedInserts:])
		d.inserts = d.inserts[:n]
	}
}

// readInteger decodes an HPACK variable-length integer (RFC 7541 §5.1) whose
// first byte carries a prefix-bit payload.
func readInteger(buf []byte, prefix uint8) (value int, consumed int, err error) {
	if len(buf) == 0 {
		return 0, 0, errHPACKTruncated
	}
	mask := int(1)<<prefix - 1
	value = int(buf[0]) & mask
	if value < mask {
		return value, 1, nil
	}
	consumed = 1
	var shift uint
	for {
		if consumed >= len(buf) {
			return 0, 0, errHPACKTruncated
		}
		if shift > 21 {
			return 0, 0, errHPACKIntegerOverflow
		}
		b := buf[consumed]
		consumed++
		value += int(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, consumed, nil
		}
		shift += 7
	}
}

// readString decodes an HPACK string literal (RFC 7541 §5.2), applying
// Huffman decoding when the H bit is set.
func readString(buf []byte) (s string, consumed int, err error) {
	if len(buf) == 0 {
		return "", 0, errHPACKTruncated
	}
	huffman := buf[0]&0x80 != 0
	length, n, err := readInteger(buf, 7)
	if err != nil {
		return "", 0, err
	}
	if length > len(buf)-n {
		return "", 0, errHPACKTruncated
	}
	raw := buf[n : n+length]
	consumed = n + length
	if !huffman {
		return string(raw), consumed, nil
	}
	s, err = hpack.HuffmanDecodeToString(raw)
	if err != nil {
		return "", 0, err
	}
	return s, consumed, nil
}

// hpackStaticTable is the RFC 7541 Appendix A static table (indices 1-61).
var hpackStaticTable = [hpackStaticTableSize]hpack.HeaderField{
	{Name: ":authority"},
	{Name: ":method", Value: "GET"},
	{Name: ":method", Value: "POST"},
	{Name: ":path", Value: "/"},
	{Name: ":path", Value: "/index.html"},
	{Name: ":scheme", Value: "http"},
	{Name: ":scheme", Value: "https"},
	{Name: ":status", Value: "200"},
	{Name: ":status", Value: "204"},
	{Name: ":status", Value: "206"},
	{Name: ":status", Value: "304"},
	{Name: ":status", Value: "400"},
	{Name: ":status", Value: "404"},
	{Name: ":status", Value: "500"},
	{Name: "accept-charset"},
	{Name: "accept-encoding", Value: "gzip, deflate"},
	{Name: "accept-language"},
	{Name: "accept-ranges"},
	{Name: "accept"},
	{Name: "access-control-allow-origin"},
	{Name: "age"},
	{Name: "allow"},
	{Name: "authorization"},
	{Name: "cache-control"},
	{Name: "content-disposition"},
	{Name: "content-encoding"},
	{Name: "content-language"},
	{Name: "content-length"},
	{Name: "content-location"},
	{Name: "content-range"},
	{Name: "content-type"},
	{Name: "cookie"},
	{Name: "date"},
	{Name: "etag"},
	{Name: "expect"},
	{Name: "expires"},
	{Name: "from"},
	{Name: "host"},
	{Name: "if-match"},
	{Name: "if-modified-since"},
	{Name: "if-none-match"},
	{Name: "if-range"},
	{Name: "if-unmodified-since"},
	{Name: "last-modified"},
	{Name: "link"},
	{Name: "location"},
	{Name: "max-forwards"},
	{Name: "proxy-authenticate"},
	{Name: "proxy-authorization"},
	{Name: "range"},
	{Name: "referer"},
	{Name: "refresh"},
	{Name: "retry-after"},
	{Name: "server"},
	{Name: "set-cookie"},
	{Name: "strict-transport-security"},
	{Name: "transfer-encoding"},
	{Name: "user-agent"},
	{Name: "vary"},
	{Name: "via"},
	{Name: "www-authenticate"},
}
