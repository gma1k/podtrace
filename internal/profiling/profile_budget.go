package profiling

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// The inflate cap bounds the bytes of a profile, not what decoding them
// costs. profile.ParseData turns every two-byte empty sample into a struct of
// about 150 bytes, so 30 KB of gzip holding 15M empty samples grew the heap to
// 2.2 GB. A pass over the wire format prices each message before anything is
// decoded, and a profile over budget is refused.
const (
	maxCPUProfileSamples = 1 << 20

	maxCPUProfileDecodedBytes = 256 * 1024 * 1024
)

// Decoded cost, in heap bytes, of each element profile.ParseData builds,
// counting the slack of the slices it grows by appending.
const (
	costSample        = 192
	costLocationID    = 24
	costSampleValue   = 16
	costLabel         = 128
	costMapping       = 192
	costLocation      = 160
	costLine          = 64
	costFunction      = 128
	costString        = 32
	costValueType     = 64
	costUnknownField  = 16
	costPackedElement = 16
)

// Field numbers of the perftools.profiles.Profile message.
const (
	fieldProfileSampleType = 1
	fieldProfileSample     = 2
	fieldProfileMapping    = 3
	fieldProfileLocation   = 4
	fieldProfileFunction   = 5
	fieldProfileString     = 6
	fieldProfileComment    = 13

	fieldSampleLocationID = 1
	fieldSampleValue      = 2
	fieldSampleLabel      = 3

	fieldLocationLine = 4
)

var errProfileOverBudget = errors.New("profile decodes past the memory budget")

// profileDecodeBudget is the running cost of a profile's wire scan.
type profileDecodeBudget struct {
	cost    uint64
	samples int
}

func (b *profileDecodeBudget) add(n uint64) error {
	b.cost += n
	if b.cost > maxCPUProfileDecodedBytes {
		return fmt.Errorf("%w: more than %d bytes", errProfileOverBudget, maxCPUProfileDecodedBytes)
	}
	return nil
}

// checkProfileDecodeBudget walks a plain pprof protobuf and refuses one whose
// decoded form would exceed maxCPUProfileDecodedBytes or hold more than
// maxCPUProfileSamples samples. Bytes that are not a protobuf message are
// refused too, which keeps profile.ParseData off its legacy text parsers.
func checkProfileDecodeBudget(plain []byte) error {
	var b profileDecodeBudget
	return scanMessage(plain, func(num protowire.Number, typ protowire.Type, body []byte) error {
		switch {
		case num == fieldProfileSample && typ == protowire.BytesType:
			b.samples++
			if b.samples > maxCPUProfileSamples {
				return fmt.Errorf("%w: more than %d samples", errProfileOverBudget, maxCPUProfileSamples)
			}
			if err := b.add(costSample); err != nil {
				return err
			}
			return scanSample(body, &b)
		case num == fieldProfileLocation && typ == protowire.BytesType:
			if err := b.add(costLocation); err != nil {
				return err
			}
			return scanMessage(body, func(n protowire.Number, _ protowire.Type, _ []byte) error {
				if n == fieldLocationLine {
					return b.add(costLine)
				}
				return nil
			})
		case num == fieldProfileString:
			return b.add(costString + uint64(len(body)))
		case num == fieldProfileMapping:
			return b.add(costMapping)
		case num == fieldProfileFunction:
			return b.add(costFunction)
		case num == fieldProfileSampleType:
			return b.add(costValueType)
		case num == fieldProfileComment && typ == protowire.BytesType:
			return b.add(costPackedElement * packedVarintCount(body))
		default:
			return b.add(costUnknownField)
		}
	})
}

// scanSample prices one sample's location ids, values and labels, whether
// the repeated scalars arrive packed or one field at a time.
func scanSample(body []byte, b *profileDecodeBudget) error {
	return scanMessage(body, func(num protowire.Number, typ protowire.Type, value []byte) error {
		var each uint64
		switch num {
		case fieldSampleLocationID:
			each = costLocationID
		case fieldSampleValue:
			each = costSampleValue
		case fieldSampleLabel:
			return b.add(costLabel)
		default:
			return nil
		}
		if typ == protowire.BytesType {
			return b.add(each * packedVarintCount(value))
		}
		return b.add(each)
	})
}

// scanMessage calls visit with every field of a protobuf message. body is the
// field's payload for length-delimited fields and nil otherwise.
func scanMessage(data []byte, visit func(protowire.Number, protowire.Type, []byte) error) error {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return fmt.Errorf("profile is not a pprof protobuf: %w", protowire.ParseError(n))
		}
		data = data[n:]
		var body []byte
		if typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return fmt.Errorf("profile is not a pprof protobuf: %w", protowire.ParseError(m))
			}
			body, n = v, m
		} else {
			n = protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return fmt.Errorf("profile is not a pprof protobuf: %w", protowire.ParseError(n))
			}
		}
		data = data[n:]
		if err := visit(num, typ, body); err != nil {
			return err
		}
	}
	return nil
}

// packedVarintCount is how many varints a packed repeated field holds: one
// per byte without the continuation bit.
func packedVarintCount(packed []byte) uint64 {
	var n uint64
	for _, c := range packed {
		if c < 0x80 {
			n++
		}
	}
	return n
}
