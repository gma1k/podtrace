package profiling

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/pprof/profile"
	"google.golang.org/protobuf/encoding/protowire"
)

func emptySamples(n int) []byte {
	out := make([]byte, 0, 2*n)
	for i := 0; i < n; i++ {
		out = protowire.AppendTag(out, fieldProfileSample, protowire.BytesType)
		out = protowire.AppendBytes(out, nil)
	}
	return out
}

func TestEmptySampleBombIsRefusedBeforeDecoding(t *testing.T) {
	bomb := gzipped(t, emptySamples(maxCPUProfileSamples+1))
	if len(bomb) > 64*1024 {
		t.Fatalf("bomb is %d bytes compressed, the fixture should be small", len(bomb))
	}
	_, err := parseCPUProfile(bomb)
	if !errors.Is(err, errProfileOverBudget) || !strings.Contains(err.Error(), "samples") {
		t.Fatalf("parseCPUProfile = %v, want the sample cap", err)
	}
}

func TestPackedLocationIDBombIsRefusedByDecodedCost(t *testing.T) {
	ids := make([]byte, maxCPUProfileDecodedBytes/costLocationID+1)
	for i := range ids {
		ids[i] = 1
	}
	var sample []byte
	sample = protowire.AppendTag(sample, fieldSampleLocationID, protowire.BytesType)
	sample = protowire.AppendBytes(sample, ids)
	var plain []byte
	plain = protowire.AppendTag(plain, fieldProfileSample, protowire.BytesType)
	plain = protowire.AppendBytes(plain, sample)

	err := checkProfileDecodeBudget(plain)
	if !errors.Is(err, errProfileOverBudget) || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("checkProfileDecodeBudget = %v, want the decoded-cost cap", err)
	}
}

func TestStringTableBombIsRefusedByDecodedCost(t *testing.T) {
	var plain []byte
	for i := 0; i <= maxCPUProfileDecodedBytes/costString; i++ {
		plain = protowire.AppendTag(plain, fieldProfileString, protowire.BytesType)
		plain = protowire.AppendBytes(plain, nil)
	}
	if err := checkProfileDecodeBudget(plain); !errors.Is(err, errProfileOverBudget) {
		t.Fatalf("checkProfileDecodeBudget = %v, want the decoded-cost cap", err)
	}
}

func everyProfileField() []byte {
	var line []byte
	line = protowire.AppendTag(line, 1, protowire.VarintType)
	line = protowire.AppendVarint(line, 1)

	var location []byte
	location = protowire.AppendTag(location, 1, protowire.VarintType)
	location = protowire.AppendVarint(location, 1)
	location = protowire.AppendTag(location, fieldLocationLine, protowire.BytesType)
	location = protowire.AppendBytes(location, line)

	var label []byte
	label = protowire.AppendTag(label, 1, protowire.VarintType)
	label = protowire.AppendVarint(label, 1)

	var sample []byte
	sample = protowire.AppendTag(sample, fieldSampleLocationID, protowire.BytesType)
	sample = protowire.AppendBytes(sample, []byte{1, 2, 0x81, 0x01})
	sample = protowire.AppendTag(sample, fieldSampleLocationID, protowire.VarintType)
	sample = protowire.AppendVarint(sample, 3)
	sample = protowire.AppendTag(sample, fieldSampleValue, protowire.VarintType)
	sample = protowire.AppendVarint(sample, 7)
	sample = protowire.AppendTag(sample, fieldSampleLabel, protowire.BytesType)
	sample = protowire.AppendBytes(sample, label)
	sample = protowire.AppendTag(sample, 9, protowire.Fixed64Type)
	sample = protowire.AppendFixed64(sample, 0)

	var plain []byte
	plain = protowire.AppendTag(plain, fieldProfileSampleType, protowire.BytesType)
	plain = protowire.AppendBytes(plain, nil)
	plain = protowire.AppendTag(plain, fieldProfileSample, protowire.BytesType)
	plain = protowire.AppendBytes(plain, sample)
	plain = protowire.AppendTag(plain, fieldProfileMapping, protowire.BytesType)
	plain = protowire.AppendBytes(plain, nil)
	plain = protowire.AppendTag(plain, fieldProfileLocation, protowire.BytesType)
	plain = protowire.AppendBytes(plain, location)
	plain = protowire.AppendTag(plain, fieldProfileFunction, protowire.BytesType)
	plain = protowire.AppendBytes(plain, nil)
	plain = protowire.AppendTag(plain, fieldProfileString, protowire.BytesType)
	plain = protowire.AppendBytes(plain, []byte("cpu"))
	plain = protowire.AppendTag(plain, fieldProfileComment, protowire.BytesType)
	plain = protowire.AppendBytes(plain, []byte{1, 2})
	plain = protowire.AppendTag(plain, 9, protowire.VarintType)
	plain = protowire.AppendVarint(plain, 12345)
	return plain
}

func TestEveryProfileFieldIsPricedWithinBudget(t *testing.T) {
	if err := checkProfileDecodeBudget(everyProfileField()); err != nil {
		t.Fatalf("checkProfileDecodeBudget = %v, want a small profile accepted", err)
	}
}

func TestARealCPUProfileFitsTheBudget(t *testing.T) {
	plain, err := inflateProfile(cpuProfileBytes(t), maxDecompressedCPUProfileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkProfileDecodeBudget(plain); err != nil {
		t.Fatalf("checkProfileDecodeBudget = %v on a real profile", err)
	}
	if _, err := profile.ParseData(plain); err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
}

func TestMalformedProfileBytesAreRefusedBeforeTheLegacyParsers(t *testing.T) {
	truncatedLength := protowire.AppendTag(nil, fieldProfileSample, protowire.BytesType)
	truncatedLength = protowire.AppendVarint(truncatedLength, 10)

	truncatedVarint := protowire.AppendTag(nil, 9, protowire.VarintType)
	truncatedVarint = append(truncatedVarint, 0x80)

	badLocation := protowire.AppendTag(nil, fieldProfileLocation, protowire.BytesType)
	badLocation = protowire.AppendBytes(badLocation, []byte{0x80})

	badSample := protowire.AppendTag(nil, fieldProfileSample, protowire.BytesType)
	badSample = protowire.AppendBytes(badSample, []byte{0x80})

	for name, plain := range map[string][]byte{
		"text":             []byte("not a profile"),
		"truncated length": truncatedLength,
		"truncated varint": truncatedVarint,
		"bad location":     badLocation,
		"bad sample":       badSample,
	} {
		if err := checkProfileDecodeBudget(plain); err == nil || !strings.Contains(err.Error(), "not a pprof protobuf") {
			t.Errorf("%s: checkProfileDecodeBudget = %v, want a malformed-profile error", name, err)
		}
	}
}

func TestBudgetErrorsInsideNestedMessagesStopTheScan(t *testing.T) {
	var location []byte
	for i := 0; i <= maxCPUProfileDecodedBytes/costLine; i++ {
		location = protowire.AppendTag(location, fieldLocationLine, protowire.BytesType)
		location = protowire.AppendBytes(location, nil)
	}
	plain := protowire.AppendTag(nil, fieldProfileLocation, protowire.BytesType)
	plain = protowire.AppendBytes(plain, location)
	if err := checkProfileDecodeBudget(plain); !errors.Is(err, errProfileOverBudget) {
		t.Fatalf("location lines: %v, want the decoded-cost cap", err)
	}

	var sample []byte
	for i := 0; i <= maxCPUProfileDecodedBytes/costLabel; i++ {
		sample = protowire.AppendTag(sample, fieldSampleLabel, protowire.BytesType)
		sample = protowire.AppendBytes(sample, nil)
	}
	plain = protowire.AppendTag(nil, fieldProfileSample, protowire.BytesType)
	plain = protowire.AppendBytes(plain, sample)
	if err := checkProfileDecodeBudget(plain); !errors.Is(err, errProfileOverBudget) {
		t.Fatalf("sample labels: %v, want the decoded-cost cap", err)
	}
}

func TestEveryTopLevelElementCountsAgainstTheBudget(t *testing.T) {
	for _, field := range []protowire.Number{fieldProfileSampleType, fieldProfileMapping, fieldProfileFunction, 9} {
		var plain []byte
		for i := 0; i <= maxCPUProfileDecodedBytes/costUnknownField; i++ {
			plain = protowire.AppendTag(plain, field, protowire.BytesType)
			plain = protowire.AppendBytes(plain, nil)
		}
		if err := checkProfileDecodeBudget(plain); !errors.Is(err, errProfileOverBudget) {
			t.Errorf("field %d: %v, want the decoded-cost cap", field, err)
		}
	}
	comments := protowire.AppendTag(nil, fieldProfileComment, protowire.BytesType)
	comments = protowire.AppendBytes(comments, make([]byte, maxCPUProfileDecodedBytes/costPackedElement+1))
	if err := checkProfileDecodeBudget(comments); !errors.Is(err, errProfileOverBudget) {
		t.Errorf("comments: %v, want the decoded-cost cap", err)
	}
}

func TestALargeRealisticProfileFitsTheBudget(t *testing.T) {
	const depth, samples = 64, 50_000
	p := &profile.Profile{
		SampleType: []*profile.ValueType{{Type: "samples", Unit: "count"}, {Type: "cpu", Unit: "nanoseconds"}},
		PeriodType: &profile.ValueType{Type: "cpu", Unit: "nanoseconds"},
		Period:     10_000_000,
	}
	for i := 0; i < 4*depth; i++ {
		fn := &profile.Function{ID: uint64(i + 1), Name: "main.f" + strings.Repeat("x", i%7)}
		p.Function = append(p.Function, fn)
		p.Location = append(p.Location, &profile.Location{ID: uint64(i + 1), Address: uint64(0x1000 + i), Line: []profile.Line{{Function: fn}}})
	}
	for i := 0; i < samples; i++ {
		stack := make([]*profile.Location, depth)
		for d := range stack {
			stack[d] = p.Location[(i+d*3)%len(p.Location)]
		}
		p.Sample = append(p.Sample, &profile.Sample{Location: stack, Value: []int64{1, 10_000_000}})
	}
	top, err := parseCPUProfile(writeProfile(t, p))
	if err != nil || len(top) == 0 {
		t.Fatalf("parseCPUProfile = %d functions, %v; want a large real profile accepted", len(top), err)
	}
}

func nearlySpentBudget() []byte {
	plain := protowire.AppendTag(nil, fieldProfileComment, protowire.BytesType)
	return protowire.AppendBytes(plain, make([]byte, maxCPUProfileDecodedBytes/costPackedElement))
}

func TestTheBudgetIsCheckedWhenASampleOrLocationStarts(t *testing.T) {
	for name, field := range map[string]protowire.Number{"sample": fieldProfileSample, "location": fieldProfileLocation} {
		plain := nearlySpentBudget()
		plain = protowire.AppendTag(plain, field, protowire.BytesType)
		plain = protowire.AppendBytes(plain, nil)
		if err := checkProfileDecodeBudget(plain); !errors.Is(err, errProfileOverBudget) {
			t.Errorf("%s: %v, want the decoded-cost cap", name, err)
		}
	}
}
