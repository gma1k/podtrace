package cri

import "testing"

func TestFindJSONHelpers(t *testing.T) {
	obj := map[string]any{
		"pid": float64(123),
		"runtimeSpec": map[string]any{
			"linux": map[string]any{
				"cgroupsPath": "/kubepods.slice/test.scope",
			},
		},
	}

	if pid, ok := findJSONInt(obj, []string{"pid"}); !ok || pid != 123 {
		t.Fatalf("expected pid=123, got pid=%d ok=%v", pid, ok)
	}

	if cg, ok := findJSONString(obj, []string{"runtimeSpec.linux.cgroupsPath"}); !ok || cg != "/kubepods.slice/test.scope" {
		t.Fatalf("expected cgroupsPath, got %q ok=%v", cg, ok)
	}

	if _, ok := findJSONString(obj, []string{"missing.path"}); ok {
		t.Fatalf("expected missing path to return ok=false")
	}
}

func TestFindJSONInt_Types(t *testing.T) {
	obj := map[string]any{
		"asFloat": float64(42),
		"asInt64": int64(99),
		"asInt":   int(7),
		"asStr":   "not-a-number",
	}

	if v, ok := findJSONInt(obj, []string{"asFloat"}); !ok || v != 42 {
		t.Errorf("float64: got %d ok=%v", v, ok)
	}
	if v, ok := findJSONInt(obj, []string{"asInt64"}); !ok || v != 99 {
		t.Errorf("int64: got %d ok=%v", v, ok)
	}
	if v, ok := findJSONInt(obj, []string{"asInt"}); !ok || v != 7 {
		t.Errorf("int: got %d ok=%v", v, ok)
	}
	if _, ok := findJSONInt(obj, []string{"asStr"}); ok {
		t.Error("expected ok=false for string value")
	}
	if _, ok := findJSONInt(obj, []string{"missing"}); ok {
		t.Error("expected ok=false for missing key")
	}
}

func TestTryParseJSON_DirectObject(t *testing.T) {
	// Plain JSON object.
	obj := tryParseJSON(`{"pid":123,"cgroupsPath":"/kubepods"}`)
	if obj == nil {
		t.Fatal("expected non-nil for valid JSON")
	}
	m, ok := obj.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", obj)
	}
	if m["pid"] != float64(123) {
		t.Errorf("pid mismatch: %v", m["pid"])
	}
}

func TestTryParseJSON_DoubleEncoded(t *testing.T) {
	// A JSON-encoded string that itself contains a JSON object.
	inner := `{"pid":7,"cgroupsPath":"/sys/fs/cgroup/test"}`
	// Double-encode: the outer value is a JSON string wrapping the inner JSON.
	encoded := `"{\"pid\":7,\"cgroupsPath\":\"/sys/fs/cgroup/test\"}"`
	obj := tryParseJSON(encoded)
	if obj == nil {
		t.Fatal("expected non-nil for double-encoded JSON")
	}
	m, ok := obj.(map[string]any)
	if !ok {
		t.Fatalf("expected map from inner JSON, got %T (inner=%s)", obj, inner)
	}
	if m["pid"] != float64(7) {
		t.Errorf("pid mismatch: %v", m["pid"])
	}
}

func TestTryParseJSON_Invalid(t *testing.T) {
	if obj := tryParseJSON("not json at all"); obj != nil {
		t.Errorf("expected nil for invalid JSON, got %v", obj)
	}
}

func TestTryParseJSON_PlainString(t *testing.T) {
	// A JSON-encoded plain string (not an object inside).
	obj := tryParseJSON(`"just a string"`)
	// The inner value is a plain string — tryParseJSON tries to re-parse it
	// as JSON, fails, and returns the original string object.
	if obj == nil {
		t.Fatal("expected non-nil")
	}
	if _, ok := obj.(string); !ok {
		t.Errorf("expected string type, got %T", obj)
	}
}

func TestFindJSONValue_EmptyPath(t *testing.T) {
	obj := map[string]any{"key": "value"}
	v, ok := findJSONValue(obj, []string{})
	if !ok {
		t.Error("expected ok=true for empty path")
	}
	if v == nil {
		t.Error("expected non-nil for empty path")
	}
}

func TestFindJSONValue_NonMapIntermediate(t *testing.T) {
	obj := map[string]any{"key": "not-a-map"}
	_, ok := findJSONValue(obj, []string{"key", "nested"})
	if ok {
		t.Error("expected ok=false when intermediate is not a map")
	}
}

func TestFindJSONString_EmptyValue(t *testing.T) {
	obj := map[string]any{"empty": ""}
	if _, ok := findJSONString(obj, []string{"empty"}); ok {
		t.Error("expected ok=false for empty string value")
	}
}



