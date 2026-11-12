package objectstore

import "testing"

func TestIsPrefixURI(t *testing.T) {
	cases := map[string]bool{
		"s3://bucket/reports/":           true,
		"s3://bucket":                    true,
		"gs://bucket/":                   true,
		"azblob://acct/container/":       true,
		"s3://bucket/reports/fixed.txt":  false,
		"azblob://acct/container/report": false,
		"":                               false,
		"ftp://bucket/reports/":          false,
		"configmap/ns/name":              false,
	}
	for uri, want := range cases {
		if got := IsPrefixURI(uri); got != want {
			t.Errorf("IsPrefixURI(%q) = %v, want %v", uri, got, want)
		}
	}
}

func TestPerNodeURI(t *testing.T) {
	cases := []struct {
		uri, node, want string
	}{
		{"s3://bucket/reports/fixed.txt", "node-a", "s3://bucket/reports/fixed-node-a.txt"},
		{"gs://bucket/fixed.report.txt", "node-a", "gs://bucket/fixed.report-node-a.txt"},
		{"azblob://acct/container/dir/report", "node-a", "azblob://acct/container/dir/report-node-a"},
		{"s3://bucket/reports/.report", "node-a", "s3://bucket/reports/.report-node-a"},
		{"s3://bucket/reports/", "node-a", "s3://bucket/reports/"},
		{"s3://bucket/reports/fixed.txt", "", "s3://bucket/reports/fixed.txt"},
		{"configmap/ns/name", "node-a", "configmap/ns/name"},
		{"ftp://bucket/fixed.txt", "node-a", "ftp://bucket/fixed.txt"},
	}
	for _, tc := range cases {
		if got := PerNodeURI(tc.uri, tc.node); got != tc.want {
			t.Errorf("PerNodeURI(%q, %q) = %q, want %q", tc.uri, tc.node, got, tc.want)
		}
	}
}

func TestPerNodeURIResolvesToDistinctKeys(t *testing.T) {
	a, err := parseURI(PerNodeURI("s3://bucket/reports/fixed.txt", "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseURI(PerNodeURI("s3://bucket/reports/fixed.txt", "node-b"))
	if err != nil {
		t.Fatal(err)
	}
	if a.prefix || b.prefix {
		t.Fatal("per-node URI of an exact key must stay an exact key")
	}
	if a.resolveKey("ignored") == b.resolveKey("ignored") {
		t.Fatalf("two nodes resolve to the same key %q", a.resolveKey("ignored"))
	}
}
