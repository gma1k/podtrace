package objectstore_test

import (
	"testing"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/internal/reportsink/objectstore"
)

func TestAPIValidatorAndParserAgree(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		ok   bool
	}{
		{"S3 prefix", "s3://b/path/", true},
		{"S3 key", "s3://b/k.txt", true},
		{"GCS prefix", "gs://b/p/", true},
		{"Azure with container", "azblob://acct/container/", true},
		{"unknown scheme", "ftp://b/k", false},
		{"missing host", "s3:///k", false},
		{"azure missing container", "azblob://acct/", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			apiErr := podtracev1alpha1.ValidateObjectStoreReference(
				&podtracev1alpha1.ObjectStoreReference{URI: tc.uri},
			)
			parserErr := objectstore.ValidateURI(tc.uri)

			if tc.ok {
				if apiErr != nil {
					t.Errorf("api ValidateObjectStoreReference(%q) error: %v", tc.uri, apiErr)
				}
				if parserErr != nil {
					t.Errorf("objectstore ValidateURI(%q) error: %v", tc.uri, parserErr)
				}
				return
			}
			if apiErr == nil {
				t.Errorf("api ValidateObjectStoreReference(%q) should fail, got nil", tc.uri)
			}
			if parserErr == nil {
				t.Errorf("objectstore ValidateURI(%q) should fail, got nil", tc.uri)
			}
		})
	}
}