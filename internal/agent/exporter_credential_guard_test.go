package agent

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

func TestBuildExporter_SplunkDataDogRequireCredential(t *testing.T) {
	cases := []struct {
		typ  bundle.Type
		want string
	}{
		{bundle.TypeSplunk, "missing token"},
		{bundle.TypeDataDog, "missing api key"},
	}
	for _, tc := range cases {
		t.Run(string(tc.typ), func(t *testing.T) {
			p := &BundlePayload{
				Type:       tc.typ,
				Endpoint:   "collector.observability:4318",
				Insecure:   true,
				HeaderName: "X-Auth",
			}
			_, err := BuildExporter(p, CRKey{"ns", "cr"})
			if err == nil {
				t.Fatalf("%s with an empty credential must fail the build, not ship unauthenticated", tc.typ)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s empty-credential error = %v, want it to contain %q", tc.typ, err, tc.want)
			}
			if got := ClassifyExporterError(err); got != ExporterErrAuthMissing {
				t.Fatalf("classifier = %q, want %q", got, ExporterErrAuthMissing)
			}
		})
	}
}
