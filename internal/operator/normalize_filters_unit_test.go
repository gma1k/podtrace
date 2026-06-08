package operator

import (
	"reflect"
	"testing"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestNormalizeFilters_Branches(t *testing.T) {
	tests := []struct {
		name string
		in   []podtracev1alpha1.EventFilter
		want []string
	}{
		{
			name: "empty input returns nil",
			in:   nil,
			want: nil,
		},
		{
			name: "trims, drops empties, dedups and sorts",
			in: []podtracev1alpha1.EventFilter{
				"  net ",
				"dns",
				"",
				"  ",
				"net",
				"cpu",
			},
			want: []string{"cpu", "dns", "net"},
		},
		{
			name: "all empty returns empty slice",
			in:   []podtracev1alpha1.EventFilter{"", "   "},
			want: []string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeFilters(tc.in)
			if tc.want == nil {
				if got != nil {
					t.Errorf("normalizeFilters() = %v, want nil", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("normalizeFilters() = %v, want %v", got, tc.want)
			}
		})
	}
}
