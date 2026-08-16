package v1alpha1

import "testing"

func TestValidateEndpointScheme_BlocksMetadataAndLinkLocal(t *testing.T) {
	cases := []struct {
		endpoint string
		wantErr  bool
	}{
		{"http://169.254.169.254:4318", true},
		{"169.254.169.254:4318", true},
		{"https://169.254.169.254", true},
		{"http://[fe80::1]:4318", true},
		{"http://0.0.0.0:4318", true},
		{"ftp://collector", true},
		{"https://collector.example.com", false},
		{"http://localhost:4318", false},
		{"http://10.1.2.3:4318", false},
		{"collector:4318", false},
		{"", false},
	}
	for _, c := range cases {
		err := validateEndpointScheme("spec.datadog.endpoint", c.endpoint)
		if (err != nil) != c.wantErr {
			t.Errorf("validateEndpointScheme(%q) err=%v, wantErr=%v", c.endpoint, err, c.wantErr)
		}
	}
}
