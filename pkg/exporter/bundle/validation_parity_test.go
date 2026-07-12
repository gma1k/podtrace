package bundle

import "testing"

func TestValidationParity(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		data    map[string]string
		wantErr bool
	}{
		{
			name:    "valid otlp",
			yaml:    "type: otlp\nendpoint: e\n",
			data:    map[string]string{"type": "otlp", "endpoint": "e"},
			wantErr: false,
		},
		{
			name:    "missing type",
			yaml:    "endpoint: e\n",
			data:    map[string]string{"endpoint": "e"},
			wantErr: true,
		},
		{
			name:    "threshold over max",
			yaml:    "type: otlp\nthresholds:\n  errorRatePercent: 200\n",
			data:    map[string]string{"type": "otlp", "threshold_error_rate_percent": "200"},
			wantErr: true,
		},
		{
			name:    "negative threshold",
			yaml:    "type: otlp\nthresholds:\n  rttSpikeMs: -5\n",
			data:    map[string]string{"type": "otlp", "threshold_rtt_spike_ms": "-5"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, yErr := FromYAML([]byte(tc.yaml))
			_, cErr := FromConfigMapData(tc.data)

			if (yErr != nil) != tc.wantErr {
				t.Errorf("FromYAML error = %v, wantErr %v", yErr, tc.wantErr)
			}
			if (cErr != nil) != tc.wantErr {
				t.Errorf("FromConfigMapData error = %v, wantErr %v", cErr, tc.wantErr)
			}
			if (yErr != nil) != (cErr != nil) {
				t.Errorf("validation drift: FromYAML err=%v but FromConfigMapData err=%v", yErr, cErr)
			}
		})
	}
}
