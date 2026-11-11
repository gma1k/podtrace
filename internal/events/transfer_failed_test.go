package events

import "testing"

func TestTransferFailedIgnoresRetriesAndKernelRestarts(t *testing.T) {
	for _, tc := range []struct {
		code int32
		want bool
	}{
		{0, false},
		{512, false},
		{-errnoEAGAIN, false},
		{-errnoERESTARTSYS, false},
		{-errnoERESTARTNOINTR, false},
		{-errnoERESTARTNOHAND, false},
		{-515, false},
		{-errnoERESTARTRESTARTBLOCK, false},
		{-104, true},
		{-32, true},
		{-errnoEINTR, true},
		{-errnoETIMEDOUT, true},
		{-517, true},
	} {
		e := &Event{Type: EventTCPRecv, Error: tc.code}
		if got := e.TransferFailed(); got != tc.want {
			t.Errorf("TransferFailed(%d) = %v, want %v", tc.code, got, tc.want)
		}
	}
}
