package operator

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// TestBestTerminationMessage_PrefersInformativeOverKubeletShutdown is
// the regression test for a real bug found during manual e2e: when a
// native sidecar's parent pod terminates while the sidecar is still
// running, the kubelet overwrites the sidecar's /dev/termination-log
// with a generic "container could not be located when the pod was
// terminated" message.
func TestBestTerminationMessage_PrefersInformativeOverKubeletShutdown(t *testing.T) {
	cases := []struct {
		name     string
		current  string
		previous string
		want     string
	}{
		{
			name:     "current_informative_preferred",
			current:  "s3://b/k/r.txt",
			previous: "stale earlier message",
			want:     "s3://b/k/r.txt",
		},
		{
			name:     "kubelet_shutdown_falls_back",
			current:  "The container could not be located when the pod was terminated",
			previous: "Error: 403 InvalidAccessKeyId",
			want:     "Error: 403 InvalidAccessKeyId",
		},
		{
			name:     "empty_current_falls_back",
			current:  "",
			previous: "Error: bucket not found",
			want:     "Error: bucket not found",
		},
		{
			name:     "both_empty",
			current:  "",
			previous: "",
			want:     "",
		},
		{
			name:     "kubelet_shutdown_with_no_previous",
			current:  "The container could not be located when the pod was terminated",
			previous: "",
			want:     "The container could not be located when the pod was terminated",
		},
		{
			name:     "node_was_lost_falls_back",
			current:  "The node was lost",
			previous: "Error: connection refused",
			want:     "Error: connection refused",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := corev1.ContainerStatus{
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{Message: tc.current},
				},
				LastTerminationState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{Message: tc.previous},
				},
			}
			if got := bestTerminationMessage(cs); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBestTerminationMessage_NilStatesAreSafe documents the
// nil-tolerance contract of the helper: a ContainerStatus where the
// kubelet has not populated either terminated state must not panic.
func TestBestTerminationMessage_NilStatesAreSafe(t *testing.T) {
	if got := bestTerminationMessage(corev1.ContainerStatus{}); got != "" {
		t.Errorf("empty ContainerStatus: got %q, want empty", got)
	}
}

func TestClassifyUploadFailure(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want podtracev1alpha1.ReportFailureReason
	}{
		{name: "s3_no_such_bucket", msg: "operation error S3: PutObject, https response error StatusCode: 404, NoSuchBucket: The specified bucket does not exist", want: podtracev1alpha1.ReportFailureReasonBucketNotFound},
		{name: "gcs_bucket_doesnt_exist", msg: "googleapi: Error 404: storage: bucket doesn't exist", want: podtracev1alpha1.ReportFailureReasonBucketNotFound},
		{name: "azure_container_not_found", msg: "RESPONSE 404 ContainerNotFound", want: podtracev1alpha1.ReportFailureReasonBucketNotFound},

		{name: "s3_access_denied", msg: "operation error S3: PutObject, https response error StatusCode: 403, AccessDenied: Access Denied", want: podtracev1alpha1.ReportFailureReasonAccessDenied},
		{name: "s3_signature", msg: "SignatureDoesNotMatch: The request signature we calculated does not match the signature you provided", want: podtracev1alpha1.ReportFailureReasonAccessDenied},
		{name: "azure_authorization_failed", msg: "RESPONSE 403 AuthorizationFailed", want: podtracev1alpha1.ReportFailureReasonAccessDenied},

		{name: "aws_no_credentials", msg: "failed to retrieve credentials, no credentials found", want: podtracev1alpha1.ReportFailureReasonCredentialMissing},
		{name: "gcs_default_credentials", msg: "google: could not find default credentials", want: podtracev1alpha1.ReportFailureReasonCredentialMissing},

		{name: "ctx_deadline", msg: "context deadline exceeded", want: podtracev1alpha1.ReportFailureReasonNetworkTimeout},
		{name: "tls_handshake", msg: "net/http: TLS handshake timeout", want: podtracev1alpha1.ReportFailureReasonNetworkTimeout},
		{name: "dns_no_such_host", msg: "dial tcp: lookup s3.bogus.example: no such host", want: podtracev1alpha1.ReportFailureReasonNetworkTimeout},
		{name: "connection_refused", msg: "dial tcp 127.0.0.1:9000: connect: connection refused", want: podtracev1alpha1.ReportFailureReasonNetworkTimeout},

		{name: "unsupported_scheme", msg: `unsupported URI scheme "ftp" (want s3, gs, or azblob)`, want: podtracev1alpha1.ReportFailureReasonInvalidURI},
		{name: "no_host", msg: `URI "s3://" must include scheme and host`, want: podtracev1alpha1.ReportFailureReasonInvalidURI},
		{name: "empty_key", msg: "s3: resolved object key is empty (URI must include a key or prefix)", want: podtracev1alpha1.ReportFailureReasonInvalidURI},

		{name: "empty", msg: "", want: podtracev1alpha1.ReportFailureReasonUnknown},
		{name: "novel_sdk_wording", msg: "ECONNRESET: kernel said no", want: podtracev1alpha1.ReportFailureReasonUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyUploadFailure(tc.msg)
			if got != tc.want {
				t.Errorf("classifyUploadFailure(%q) = %q, want %q", tc.msg, got, tc.want)
			}
		})
	}
}

func TestApplyReportUploadStatus_AttemptsAndReason(t *testing.T) {
	session := func(prev podtracev1alpha1.ReportFailureReason) *podtracev1alpha1.PodTraceSession {
		s := &podtracev1alpha1.PodTraceSession{
			Spec: podtracev1alpha1.PodTraceSessionSpec{
				ReportRef: &podtracev1alpha1.ReportReference{
					ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "s3://b/k"},
				},
			},
		}
		s.Status.ReportFailureReason = prev
		return s
	}

	t.Run("pending clears prior reason", func(t *testing.T) {
		s := session(podtracev1alpha1.ReportFailureReasonNetworkTimeout)
		applyReportUploadStatus(s, reportUploadObservation{Attempts: 2})
		if s.Status.ReportFailureReason != "" {
			t.Errorf("pending must clear reason, got %q", s.Status.ReportFailureReason)
		}
		if s.Status.ReportAttempts != 2 {
			t.Errorf("attempts = %d, want 2", s.Status.ReportAttempts)
		}
	})

	t.Run("success clears reason and stamps location", func(t *testing.T) {
		s := session(podtracev1alpha1.ReportFailureReasonAccessDenied)
		applyReportUploadStatus(s, reportUploadObservation{
			ResolvedURI: "s3://b/k/r.txt",
			Terminated:  true,
			Succeeded:   true,
			Attempts:    1,
		})
		if s.Status.ReportFailureReason != "" {
			t.Errorf("success must clear reason, got %q", s.Status.ReportFailureReason)
		}
		if s.Status.ReportLocation != "s3://b/k/r.txt" {
			t.Errorf("location not stamped, got %q", s.Status.ReportLocation)
		}
	})

	t.Run("failure sets reason from classifier", func(t *testing.T) {
		s := session("")
		applyReportUploadStatus(s, reportUploadObservation{
			ResolvedURI: "operation error S3: PutObject, 403 AccessDenied",
			Terminated:  true,
			Succeeded:   false,
			Attempts:    4,
		})
		if s.Status.ReportFailureReason != podtracev1alpha1.ReportFailureReasonAccessDenied {
			t.Errorf("reason = %q, want AccessDenied", s.Status.ReportFailureReason)
		}
		if s.Status.ReportAttempts != 4 {
			t.Errorf("attempts = %d, want 4", s.Status.ReportAttempts)
		}
	})

	t.Run("non-objectstore session is no-op", func(t *testing.T) {
		s := &podtracev1alpha1.PodTraceSession{} // no ReportRef.ObjectStore
		applyReportUploadStatus(s, reportUploadObservation{Terminated: true, Succeeded: false, Attempts: 7})
		if s.Status.ReportAttempts != 0 {
			t.Errorf("non-objectstore session must not touch status, attempts=%d", s.Status.ReportAttempts)
		}
	})
}
