package objectstore

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3 credential keys read from the user-supplied Secret. All optional —
// missing keys mean "fall back to the SDK default credential chain"
// (which discovers IRSA, env vars, EC2 instance profile, etc.).
//
// Documented as a public API surface in doc/object-store-reports.md.
const (
	s3SecretKeyAccessKeyID     = "access_key_id"
	s3SecretKeySecretAccessKey = "secret_access_key"
	s3SecretKeySessionToken    = "session_token"
	s3SecretKeyRegion          = "region"
	s3SecretKeyEndpoint = "endpoint"
	s3SecretKeyForcePath = "force_path_style"
)

// s3Sink uploads to AWS S3 or any S3-compatible bucket via the
// low-level s3.Client.PutObject API.
//
// We deliberately do not use feature/s3/manager.Uploader (now
// deprecated) or its successor feature/s3/transfermanager: session
// reports are text artifacts a few hundred KB at most, well below the
// 5 MiB single-part PutObject limit. Multipart adds round-trips and
// complexity (CompleteMultipartUpload, error recovery on partial
// uploads) that buy nothing for our payload size.
type s3Sink struct {
	client    *s3.Client
	dest      destination
	uriPrefix string
}

func newS3Sink(ctx context.Context, cfg Config, d destination) (Sink, error) {
	creds := cfg.Credentials

	loadOpts := []func(*awsconfig.LoadOptions) error{}

	region := stringFromCreds(creds, s3SecretKeyRegion)
	if region == "" {
		if env := os.Getenv("AWS_REGION"); env != "" {
			region = env
		} else {
			region = "us-east-1"
		}
	}
	loadOpts = append(loadOpts, awsconfig.WithRegion(region))

	if id, secret := stringFromCreds(creds, s3SecretKeyAccessKeyID), stringFromCreds(creds, s3SecretKeySecretAccessKey); id != "" && secret != "" {
		token := stringFromCreds(creds, s3SecretKeySessionToken)
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(id, secret, token),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("s3: load AWS config: %w", err)
	}

	clientOpts := []func(*s3.Options){}
	if endpoint := stringFromCreds(creds, s3SecretKeyEndpoint); endpoint != "" {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}
	if strings.EqualFold(stringFromCreds(creds, s3SecretKeyForcePath), "true") {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, clientOpts...)

	return &s3Sink{
		client:    client,
		dest:      d,
		uriPrefix: SchemeS3 + "://" + d.bucket,
	}, nil
}

func (s *s3Sink) Upload(ctx context.Context, keyHint, contentType string, body io.Reader) (string, error) {
	key := s.dest.resolveKey(keyHint)
	if key == "" {
		return "", fmt.Errorf("s3: resolved object key is empty (URI must include a key or prefix)")
	}
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.dest.bucket),
		Key:         aws.String(key),
		Body:        body,
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return "", fmt.Errorf("s3: upload %s/%s: %w", s.dest.bucket, key, err)
	}
	return s.uriPrefix + "/" + key, nil
}

func (s *s3Sink) Close() error {
	return nil
}

// stringFromCreds reads a key from a Secret-style map[string][]byte
// and returns it as a string, trimmed of surrounding whitespace. Empty
// when the key is absent.
func stringFromCreds(creds map[string][]byte, key string) string {
	if creds == nil {
		return ""
	}
	v, ok := creds[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(string(v))
}