package objectstore

import (
	"context"
	"fmt"
	"io"
	"os"

	"cloud.google.com/go/auth/credentials"
	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

const (
	gcsSecretKeyServiceAccountJSON = "service_account_json"
	gcsSecretKeyEndpoint           = "endpoint"
)

// gcsScopes lists the OAuth2 scopes the storage client needs. Hardcoding
// them keeps the credentials-construction path explicit.
var gcsScopes = []string{
	"https://www.googleapis.com/auth/devstorage.read_write",
	"https://www.googleapis.com/auth/cloud-platform",
}

type gcsSink struct {
	client    *storage.Client
	dest      destination
	uriPrefix string
}

func newGCSSink(ctx context.Context, cfg Config, d destination) (Sink, error) {
	creds := cfg.Credentials

	var opts []option.ClientOption
	saJSON := stringFromCreds(creds, gcsSecretKeyServiceAccountJSON)
	if saJSON != "" {
		ac, err := credentials.DetectDefault(&credentials.DetectOptions{
			CredentialsJSON: []byte(saJSON),
			Scopes:          gcsScopes,
		})
		if err != nil {
			return nil, fmt.Errorf("gcs: load service account JSON: %w", err)
		}
		opts = append(opts, option.WithAuthCredentials(ac))
	}
	if endpoint := stringFromCreds(creds, gcsSecretKeyEndpoint); endpoint != "" {
		opts = append(opts, option.WithEndpoint(endpoint))
		if saJSON == "" {
			opts = append(opts, option.WithoutAuthentication())
		}
	}

	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcs: new client: %w", err)
	}

	client.SetRetry(storage.WithErrorFunc(loggingGCSShouldRetry))

	return &gcsSink{
		client:    client,
		dest:      d,
		uriPrefix: SchemeGCS + "://" + d.bucket,
	}, nil
}

// loggingGCSShouldRetry mirrors storage.ShouldRetry's decision while
// emitting one structured log line per evaluation.
func loggingGCSShouldRetry(err error) bool {
	if err == nil {
		return false
	}
	shouldRetry := storage.ShouldRetry(err)
	_, _ = fmt.Fprintf(os.Stderr,
		`{"component":"objectstore.retry","backend":"gs","retry":%v,"error":%q}`+"\n",
		shouldRetry, err.Error(),
	)
	return shouldRetry
}

func (g *gcsSink) Upload(ctx context.Context, keyHint, contentType string, body io.Reader) (string, error) {
	key := g.dest.resolveKey(keyHint)
	if key == "" {
		return "", fmt.Errorf("gcs: resolved object key is empty (URI must include a key or prefix)")
	}
	w := g.client.Bucket(g.dest.bucket).Object(key).NewWriter(ctx)
	w.ContentType = contentType
	if _, err := io.Copy(w, body); err != nil {
		_ = w.Close()
		return "", fmt.Errorf("gcs: stream to %s/%s: %w", g.dest.bucket, key, err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("gcs: finalise %s/%s: %w", g.dest.bucket, key, err)
	}
	return g.uriPrefix + "/" + key, nil
}

func (g *gcsSink) Close() error {
	return g.client.Close()
}