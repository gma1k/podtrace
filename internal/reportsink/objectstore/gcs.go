package objectstore

import (
	"context"
	"fmt"
	"io"

	"cloud.google.com/go/auth/credentials"
	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

const (
	gcsSecretKeyServiceAccountJSON = "service_account_json"
	gcsSecretKeyEndpoint           = "endpoint"
)

// gcsScopes lists the OAuth2 scopes the storage client needs. Hardcoding
// them keeps the credentials-construction path explicit; the older
// option.WithCredentialsJSON helper looked up scopes implicitly but is
// deprecated as of the auth-library v0.20 because it surfaces JSON
// material through chains where it can be logged or cached unintendedly.
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
		// Use the modern cloud.google.com/go/auth/credentials path
		// instead of the deprecated option.WithCredentialsJSON: the
		// new helper validates the payload, derives an explicit token
		// source, and avoids the security-review concerns documented
		// in the v0.20 deprecation notice.
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
		// Test endpoints (fake-gcs-server) speak plaintext HTTP with
		// no auth handshake. Skip auth when the user provided no
		// explicit service account.
		if saJSON == "" {
			opts = append(opts, option.WithoutAuthentication())
		}
	}

	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcs: new client: %w", err)
	}

	return &gcsSink{
		client:    client,
		dest:      d,
		uriPrefix: SchemeGCS + "://" + d.bucket,
	}, nil
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