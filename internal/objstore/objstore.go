// Package objstore is the platform's S3-compatible object storage client
// (F-002 T-08, design §6.3, §6.7, D4; ADR-012): write-once objects under
// Object Lock in compliance mode, legal holds, versioned reads and deletes,
// and listings. It wraps minio-go so the library can be replaced.
//
// Every object is addressed by key and version: deletes name the version
// they remove, so a delete never just hides an object behind a marker.
// Connections use TLS 1.2 or later; credentials are read from files.
package objstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Config locates a bucket and the credentials for it.
type Config struct {
	Endpoint      string // host:port, no scheme
	Bucket        string
	Region        string // default us-east-1
	AccessKeyFile string
	SecretKeyFile string
	CAFile        string // optional: the store's CA (else the system roots)
	// Plaintext allows HTTP without TLS: development only (Env).
	Plaintext bool
	Env       string // FAIR_ENV
}

// FromEnv reads a Config from <prefix>_ENDPOINT, _BUCKET, _REGION,
// _ACCESS_KEY_FILE, _SECRET_KEY_FILE, _CA_FILE and _PLAINTEXT ("true").
func FromEnv(prefix, env string, getenv func(string) string) Config {
	return Config{
		Endpoint: getenv(prefix + "_ENDPOINT"), Bucket: getenv(prefix + "_BUCKET"), Region: getenv(prefix + "_REGION"),
		AccessKeyFile: getenv(prefix + "_ACCESS_KEY_FILE"), SecretKeyFile: getenv(prefix + "_SECRET_KEY_FILE"),
		CAFile: getenv(prefix + "_CA_FILE"), Plaintext: getenv(prefix+"_PLAINTEXT") == "true", Env: env,
	}
}

// Store is one bucket.
type Store struct {
	c      *minio.Client
	bucket string
}

// ErrConfig is returned for an unusable configuration.
var ErrConfig = errors.New("objstore: configuration")

// New checks cfg and returns its Store. It does not contact the store; use
// CheckBucket for that.
func New(cfg Config) (*Store, error) {
	var errs []error
	if cfg.Endpoint == "" || strings.Contains(cfg.Endpoint, "://") {
		errs = append(errs, fmt.Errorf("%w: the endpoint is host:port without a scheme, got %q", ErrConfig, cfg.Endpoint))
	} else if _, _, err := net.SplitHostPort(cfg.Endpoint); err != nil {
		errs = append(errs, fmt.Errorf("%w: endpoint %q: %w", ErrConfig, cfg.Endpoint, err))
	}
	if cfg.Bucket == "" {
		errs = append(errs, fmt.Errorf("%w: a bucket is required", ErrConfig))
	}
	if cfg.Plaintext && cfg.Env != "development" {
		errs = append(errs, fmt.Errorf("%w: plaintext object storage is for development only; use TLS", ErrConfig))
	}
	access, err := readCredential(cfg.AccessKeyFile, "access key")
	if err != nil {
		errs = append(errs, err)
	}
	secret, err := readCredential(cfg.SecretKeyFile, "secret key")
	if err != nil {
		errs = append(errs, err)
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) // #nosec G304 -- operator-supplied CA file
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: CA file: %w", ErrConfig, err))
		} else {
			tlsConf.RootCAs = x509.NewCertPool()
			if !tlsConf.RootCAs.AppendCertsFromPEM(pem) {
				errs = append(errs, fmt.Errorf("%w: the CA file holds no certificate", ErrConfig))
			}
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConf
	c, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds: credentials.NewStaticV4(access, secret, ""), Secure: !cfg.Plaintext, Region: region, Transport: tr,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	return &Store{c: c, bucket: cfg.Bucket}, nil
}

func readCredential(file, what string) (string, error) {
	if file == "" {
		return "", fmt.Errorf("%w: the %s file is required", ErrConfig, what)
	}
	b, err := os.ReadFile(file) // #nosec G304 -- operator-supplied credential file
	if err != nil {
		return "", fmt.Errorf("%w: %s file: %w", ErrConfig, what, err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%w: the %s file is empty", ErrConfig, what)
	}
	return v, nil
}

// ErrNotWORM is returned by CheckBucket for a bucket that cannot hold
// write-once objects.
var ErrNotWORM = errors.New("objstore: the bucket does not have versioning and Object Lock enabled")

// CheckBucket confirms the bucket exists with versioning and Object Lock
// enabled, so a store that cannot keep records write-once is refused at
// startup rather than discovered later.
func (s *Store) CheckBucket(ctx context.Context) error {
	ok, err := s.c.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("objstore: bucket %s: %w", s.bucket, err)
	}
	if !ok {
		return fmt.Errorf("objstore: bucket %s does not exist", s.bucket)
	}
	v, err := s.c.GetBucketVersioning(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("%w (%s: versioning: %w)", ErrNotWORM, s.bucket, err)
	}
	if !v.Enabled() {
		return fmt.Errorf("%w (%s: versioning is off)", ErrNotWORM, s.bucket)
	}
	mode, _, _, _, err := s.c.GetObjectLockConfig(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("%w (%s: object lock: %w)", ErrNotWORM, s.bucket, err)
	}
	if mode != "Enabled" {
		return fmt.Errorf("%w (%s: object lock %q)", ErrNotWORM, s.bucket, mode)
	}
	return nil
}

// Version names one version of an object.
type Version struct {
	Key, VersionID string
}

// Put writes data under key, locked in compliance mode until retainUntil
// (zero: not locked), and returns the new version. S3 requires a body
// checksum on Object Lock writes; Content-MD5 is the one every
// S3-compatible store accepts. It checks transport only (ADR-012): the
// trail's integrity is SHA-256, and callers read archives back with Digest.
func (s *Store) Put(ctx context.Context, key string, data []byte, retainUntil time.Time) (Version, error) {
	opts := minio.PutObjectOptions{ContentType: "application/octet-stream", SendContentMd5: true}
	if !retainUntil.IsZero() {
		opts.Mode = minio.Compliance
		opts.RetainUntilDate = retainUntil.UTC()
	}
	info, err := s.c.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		return Version{}, fmt.Errorf("objstore: put %s: %w", key, err)
	}
	if info.VersionID == "" {
		return Version{}, fmt.Errorf("%w (put %s returned no version)", ErrNotWORM, key)
	}
	return Version{Key: key, VersionID: info.VersionID}, nil
}

// MaxGet bounds Get; read larger objects with Open.
const MaxGet = 256 << 20

// Get reads one version (at most MaxGet bytes).
func (s *Store) Get(ctx context.Context, v Version) ([]byte, error) { return s.get(ctx, v, MaxGet) }

func (s *Store) get(ctx context.Context, v Version, limit int) ([]byte, error) {
	r, err := s.Open(ctx, v)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("objstore: get %s: %w", v.Key, err)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("objstore: %s is larger than %d bytes; use Open", v.Key, limit)
	}
	return b, nil
}

// Open streams one version.
func (s *Store) Open(ctx context.Context, v Version) (io.ReadCloser, error) {
	if v.VersionID == "" {
		return nil, fmt.Errorf("objstore: open %s: a version is required", v.Key)
	}
	o, err := s.c.GetObject(ctx, s.bucket, v.Key, minio.GetObjectOptions{VersionID: v.VersionID})
	if err != nil {
		return nil, fmt.Errorf("objstore: open %s: %w", v.Key, err)
	}
	if _, err := o.Stat(); err != nil {
		_ = o.Close()
		return nil, fmt.Errorf("objstore: open %s: %w", v.Key, err)
	}
	return o, nil
}

// Digest is the SHA-256 of one version's content, read back from the store
// (design §6.7: an archive is checked after it is written).
func (s *Store) Digest(ctx context.Context, v Version) ([32]byte, error) {
	r, err := s.Open(ctx, v)
	if err != nil {
		return [32]byte{}, err
	}
	defer func() { _ = r.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return [32]byte{}, fmt.Errorf("objstore: digest %s: %w", v.Key, err)
	}
	var d [32]byte
	h.Sum(d[:0])
	return d, nil
}

// Delete removes one version. The store refuses while it is under
// retention or a legal hold.
func (s *Store) Delete(ctx context.Context, v Version) error {
	if v.VersionID == "" {
		return fmt.Errorf("objstore: delete %s: a version is required", v.Key)
	}
	if err := s.c.RemoveObject(ctx, s.bucket, v.Key, minio.RemoveObjectOptions{VersionID: v.VersionID}); err != nil {
		return fmt.Errorf("objstore: delete %s: %w", v.Key, err)
	}
	return nil
}

// SetLegalHold places (on) or releases a legal hold on one version
// (AC-29).
func (s *Store) SetLegalHold(ctx context.Context, v Version, on bool) error {
	st := minio.LegalHoldDisabled
	if on {
		st = minio.LegalHoldEnabled
	}
	if err := s.c.PutObjectLegalHold(ctx, s.bucket, v.Key, minio.PutObjectLegalHoldOptions{VersionID: v.VersionID, Status: &st}); err != nil {
		return fmt.Errorf("objstore: legal hold %s: %w", v.Key, err)
	}
	return nil
}

// LegalHold reports whether one version is under a legal hold.
func (s *Store) LegalHold(ctx context.Context, v Version) (bool, error) {
	st, err := s.c.GetObjectLegalHold(ctx, s.bucket, v.Key, minio.GetObjectLegalHoldOptions{VersionID: v.VersionID})
	if err != nil {
		return false, fmt.Errorf("objstore: legal hold %s: %w", v.Key, err)
	}
	return st != nil && *st == minio.LegalHoldEnabled, nil
}

// RetainedUntil is the compliance retention of one version (zero: none).
func (s *Store) RetainedUntil(ctx context.Context, v Version) (time.Time, error) {
	mode, until, err := s.c.GetObjectRetention(ctx, s.bucket, v.Key, v.VersionID)
	if err != nil {
		var resp minio.ErrorResponse
		if errors.As(err, &resp) && resp.Code == "NoSuchObjectLockConfiguration" {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("objstore: retention %s: %w", v.Key, err)
	}
	if mode == nil || until == nil {
		return time.Time{}, nil
	}
	if *mode != minio.Compliance {
		return time.Time{}, fmt.Errorf("objstore: %s is retained in %s mode, not compliance", v.Key, *mode)
	}
	return until.UTC(), nil
}

// Object is one listed version.
type Object struct {
	Version
	Size         int64
	LastModified time.Time
	Latest       bool
}

// List returns every version of every object under prefix.
func (s *Store) List(ctx context.Context, prefix string) ([]Object, error) {
	var out []Object
	for o := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true, WithVersions: true}) {
		if o.Err != nil {
			return nil, fmt.Errorf("objstore: list %s: %w", prefix, o.Err)
		}
		if o.IsDeleteMarker {
			continue
		}
		out = append(out, Object{Version: Version{Key: o.Key, VersionID: o.VersionID}, Size: o.Size, LastModified: o.LastModified, Latest: o.IsLatest})
	}
	return out, nil
}
