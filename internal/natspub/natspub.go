// Package natspub publishes platform events to NATS JetStream (ADR-003).
//
// Publish waits for the stream's acknowledgement, so a returned nil means the
// event is stored. Streams are provisioned by the installer (F-014); Connect
// fails fast if no stream captures a required subject rather than creating
// one, so services need no stream-management rights.
package natspub

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Publisher publishes acknowledged messages to JetStream subjects.
type Publisher struct {
	nc *nats.Conn
	js jetstream.JetStream
}

// Options configures Connect.
type Options struct {
	Env       string   // "production" requires tls:// URLs
	URL       string   // e.g. tls://nats.fair-platform:4222
	CredsFile string   // optional NATS credentials file (mounted secret)
	Name      string   // client name shown in NATS monitoring
	Subjects  []string // subjects that must be captured by a stream
}

// Connect dials NATS with TLS 1.2 or later and checks that every required
// subject has a stream.
func Connect(ctx context.Context, o Options) (*Publisher, error) {
	if o.URL == "" {
		return nil, errors.New("natspub: NATS URL is required")
	}
	if o.Env == "production" {
		for _, u := range strings.Split(o.URL, ",") {
			if !strings.HasPrefix(strings.TrimSpace(u), "tls://") {
				return nil, fmt.Errorf("natspub: %q: tls:// is required when FAIR_ENV=production", u)
			}
		}
	}
	opts := []nats.Option{nats.Name(o.Name), nats.Timeout(10 * time.Second), nats.MaxReconnects(-1)}
	if strings.Contains(o.URL, "tls://") { // always the case in production
		opts = append(opts, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS12}))
	}
	if o.CredsFile != "" {
		opts = append(opts, nats.UserCredentials(o.CredsFile))
	}
	nc, err := nats.Connect(o.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("natspub: connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("natspub: %w", err)
	}
	for _, s := range o.Subjects {
		if _, err := js.StreamNameBySubject(ctx, s); err != nil {
			nc.Close()
			return nil, fmt.Errorf("natspub: no JetStream stream captures %q (provisioned by the installer): %w", s, err)
		}
	}
	return &Publisher{nc: nc, js: js}, nil
}

// Publish stores data on subject and waits for the stream acknowledgement.
// msgID enables JetStream de-duplication of redelivered events.
func (p *Publisher) Publish(ctx context.Context, subject, msgID string, data []byte) error {
	_, err := p.js.Publish(ctx, subject, data, jetstream.WithMsgID(msgID))
	return err
}

// Close drains and closes the connection.
func (p *Publisher) Close() {
	_ = p.nc.Drain()
}
