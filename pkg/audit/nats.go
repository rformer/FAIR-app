package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Publisher is the minimal surface the NATS sink needs. It is satisfied by
// JetStreamPublisher (acknowledged, durable) and by test fakes.
type Publisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// NATSSink publishes each event to "<prefix>.<event type>" (default prefix
// "audit"), matching the audit.* subjects in the F-001 design.
type NATSSink struct {
	pub    Publisher
	prefix string
	closer func() error
	ping   func() error
	mu     sync.RWMutex
	closed bool
}

// NewNATSSink wraps a Publisher. closer (optional) runs on Close.
func NewNATSSink(pub Publisher, prefix string, closer func() error) *NATSSink {
	if prefix == "" {
		prefix = "audit"
	}
	return &NATSSink{pub: pub, prefix: prefix, closer: closer}
}

// Subject returns the subject an event is published on.
func (s *NATSSink) Subject(e Event) string { return s.prefix + "." + e.Type }

// Emit implements Emitter.
func (s *NATSSink) Emit(ctx context.Context, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit nats: marshal: %w", err)
	}
	if err := s.pub.Publish(ctx, s.Subject(e), b); err != nil {
		return fmt.Errorf("audit nats: publish: %w", err)
	}
	return nil
}

// Ping reports whether the underlying connection is usable (readiness).
func (s *NATSSink) Ping(context.Context) error {
	if s.ping == nil {
		return nil
	}
	return s.ping()
}

// Close implements Emitter.
func (s *NATSSink) Close(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.closer != nil {
		return s.closer()
	}
	return nil
}

// JetStreamPublisher publishes with JetStream acknowledgements, so an event
// is only reported delivered once the stream has persisted it. The message ID
// is the event ID, which lets JetStream de-duplicate retries.
type JetStreamPublisher struct {
	js jetstream.JetStream
}

// Publish implements Publisher.
func (p *JetStreamPublisher) Publish(ctx context.Context, subject string, data []byte) error {
	var e struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(data, &e)
	_, err := p.js.Publish(ctx, subject, data, jetstream.WithMsgID(e.ID))
	return err
}

// StreamName returns the JetStream stream name for a subject prefix
// ("audit" -> "AUDIT").
func StreamName(prefix string) string {
	return strings.ToUpper(strings.NewReplacer(".", "_", "*", "_", ">", "_").Replace(prefix))
}

// DialNATS connects to NATS, ensures the audit stream exists for subjects
// "<prefix>.>", and returns a ready sink. opts are passed to nats.Connect
// (credentials, TLS config, etc.).
func DialNATS(ctx context.Context, url, prefix string, opts ...nats.Option) (*NATSSink, error) {
	if prefix == "" {
		prefix = "audit"
	}
	nc, err := nats.Connect(url, append([]nats.Option{nats.Name("fair-audit-emitter")}, opts...)...)
	if err != nil {
		return nil, fmt.Errorf("audit nats: connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("audit nats: jetstream: %w", err)
	}
	// The stream is normally provisioned by the installer with the
	// customer's retention settings; create a default one only if missing,
	// and never overwrite an existing configuration.
	name := StreamName(prefix)
	if _, err := js.Stream(ctx, name); errors.Is(err, jetstream.ErrStreamNotFound) {
		_, err = js.CreateStream(ctx, jetstream.StreamConfig{
			Name:      name,
			Subjects:  []string{prefix + ".>"},
			Storage:   jetstream.FileStorage,
			Retention: jetstream.LimitsPolicy,
		})
		if err != nil && !errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
			nc.Close()
			return nil, fmt.Errorf("audit nats: create stream: %w", err)
		}
	} else if err != nil {
		nc.Close()
		return nil, fmt.Errorf("audit nats: stream: %w", err)
	}
	sink := NewNATSSink(&JetStreamPublisher{js: js}, prefix, func() error {
		return nc.Drain()
	})
	sink.ping = func() error {
		if st := nc.Status(); st != nats.CONNECTED {
			return fmt.Errorf("audit nats: connection %s", st)
		}
		return nil
	}
	return sink, nil
}
