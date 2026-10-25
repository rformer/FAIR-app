package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Emitter records security events. Implementations must:
//   - reject invalid events with an error wrapping ErrInvalidEvent;
//   - be safe for concurrent use;
//   - return ErrClosed from Emit after Close; Close is idempotent;
//   - return an error when an event could not be delivered, never drop it silently.
//
// The contract is checked by audittest.RunContract for every implementation.
type Emitter interface {
	Emit(ctx context.Context, e Event) error
	Close(ctx context.Context) error
}

// Multi fans an event out to every sink. Delivery is attempted on all sinks
// even if one fails; the returned error joins every failure so the caller can
// fail the audited operation (audit failure must not be silent, AU-5).
type Multi struct {
	sinks []namedSink
	mu    sync.RWMutex
	done  bool
}

type namedSink struct {
	name string
	e    Emitter
}

// NewMulti builds a fan-out emitter. Names appear in error messages.
func NewMulti() *Multi { return &Multi{} }

// Add registers a sink.
func (m *Multi) Add(name string, e Emitter) *Multi {
	m.sinks = append(m.sinks, namedSink{name, e})
	return m
}

// Len returns the number of registered sinks.
func (m *Multi) Len() int { return len(m.sinks) }

// Emit implements Emitter.
func (m *Multi) Emit(ctx context.Context, e Event) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.done {
		return ErrClosed
	}
	if err := e.Validate(); err != nil {
		return err
	}
	var errs []error
	for _, s := range m.sinks {
		if err := s.e.Emit(ctx, e); err != nil {
			errs = append(errs, fmt.Errorf("sink %s: %w", s.name, err))
		}
	}
	return errors.Join(errs...)
}

// Close implements Emitter.
func (m *Multi) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done {
		return nil
	}
	m.done = true
	var errs []error
	for _, s := range m.sinks {
		if err := s.e.Close(ctx); err != nil {
			errs = append(errs, fmt.Errorf("sink %s: %w", s.name, err))
		}
	}
	return errors.Join(errs...)
}

// Memory keeps events in memory. It is used in tests and as the default sink
// when nothing else is configured in a dev environment.
type Memory struct {
	mu     sync.Mutex
	events []Event
	closed bool
}

// NewMemory returns an empty in-memory emitter.
func NewMemory() *Memory { return &Memory{} }

// Emit implements Emitter.
func (m *Memory) Emit(_ context.Context, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.events = append(m.events, e)
	return nil
}

// Close implements Emitter.
func (m *Memory) Close(context.Context) error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}

// Events returns a copy of recorded events.
func (m *Memory) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.events...)
}

// OfType returns recorded events of the given type.
func (m *Memory) OfType(t string) []Event {
	var out []Event
	for _, e := range m.Events() {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}
