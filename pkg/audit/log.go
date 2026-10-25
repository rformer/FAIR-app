package audit

import (
	"context"
	"encoding/json"
	"io"
	"sync"
)

// WriterSink writes one JSON event per line to w (normally stdout, which the
// cluster's log pipeline collects). It is the zero-dependency default sink.
type WriterSink struct {
	mu     sync.Mutex
	w      io.Writer
	closed bool
}

// NewWriterSink returns a sink writing JSON lines to w.
func NewWriterSink(w io.Writer) *WriterSink { return &WriterSink{w: w} }

// Emit implements Emitter.
func (s *WriterSink) Emit(_ context.Context, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(struct {
		Log string `json:"log"`
		Event
	}{"audit", e})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	_, err = s.w.Write(append(b, '\n'))
	return err
}

// Close implements Emitter.
func (s *WriterSink) Close(context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}
