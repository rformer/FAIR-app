package installer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rformer/fair-app/pkg/audit"
)

// LogFile is the install log's name, in the directory fairctl runs from
// unless -log names another.
const LogFile = "fair-install.log"

// LogFormat names the install log's lines (docs/formats/fair-install-log-v1.md).
const LogFormat = "fair.install-log.v1"

// Entry is one line of the install log: a step's new state, or an event
// for the trail (step 9 replays them through install.submit_events, which
// keeps their ids and times, so a replay records nothing twice).
type Entry struct {
	Format string       `json:"format"`
	Time   time.Time    `json:"time"`
	Kind   string       `json:"kind"` // step or event
	Step   Step         `json:"step,omitempty"`
	State  State        `json:"state,omitempty"`
	Event  *audit.Event `json:"event,omitempty"`
}

// Entry kinds.
const (
	KindStep  = "step"
	KindEvent = "event"
)

// operatorActor is the only actor install.submit_events accepts.
var operatorActor = regexp.MustCompile(`^operator:\S`)

// installerType is what install.submit_events accepts as an installer event.
var installerType = regexp.MustCompile(`^(?:install|license)\.|^posture\.deployment_exception_`)

// Log is the local install log: JSON lines, appended and synced one by one,
// never holding a secret (every line is checked before it is written).
type Log struct {
	mu   sync.Mutex
	f    *os.File
	now  func() time.Time
	path string
}

// OpenLog opens (creating, mode 0600) the install log at path for appending.
func OpenLog(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- the operator's chosen log path
	if err != nil {
		return nil, fmt.Errorf("installer: install log: %w", err)
	}
	return &Log{f: f, now: time.Now, path: path}, nil
}

// Path is the log's path.
func (l *Log) Path() string { return l.path }

// Close closes the log.
func (l *Log) Close() error { return l.f.Close() }

// Step records a step's new state.
func (l *Log) Step(step Step, state State) error {
	if !validStep(step) || !validState(state) {
		return fmt.Errorf("installer: step %q state %q", step, state)
	}
	return l.write(Entry{Kind: KindStep, Step: step, State: state})
}

// Event records an event for the trail. It must be an installer event in
// the catalog, by an operator (operator:<name>), and hold nothing that looks
// secret; its id and time are fixed here, so that the replay is idempotent.
func (l *Log) Event(e audit.Event) (audit.Event, error) {
	e, err := CheckEvent(e, l.now())
	if err != nil {
		return e, err
	}
	return e, l.write(Entry{Kind: KindEvent, Event: &e})
}

// CheckEvent normalizes an installer event and checks it as
// install.submit_events and the audit catalog would.
func CheckEvent(e audit.Event, now time.Time) (audit.Event, error) {
	e, err := audit.Normalize(e, now)
	if err != nil {
		return e, err
	}
	switch {
	case !installerType.MatchString(e.Type):
		return e, fmt.Errorf("installer: %s is not an installer event", e.Type)
	case !operatorActor.MatchString(e.Actor):
		return e, fmt.Errorf("installer: %s: the actor is operator:<name>", e.Type)
	}
	cat, err := audit.DefaultCatalog()
	if err != nil {
		return e, err
	}
	if err := cat.Validate(e); err != nil {
		return e, err
	}
	return e, nil
}

func (l *Log) write(en Entry) error {
	en.Format = LogFormat
	if en.Time.IsZero() {
		en.Time = l.now().UTC()
	}
	b, err := json.Marshal(en)
	if err != nil {
		return err
	}
	if LooksSecret(string(b)) {
		return errors.New("installer: refused to write a value that looks secret to the install log")
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(b); err != nil {
		return fmt.Errorf("installer: install log: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("installer: install log: %w", err)
	}
	return nil
}

// ReadLog reads an install log. A last line cut short (an interrupted
// write) is ignored; any other malformed line is an error.
func ReadLog(r io.Reader) ([]Entry, error) {
	br := bufio.NewReader(r)
	var out []Entry
	for n := 1; ; n++ {
		line, err := br.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			if len(bytes.TrimSpace(line)) > 0 {
				var en Entry
				if json.Unmarshal(line, &en) == nil && en.Format == LogFormat {
					out = append(out, en) // complete but unterminated
				}
			}
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var en Entry
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&en); err != nil {
			return nil, fmt.Errorf("installer: install log line %d: %w", n, err)
		}
		if en.Format != LogFormat {
			return nil, fmt.Errorf("installer: install log line %d: format %q, not %s", n, en.Format, LogFormat)
		}
		switch {
		case en.Kind == KindStep && validStep(en.Step) && validState(en.State) && en.Event == nil:
		case en.Kind == KindEvent && en.Event != nil && en.Step == "" && en.State == "":
		default:
			return nil, fmt.Errorf("installer: install log line %d: not a step or an event", n)
		}
		out = append(out, en)
	}
}

// ProgressOf returns the step states the entries leave (the last state
// recorded for each step).
func ProgressOf(entries []Entry) Progress {
	p := NewProgress()
	for _, en := range entries {
		if en.Kind == KindStep {
			p[en.Step] = en.State
		}
	}
	return p
}

// EventsOf returns the entries' events in order.
func EventsOf(entries []Entry) []audit.Event {
	var out []audit.Event
	for _, en := range entries {
		if en.Kind == KindEvent {
			out = append(out, *en.Event)
		}
	}
	return out
}

// EventSubmitter submits events to the trail: install.submit_events as
// app_migrator, which accepts at most SubmitBatch events per call.
type EventSubmitter interface {
	SubmitEvents(ctx context.Context, events []audit.Event) (int, error)
}

// SubmitBatch is install.submit_events' limit per call.
const SubmitBatch = 1000

// Replay submits events in batches (step 9). Each event keeps its id and
// time, so replaying after an interruption records nothing twice.
func Replay(ctx context.Context, s EventSubmitter, events []audit.Event) (int, error) {
	total := 0
	for i := 0; i < len(events); i += SubmitBatch {
		batch := events[i:min(i+SubmitBatch, len(events))]
		for _, e := range batch {
			if !installerType.MatchString(e.Type) || !operatorActor.MatchString(e.Actor) || e.ID == "" || e.Time.IsZero() {
				return total, fmt.Errorf("installer: event %q is not a replayable installer event", e.ID)
			}
		}
		n, err := s.SubmitEvents(ctx, batch)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// OperatorActor is the actor for an operator's stated name.
func OperatorActor(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errors.New("installer: the operator's name is 1 to 200 printable characters")
	}
	return "operator:" + name, nil
}
