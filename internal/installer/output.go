package installer

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Exit codes (design §3.4).
const (
	ExitOK          = 0 // done
	ExitRefused     = 1 // refused: verification or a check failed
	ExitUsage       = 2 // usage, unreadable or invalid input, or a command not in this build
	ExitInterrupted = 3 // interrupted; resumable
	ExitUnreachable = 4 // the environment (cluster, database, store) is unreachable
)

// ExitCodes describes the exit codes, for usage.
func ExitCodes() []string {
	return []string{
		fmt.Sprintf("%d done", ExitOK),
		fmt.Sprintf("%d refused (verification or a check failed)", ExitRefused),
		fmt.Sprintf("%d usage or invalid input", ExitUsage),
		fmt.Sprintf("%d interrupted (resumable)", ExitInterrupted),
		fmt.Sprintf("%d environment unreachable", ExitUnreachable),
	}
}

// Output is what every fairctl command prints through (AC-54): plain lines,
// one fact per line; colour only when asked for (-color) and never with
// NO_COLOR set (the caller resolves both into Color); no cursor movement,
// spinners or progress bars; with JSON, one document on stdout and nothing
// else there. Text from outside (file names, server messages) is made
// printable first, so no escape sequence reaches the terminal.
type Output struct {
	Stdout, Stderr io.Writer
	JSON           bool
	Color          bool
}

// Printable replaces control characters (escape sequences, carriage
// returns, backspaces) with visible \xNN escapes.
func Printable(s string) string {
	if !strings.ContainsFunc(s, isControl) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if isControl(r) {
			fmt.Fprintf(&b, `\x%02x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isControl(r rune) bool { return (r < 0x20 && r != '\t') || r == 0x7f || (r >= 0x80 && r < 0xa0) }

// Fact prints "key: value" (text only).
func (o *Output) Fact(key, value string) {
	if o.JSON {
		return
	}
	_, _ = fmt.Fprintf(o.Stdout, "%s: %s\n", Printable(key), Printable(value))
}

// Line prints one line (text only).
func (o *Output) Line(format string, a ...any) {
	if o.JSON {
		return
	}
	_, _ = fmt.Fprintln(o.Stdout, Printable(fmt.Sprintf(format, a...)))
}

// Result prints a check's outcome on one line: "ok: ..." or "FAIL: ...",
// green or red only with Color (text only).
func (o *Output) Result(ok bool, format string, a ...any) {
	if o.JSON {
		return
	}
	word, color := "FAIL", "31"
	if ok {
		word, color = "ok", "32"
	}
	if o.Color {
		word = "\x1b[" + color + "m" + word + "\x1b[0m"
	}
	_, _ = fmt.Fprintf(o.Stdout, "%s: %s\n", word, Printable(fmt.Sprintf(format, a...)))
}

// Document prints v as the command's one JSON document.
func (o *Output) Document(v any) error {
	enc := json.NewEncoder(o.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ErrorDocument is a command's JSON document when it fails before its own
// result exists (docs/formats/fairctl-error.schema.json).
type ErrorDocument struct {
	Command  string    `json:"command"`
	OK       bool      `json:"ok"`
	ExitCode int       `json:"exit_code"`
	Error    ErrorBody `json:"error"`
}

// ErrorBody names the error.
type ErrorBody struct {
	Code     string    `json:"code"` // usage, not_available, invalid_decisions, refused, interrupted, unreachable
	Message  string    `json:"message"`
	Problems []Problem `json:"problems,omitempty"`
}

// Error codes.
const (
	CodeUsage            = "usage"
	CodeNotAvailable     = "not_available"
	CodeInvalidDecisions = "invalid_decisions"
	CodeRefused          = "refused"
	CodeInterrupted      = "interrupted"
	CodeUnreachable      = "unreachable"
)

// Fail reports a command's failure, in text on stderr ("fairctl CMD:
// message", then each problem on its own line) or as its JSON document,
// and returns the exit code.
func (o *Output) Fail(command string, exit int, code, message string, problems ...Problem) int {
	if o.JSON {
		_ = o.Document(ErrorDocument{Command: command, ExitCode: exit, Error: ErrorBody{Code: code, Message: Printable(message), Problems: problems}})
		return exit
	}
	_, _ = fmt.Fprintf(o.Stderr, "fairctl %s: %s\n", command, Printable(message))
	for _, p := range problems {
		_, _ = fmt.Fprintf(o.Stderr, "  %s\n", Printable(p.String()))
	}
	return exit
}

// ErrNoAnswer means the input ended before an accepted answer.
var ErrNoAnswer = errors.New("installer: no answer (input ended)")

// Prompt asks a question on stderr, ending with the accepted answers
// ("Proceed? [yes/no]: "), and reads lines from in until one is accepted.
// An empty line takes def when def is one of the answers.
func (o *Output) Prompt(in *bufio.Reader, question string, answers []string, def string) (string, error) {
	shown := make([]string, len(answers))
	for i, a := range answers {
		shown[i] = a
		if a == def {
			shown[i] = strings.ToUpper(a[:1]) + a[1:] // the default, as "[Yes/no]"
		}
	}
	for {
		_, _ = fmt.Fprintf(o.Stderr, "%s [%s]: ", Printable(question), strings.Join(shown, "/"))
		line, err := in.ReadString('\n')
		a := strings.TrimSpace(line)
		if a == "" && def != "" && slices.Contains(answers, def) && (err == nil || line != "") {
			return def, nil
		}
		if slices.Contains(answers, a) {
			return a, nil
		}
		if err != nil {
			_, _ = fmt.Fprintln(o.Stderr)
			return "", ErrNoAnswer
		}
		_, _ = fmt.Fprintf(o.Stderr, "answer one of: %s\n", strings.Join(answers, ", "))
	}
}
