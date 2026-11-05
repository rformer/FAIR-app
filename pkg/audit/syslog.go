package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// FormatRFC5424 renders an event as an RFC 5424 message (facility: security/auth = 10).
func FormatRFC5424(e Event, hostname, appName string) (string, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	const facility = 10
	pri := facility*8 + syslogSeverity(e.Severity)
	return fmt.Sprintf("<%d>1 %s %s %s - %s - %s",
		pri,
		e.Time.UTC().Format(time.RFC3339Nano),
		nilvalue(hostname),
		nilvalue(appName),
		nilvalue(sanitizeMsgID(e.Type)),
		body,
	), nil
}

func syslogSeverity(s Severity) int {
	switch s {
	case SeverityCritical:
		return 2 // critical
	case SeverityHigh:
		return 4 // warning
	case SeverityLow:
		return 5 // notice
	default:
		return 6 // informational
	}
}

func nilvalue(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// MSGID is limited to 32 printable US-ASCII characters without spaces.
func sanitizeMsgID(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 33 || r > 126 {
			return -1
		}
		return r
	}, s)
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}
