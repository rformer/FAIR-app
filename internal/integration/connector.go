package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// F-011 T-16 (F-011-AC-01, AC-04; design §3.1, §3.3): a connector
// integration's settings as the integrations API accepts them; the
// database re-checks the same rules (integration.check_connector). The
// source host is checked against integration.allowed_hosts and resolved by
// the API's egress.Guard on every save. The connectors themselves (fetching,
// paging, mapping) are the runner's (T-17).

// Connector types (design §3.3, OQ2).
const (
	ConnectorHTTPJSON       = "http_json"
	ConnectorServiceNowCMDB = "servicenow_cmdb"
)

// ConnectorTypes are the v1 connectors.
var ConnectorTypes = []string{ConnectorHTTPJSON, ConnectorServiceNowCMDB}

// Connector is a connector integration's settings.
type Connector struct {
	Type            string          `json:"type"`
	Source          string          `json:"source"`
	ScheduleMinutes int             `json:"schedule_minutes"`
	Settings        json.RawMessage `json:"settings,omitempty"` // the connector's own (field mapping, paging, CMDB class)
}

// ParseConnector reads a connector's settings strictly and checks them.
func ParseConnector(raw []byte) (Connector, error) {
	var c Connector
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Connector{}, errors.New("integration: the connector is an object of type, source, schedule_minutes and settings")
	}
	if dec.More() {
		return Connector{}, errors.New("integration: the connector is one object")
	}
	return c, c.Check()
}

// Check refuses settings the database would refuse, with the reason.
func (c Connector) Check() error {
	if !slices.Contains(ConnectorTypes, c.Type) {
		return fmt.Errorf("integration: the connector type is %s", strings.Join(ConnectorTypes, " or "))
	}
	if _, err := c.SourceURL(); err != nil {
		return err
	}
	if c.ScheduleMinutes < 15 || c.ScheduleMinutes > 1440 {
		return errors.New("integration: the schedule is 15 to 1,440 minutes")
	}
	if len(c.Settings) > 0 {
		var m map[string]json.RawMessage
		if json.Unmarshal(c.Settings, &m) != nil || m == nil {
			return errors.New("integration: the connector's settings are an object")
		}
	}
	return nil
}

// SourceURL is the source as a URL: https, a host, no user and no
// fragment, at most 2,048 characters (the database's rule).
func (c Connector) SourceURL() (*url.URL, error) {
	bad := errors.New("integration: the source is an https URL of at most 2,048 characters, with no user or fragment in it")
	if len(c.Source) > 2048 || strings.ContainsAny(c.Source, " \t\r\n") {
		return nil, bad
	}
	u, err := url.Parse(c.Source)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" ||
		strings.Contains(c.Source, "@") || strings.Contains(c.Source, "#") {
		return nil, bad
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, errors.New("integration: the source's port is 1 to 65535")
		}
	}
	return u, nil
}

// Host is the source's host name, lower case (for the allow-list).
func (c Connector) Host() string {
	u, err := c.SourceURL()
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// TestRequest is what a connector test fetches with: the integration's
// kind and mapping, its connector, and its source credential (nil when none
// is set). A test fetches the first page and submits nothing (design §6.1).
type TestRequest struct {
	IntegrationID string
	BUID          string
	Kind          string
	Mapping       json.RawMessage
	Connector     Connector
	Source        *Credential
}

// TestResult is a test's answer: the records the first page held and the
// first problems mapping them (at most 20).
type TestResult struct {
	Records  int       `json:"records"`
	Problems []Refusal `json:"problems"`
}

// MaxTestProblems is how many mapping problems a test answers.
const MaxTestProblems = 20
