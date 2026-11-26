package changeevidence

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Doer sends HTTP requests: an *http.Client in production, a recorded
// replay (ghreplay) in tests.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// GitHub reads the GitHub REST API (read-only: every request is a GET).
type GitHub struct {
	base  *url.URL
	token string
	http  Doer
}

// maxBody bounds one response (an API page or a release asset).
const maxBody = 32 << 20

// NewGitHub is a client for the API at base (https only), authenticated
// with the token in tokenFile. With doer nil it uses an HTTP client that
// requires TLS 1.2 or later and gives up after a minute per request.
func NewGitHub(base, tokenFile string, doer Doer) (*GitHub, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("changeevidence: API URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return nil, fmt.Errorf("changeevidence: API URL %q must be https://host[/path]", base)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	tok, err := ReadToken(tokenFile)
	if err != nil {
		return nil, err
	}
	if doer == nil {
		doer = &http.Client{
			Timeout: time.Minute,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout: 10 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		}
	}
	return &GitHub{base: u, token: tok, http: doer}, nil
}

// ReadToken reads a GitHub token from a file (never from the
// environment): one line, nothing else.
func ReadToken(file string) (string, error) {
	if file == "" {
		return "", errors.New("changeevidence: a token file is required")
	}
	b, err := os.ReadFile(file) // #nosec G304 -- the operator's token file
	if err != nil {
		return "", fmt.Errorf("changeevidence: token: %w", err)
	}
	t := strings.TrimSpace(string(b))
	if t == "" || strings.ContainsAny(t, " \t\r\n") {
		return "", fmt.Errorf("changeevidence: %s must hold one token", file)
	}
	return t, nil
}

// ErrNotFound is GitHub's 404.
var ErrNotFound = errors.New("changeevidence: not found")

// get reads one JSON document at path (relative to the API base) into out.
func (g *GitHub) get(ctx context.Context, path string, q url.Values, out any) error {
	b, _, err := g.fetch(ctx, g.resolve(path, q), "application/vnd.github+json")
	if err != nil {
		return err
	}
	return decode(b, out)
}

// list reads every page of a list at path. key names the array inside a
// wrapping object ("check_runs", "jobs", ...), or "" for a bare array.
func (g *GitHub) list(ctx context.Context, path string, q url.Values, key string, each func(json.RawMessage) error) error {
	q = cloneValues(q)
	q.Set("per_page", "100")
	next := g.resolve(path, q)
	for pages := 0; next != ""; pages++ {
		if pages == 1000 {
			return fmt.Errorf("changeevidence: %s: more than 1000 pages", path)
		}
		b, h, err := g.fetch(ctx, next, "application/vnd.github+json")
		if err != nil {
			return err
		}
		var items []json.RawMessage
		if key == "" {
			err = decode(b, &items)
		} else {
			var w map[string]json.RawMessage
			if err = decode(b, &w); err == nil {
				if raw, ok := w[key]; ok {
					err = decode(raw, &items)
				}
			}
		}
		if err != nil {
			return fmt.Errorf("changeevidence: %s: %w", path, err)
		}
		for _, it := range items {
			if err := each(it); err != nil {
				return err
			}
		}
		if next, err = g.nextPage(h.Get("Link")); err != nil {
			return err
		}
	}
	return nil
}

// asset downloads a release asset by its API URL.
func (g *GitHub) asset(ctx context.Context, apiURL string) ([]byte, error) {
	if err := g.sameOrigin(apiURL); err != nil {
		return nil, err
	}
	b, _, err := g.fetch(ctx, apiURL, "application/octet-stream")
	return b, err
}

func (g *GitHub) resolve(path string, q url.Values) string {
	u := *g.base
	u.Path = g.base.Path + path
	u.RawQuery = q.Encode()
	return u.String()
}

var linkNext = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

// nextPage is the Link header's next page, which must be on the API's host.
func (g *GitHub) nextPage(link string) (string, error) {
	m := linkNext.FindStringSubmatch(link)
	if m == nil {
		return "", nil
	}
	if err := g.sameOrigin(m[1]); err != nil {
		return "", err
	}
	return m[1], nil
}

func (g *GitHub) sameOrigin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != g.base.Scheme || u.Host != g.base.Host {
		return fmt.Errorf("changeevidence: %q is not on the API's host", raw)
	}
	return nil
}

func (g *GitHub) fetch(ctx context.Context, raw, accept string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "fair-evidence")
	resp, err := g.http.Do(req) // #nosec G107 G704 -- the operator's API host; next pages and assets checked against it
	if err != nil {
		return nil, nil, fmt.Errorf("changeevidence: GET %s: %w", req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, nil, fmt.Errorf("changeevidence: GET %s: %w", req.URL.Path, err)
	}
	if len(b) > maxBody {
		return nil, nil, fmt.Errorf("changeevidence: GET %s: response over %d bytes", req.URL.Path, maxBody)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil, fmt.Errorf("%w: %s", ErrNotFound, req.URL.Path)
	case resp.StatusCode != http.StatusOK:
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &e)
		return nil, nil, fmt.Errorf("changeevidence: GET %s: %s %s", req.URL.Path, resp.Status, e.Message)
	}
	return b, resp.Header, nil
}

func decode(b []byte, out any) error {
	return json.NewDecoder(bytes.NewReader(b)).Decode(out)
}

func cloneValues(q url.Values) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// The parts of GitHub's responses the export reads.

type ghUser struct {
	Login string `json:"login"`
}

type ghPull struct {
	Number         int        `json:"number"`
	Title          string     `json:"title"`
	HTMLURL        string     `json:"html_url"`
	User           *ghUser    `json:"user"`
	MergedAt       *time.Time `json:"merged_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	MergeCommitSHA string     `json:"merge_commit_sha"`
	Head           struct {
		SHA string `json:"sha"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

type ghReview struct {
	ID          int64      `json:"id"`
	User        *ghUser    `json:"user"`
	State       string     `json:"state"`
	CommitID    string     `json:"commit_id"`
	SubmittedAt *time.Time `json:"submitted_at"`
}

type ghCommit struct {
	SHA    string  `json:"sha"`
	Author *ghUser `json:"author"`
}

type ghCheckRun struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	HTMLURL    string `json:"html_url"`
}

type ghRelease struct {
	ID          int64      `json:"id"`
	TagName     string     `json:"tag_name"`
	Draft       bool       `json:"draft"`
	Prerelease  bool       `json:"prerelease"`
	PublishedAt *time.Time `json:"published_at"`
	HTMLURL     string     `json:"html_url"`
	Assets      []ghAsset  `json:"assets"`
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type ghRun struct {
	ID              int64     `json:"id"`
	HeadBranch      string    `json:"head_branch"`
	HeadSHA         string    `json:"head_sha"`
	Event           string    `json:"event"`
	Status          string    `json:"status"`
	Conclusion      string    `json:"conclusion"`
	HTMLURL         string    `json:"html_url"`
	CreatedAt       time.Time `json:"created_at"`
	Actor           *ghUser   `json:"actor"`
	TriggeringActor *ghUser   `json:"triggering_actor"`
}

type ghJob struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	HTMLURL    string `json:"html_url"`
}

type ghEnvironment struct {
	Name string `json:"name"`
}

type ghApproval struct {
	Environments []ghEnvironment `json:"environments"`
	State        string          `json:"state"`
	User         *ghUser         `json:"user"`
	Comment      string          `json:"comment"`
}

func login(u *ghUser) string {
	if u == nil {
		return ""
	}
	return u.Login
}
