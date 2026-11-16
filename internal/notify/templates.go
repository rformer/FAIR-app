package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"mime"
	"net/url"
	"strings"
	texttemplate "text/template"
	"time"
	"unicode"
)

// F-009 T-07 (F-009-AC-05 to AC-07; design §3.3): what a notice says outside
// the app. Every email and webhook body is built from a fixed template over
// the notice's envelope: its kind (and the kind's label), when, the business
// unit, the item's type and a link into the platform, and the item's title
// only when the envelope carries one (notification.detail, never for
// restricted units). Values are escaped by their template; header values
// are Q-encoded and CR or LF is refused; links are built from the
// platform's base URL and the item's path, never from data.

// Envelope is a notice's envelope (notify.notice.envelope).
type Envelope struct {
	ID   string    `json:"id"`
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
	BU   struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"bu"`
	Item struct {
		Type string  `json:"type"`
		ID   *string `json:"id"`
		Link string  `json:"link"`
	} `json:"item"`
	Title string `json:"title,omitempty"`
}

// Message is an email's subject and its two parts.
type Message struct {
	Subject string // Q-encoded, safe as a header value
	Text    string
	HTML    string
}

// Composer renders notices for email and webhooks.
type Composer struct {
	Base   string // the platform's base URL (FAIR_NOTIFY_BASE_URL)
	Banner string // the system-use banner's short form, if any (F-001 iam.banner)
}

// itemNoun names an item type in a sentence.
var itemNoun = map[string]string{
	"acceptance":       "the acceptance",
	"estimate_request": "the estimate request",
	"posture":          "the Security Posture page",
	"breakglass":       "the break-glass account's audit history",
	"finding":          "the Security Posture page",
	"risk":             "the risk",
	"test":             "the platform",
}

// ErrUnsafe is a value that cannot be placed in a message safely.
var ErrUnsafe = errors.New("notify: unsafe value")

// Link is the absolute URL of the item's path in the platform: the path
// must be relative to the platform (starting with one "/", no scheme, host
// or backslash).
func (c Composer) Link(path string) (string, error) {
	base, err := BaseURL(c.Base)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n\t ") {
		return "", fmt.Errorf("%w: link %q is not a path in the platform", ErrUnsafe, path)
	}
	u, err := url.Parse(path)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "", fmt.Errorf("%w: link %q is not a path in the platform", ErrUnsafe, path)
	}
	return base.ResolveReference(u).String(), nil
}

// clean turns control characters into spaces and trims (for text taken
// from data: names and titles).
func clean(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s))
}

// HeaderValue Q-encodes s for a header, refusing CR and LF.
func HeaderValue(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n") {
		return "", fmt.Errorf("%w: a header value with CR or LF", ErrUnsafe)
	}
	return mime.QEncoding.Encode("utf-8", s), nil
}

type view struct {
	Label, BU, When, Noun, Link, Title, Banner string
}

var textTmpl = texttemplate.Must(texttemplate.New("text").Parse(`{{.Label}}
{{if .Title}}
{{.Title}}
{{end}}
Business unit: {{.BU}}
When: {{.When}}

Open {{.Noun}} in the FAIR Risk Platform:
{{.Link}}

Sign in to see the details; what you see depends on your access.
{{if .Banner}}
--
{{.Banner}}
{{end}}`))

var htmlTmpl = htmltemplate.Must(htmltemplate.New("html").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{{.Label}}</title></head>
<body style="font-family: sans-serif; line-height: 1.5">
<h1 style="font-size: 1.2em">{{.Label}}</h1>
{{if .Title}}<p><strong>{{.Title}}</strong></p>
{{end}}<p>Business unit: {{.BU}}<br>When: {{.When}}</p>
<p><a href="{{.Link}}">Open {{.Noun}} in the FAIR Risk Platform</a></p>
<p style="color: #555">Sign in to see the details; what you see depends on your access.</p>
{{if .Banner}}<hr><p style="color: #555; font-size: 0.9em">{{.Banner}}</p>
{{end}}</body></html>
`))

// Email renders env (of the kind labelled label) as an email.
func (c Composer) Email(env Envelope, label string) (Message, error) {
	link, err := c.Link(env.Item.Link)
	if err != nil {
		return Message{}, err
	}
	noun := itemNoun[env.Item.Type]
	if noun == "" {
		noun = "the item"
	}
	v := view{Label: clean(label), BU: clean(env.BU.Name), When: env.At.UTC().Format("2006-01-02 15:04 UTC"), Noun: noun, Link: link,
		Title: clean(env.Title), Banner: clean(c.Banner)}
	subject := "[FAIR] " + v.Label
	if v.Title != "" {
		subject += ": " + v.Title
	}
	if len(subject) > 200 {
		subject = strings.ToValidUTF8(subject[:200], "") + "…"
	}
	var m Message
	if m.Subject, err = HeaderValue(subject); err != nil {
		return Message{}, err
	}
	var tb, hb bytes.Buffer
	if err := textTmpl.Execute(&tb, v); err != nil {
		return Message{}, err
	}
	if err := htmlTmpl.Execute(&hb, v); err != nil {
		return Message{}, err
	}
	m.Text, m.HTML = tb.String(), hb.String()
	return m, nil
}

// WebhookFormat names the webhook body's format (docs/formats/fair-notification-v1.md).
const WebhookFormat = "fair.notification.v1"

// WebhookBody renders env as a webhook body: the envelope with an absolute
// link and the format named, nothing else.
func (c Composer) WebhookBody(env Envelope, deliveryID string) ([]byte, error) {
	link, err := c.Link(env.Item.Link)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"format":   WebhookFormat,
		"delivery": deliveryID,
		"notice":   env.ID,
		"kind":     env.Kind,
		"at":       env.At.UTC().Format(time.RFC3339),
		"bu":       map[string]any{"id": env.BU.ID, "name": clean(env.BU.Name)},
		"item":     map[string]any{"type": env.Item.Type, "id": env.Item.ID, "link": link},
	}
	if t := clean(env.Title); t != "" {
		body["title"] = t
	}
	return json.Marshal(body)
}

// DigestItem is one notice in a daily digest.
type DigestItem struct {
	Envelope Envelope
	Label    string
}

var digestText = texttemplate.Must(texttemplate.New("digest").Parse(`Your daily digest of FAIR Risk Platform notices: {{len .Items}}
{{range .Items}}
- {{.Label}}{{if .Title}}: {{.Title}}{{end}}
  {{.BU}}, {{.When}}
  {{.Link}}
{{end}}
Sign in to see the details; what you see depends on your access.
{{if .Banner}}
--
{{.Banner}}
{{end}}`))

var digestHTML = htmltemplate.Must(htmltemplate.New("digest").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Your daily digest</title></head>
<body style="font-family: sans-serif; line-height: 1.5">
<h1 style="font-size: 1.2em">Your daily digest: {{len .Items}} notices</h1>
<ul>
{{range .Items}}<li><a href="{{.Link}}">{{.Label}}</a>{{if .Title}}: {{.Title}}{{end}}<br><span style="color: #555">{{.BU}}, {{.When}}</span></li>
{{end}}</ul>
<p style="color: #555">Sign in to see the details; what you see depends on your access.</p>
{{if .Banner}}<hr><p style="color: #555; font-size: 0.9em">{{.Banner}}</p>
{{end}}</body></html>
`))

// Digest renders a user's held optional notices as one email (AC-19).
func (c Composer) Digest(items []DigestItem) (Message, error) {
	vs := make([]view, 0, len(items))
	for _, it := range items {
		link, err := c.Link(it.Envelope.Item.Link)
		if err != nil {
			return Message{}, err
		}
		vs = append(vs, view{Label: clean(it.Label), BU: clean(it.Envelope.BU.Name), When: it.Envelope.At.UTC().Format("2006-01-02 15:04 UTC"),
			Link: link, Title: clean(it.Envelope.Title)})
	}
	data := struct {
		Items  []view
		Banner string
	}{vs, clean(c.Banner)}
	var m Message
	var err error
	if m.Subject, err = HeaderValue(fmt.Sprintf("[FAIR] Your daily digest: %d notices", len(items))); err != nil {
		return Message{}, err
	}
	var tb, hb bytes.Buffer
	if err := digestText.Execute(&tb, data); err != nil {
		return Message{}, err
	}
	if err := digestHTML.Execute(&hb, data); err != nil {
		return Message{}, err
	}
	m.Text, m.HTML = tb.String(), hb.String()
	return m, nil
}
