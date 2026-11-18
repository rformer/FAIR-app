// Package notify is the notification service (F-009): it collects the
// notices the features queue, resolves their recipients, and delivers them
// in the app, by email and to webhooks.
package notify

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
)

// F-009 T-02 (design §3.1, §5): the notice kinds a release knows, synced
// into notify.kind by iam migrate.

// Kind is one kind of notice: where it comes from, and whether a user may
// mute it by email (mandatory kinds cannot be muted; security kinds also
// raise the notification_undelivered finding when undelivered, §3.5).
type Kind struct {
	Kind       string `json:"kind"`        // the notice's kind, e.g. acceptance.expiring
	Source     string `json:"source"`      // the outbox it comes from
	SourceKind string `json:"source_kind"` // the kind as that outbox names it
	Mandatory  bool   `json:"mandatory"`
	Security   bool   `json:"security"`
	Label      string `json:"label"` // for the preferences page
}

// Sources are the outboxes notify.collect reads (§3.1), and notify itself
// (test messages).
var Sources = []string{"estimate", "acceptance", "posture", "iam", "finding", "register", "report", "integration", "notify"}

// Kinds are the release's notice kinds (design §3.1; OQ5).
var Kinds = []Kind{
	{"estimate.assigned", "estimate", "assigned", true, false, "An estimate request is addressed to you"},
	{"estimate.reminder", "estimate", "reminder", true, false, "An estimate request you have not answered is due soon"},
	{"estimate.finished", "estimate", "finished", false, false, "An estimate request you answered has finished"},
	{"estimate.closed", "estimate", "closed", false, false, "An estimate request addressed to you has closed"},
	{"acceptance.expiring", "acceptance", "expiring", true, false, "A risk acceptance you own or requested expires soon"},
	{"acceptance.expired", "acceptance", "expired", true, false, "A risk acceptance you own or requested has expired"},
	{"acceptance.suspended", "acceptance", "suspended", true, false, "A risk acceptance you own or requested is suspended for review"},
	{"acceptance.decision_needed", "acceptance", "decision_needed", true, false, "A risk acceptance waits for your decision"},
	{"acceptance.decided", "acceptance", "decided", false, false, "A risk acceptance you requested was decided"},
	{"setting.exception_expiring", "posture", "setting.exception_expiring", true, true, "A security setting exception expires soon"},
	{"setting.exception_reverted", "posture", "setting.exception_reverted", true, true, "A security setting exception expired and was reverted"},
	{"setting.revert_failed", "posture", "setting.revert_failed", true, true, "A security setting could not be reverted"},
	{"breakglass.login", "iam", "breakglass.login", true, true, "A break-glass account signed in"},
	{"breakglass.emergency_enabled", "iam", "breakglass.emergency_enabled", true, true, "Break-glass was enabled in an emergency"},
	{"finding.opened", "finding", "finding.opened", true, true, "A high or critical security finding opened"},
	{"risk.stale", "register", "risk.stale", false, false, "The exposure of a risk you own is stale"},
	{"risk.action_overdue", "register", "risk.action_overdue", false, false, "A treatment action of a risk you own is overdue"},
	{"report.ready", "report", "report.ready", false, false, "A report you scheduled is ready"},
	{"report.failed", "report", "report.failed", false, false, "A report you scheduled could not be generated"},
	{"report.schedule_suspended", "report", "report.schedule_suspended", true, false, "A report schedule of yours was suspended"},
	// F-011 T-10b: an integration's run left proposals waiting for review.
	{"integration.proposals_waiting", "integration", "integration.proposals_waiting", false, false, "Changes proposed by an integration are waiting for your review"},
	// F-011 T-13: a control a scenario of yours relies on is no longer in place.
	{"control.lapsed", "integration", "control.lapsed", false, false, "A control a scenario of yours relies on is no longer in place"},
	{"notify.test", "notify", "test", false, false, "A test message"},
}

var kindRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// CheckKinds checks the release's kinds: well formed, unique, from known
// sources, one per source and source kind, labelled, and every security
// kind mandatory.
func CheckKinds(ks []Kind) error {
	seen, pairs := map[string]bool{}, map[string]bool{}
	for _, k := range ks {
		switch {
		case !kindRE.MatchString(k.Kind) || len(k.Kind) > 64:
			return fmt.Errorf("notify: kind %q is not a dotted lower-case name", k.Kind)
		case seen[k.Kind]:
			return fmt.Errorf("notify: kind %q twice", k.Kind)
		case !slices.Contains(Sources, k.Source):
			return fmt.Errorf("notify: kind %q: unknown source %q", k.Kind, k.Source)
		case k.SourceKind == "" || pairs[k.Source+"/"+k.SourceKind]:
			return fmt.Errorf("notify: kind %q: source kind %q missing or taken", k.Kind, k.SourceKind)
		case k.Label == "":
			return fmt.Errorf("notify: kind %q has no label", k.Kind)
		case k.Security && !k.Mandatory:
			return fmt.Errorf("notify: security kind %q must be mandatory", k.Kind)
		}
		seen[k.Kind], pairs[k.Source+"/"+k.SourceKind] = true, true
	}
	return nil
}

// KindOf returns the kind named kind.
func KindOf(kind string) (Kind, bool) {
	i := slices.IndexFunc(Kinds, func(k Kind) bool { return k.Kind == kind })
	if i < 0 {
		return Kind{}, false
	}
	return Kinds[i], true
}

// SyncPayload is the release's kinds for notify.sync_kinds.
func SyncPayload() ([]byte, error) {
	if err := CheckKinds(Kinds); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"kinds": Kinds})
}
