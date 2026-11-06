package model

import "fmt"

// Node statuses in the taxonomy view (AC-28; design §3.1).
const (
	NodeEntered = "entered"  // estimated on the scenario
	NodeDerived = "derived"  // computed from the nodes below it
	NodeLibrary = "library"  // taken from a pinned library entry
	NodeNotUsed = "not_used" // below the level the scenario is estimated at
)

// Node is one factor of the FAIR taxonomy as a scenario estimates it.
type Node struct {
	Factor  string `json:"factor"`            // e.g. "loss_event_frequency", "primary_loss.response"
	Parent  string `json:"parent,omitempty"`  // the factor it feeds
	Status  string `json:"status"`            // entered, derived, library or not_used
	Pointer string `json:"pointer,omitempty"` // where the estimate is, for entered nodes
}

// Taxonomy is the tree of a valid scenario, top down: which factors were
// entered, which will be derived, and which are not used (AC-28).
func Taxonomy(s *Scenario) []Node {
	var out []Node
	add := func(factor, parent, status, ptr string) {
		out = append(out, Node{Factor: factor, Parent: parent, Status: status, Pointer: ptr})
	}
	pick := func(entered bool, ptr string) (string, string) {
		if entered {
			return NodeEntered, ptr
		}
		return NodeNotUsed, ""
	}
	add("risk", "", NodeDerived, "")

	// Loss event frequency.
	l := s.LEF
	if l.Level == "lef" {
		add("loss_event_frequency", "risk", NodeEntered, "/lef/estimate")
	} else {
		add("loss_event_frequency", "risk", NodeDerived, "")
	}
	tefStatus, tefPtr, cf, poa := NodeNotUsed, "", false, false
	vulnStatus, vulnPtr, tcap, tcapPtr, rs := NodeNotUsed, "", NodeNotUsed, "", false
	if l.TEF != nil {
		switch l.TEF.Level {
		case "tef":
			tefStatus, tefPtr = NodeEntered, "/lef/tef/estimate"
		case "cf_poa":
			tefStatus, cf, poa = NodeDerived, true, true
		}
	}
	if l.Vulnerability != nil {
		switch l.Vulnerability.Level {
		case "direct":
			vulnStatus, vulnPtr = NodeEntered, "/lef/vulnerability/estimate"
		case "derived":
			vulnStatus, rs = NodeDerived, true
			if tc := l.Vulnerability.ThreatCapability; tc != nil && tc.Source == "scenario" {
				tcap, tcapPtr = NodeEntered, "/lef/vulnerability/threat_capability/estimate"
			} else {
				tcap = NodeLibrary
			}
		}
	}
	add("threat_event_frequency", "loss_event_frequency", tefStatus, tefPtr)
	st, p := pick(cf, "/lef/tef/contact_frequency")
	add("contact_frequency", "threat_event_frequency", st, p)
	st, p = pick(poa, "/lef/tef/probability_of_action")
	add("probability_of_action", "threat_event_frequency", st, p)
	add("vulnerability", "loss_event_frequency", vulnStatus, vulnPtr)
	add("threat_capability", "vulnerability", tcap, tcapPtr)
	st, p = pick(rs, "/lef/vulnerability/resistance_strength")
	add("resistance_strength", "vulnerability", st, p)

	// Loss magnitude: primary loss per form, secondary risk per stakeholder.
	add("loss_magnitude", "risk", NodeDerived, "")
	add("primary_loss", "loss_magnitude", NodeDerived, "")
	for _, f := range FormsOfLoss {
		_, ok := s.PrimaryLoss[f]
		st, p := pick(ok, "/primary_loss/"+f)
		add("primary_loss."+f, "primary_loss", st, p)
	}
	if len(s.SecondaryRisk) == 0 {
		add("secondary_risk", "loss_magnitude", NodeNotUsed, "")
		return out
	}
	add("secondary_risk", "loss_magnitude", NodeDerived, "")
	for i, g := range s.SecondaryRisk {
		base := fmt.Sprintf("secondary_risk.%d", i)
		add(base, "secondary_risk", NodeDerived, "")
		add(base+".slef", base, NodeEntered, fmt.Sprintf("/secondary_risk/%d/slef", i))
		for _, f := range FormsOfLoss {
			_, ok := g.Loss[f]
			st, p := pick(ok, fmt.Sprintf("/secondary_risk/%d/loss/%s", i, f))
			add(base+".loss."+f, base, st, p)
		}
	}
	return out
}
