package tests

import (
	"context"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-13 property "floor never violated", against the real registry
// (moved from the retired T-00b Registry with T-18): across random changes
// in each built-in profile, through settings.Setter, with approvals granted
// at random, no value in force is ever weaker than a hard floor that applies
// to the profile's family. The floor condition is computed here from the
// F-001 definitions, not by the code under test.
func TestFloorNeverViolatedRealRegistry(t *testing.T) {
	families := map[string]settings.Family{
		settings.ProfileFedRAMPModerate: settings.FamilyFedRAMP, settings.ProfileCMMCL2R2: settings.FamilyCMMC,
		settings.ProfileEnterpriseBaseline: settings.FamilyEnterprise,
	}
	defs := settings.F001Defs()
	value := func(r *rand.Rand, d settings.Def) any {
		switch d.Kind {
		case settings.KindDuration:
			units := []time.Duration{time.Minute, time.Hour, 24 * time.Hour}
			return time.Duration(1+r.IntN(200)) * units[r.IntN(len(units))]
		case settings.KindInt:
			return r.IntN(12)
		case settings.KindBool:
			return r.IntN(2) == 1
		default:
			return d.Order[r.IntN(len(d.Order))]
		}
	}
	for profile, family := range families {
		t.Run(profile, func(t *testing.T) {
			reg := registryFixture(t, profile, "self-hosted")
			ctx := context.Background()
			admin, admin2 := reg.e.principal("admin"), reg.e.principal("admin2")
			appr := approvals.Service{DB: reg.e.appPool()}
			r := rand.New(rand.NewPCG(20261027, uint64(len(profile)))) // #nosec G404 -- seeded, reproducible test data
			check := func(step int) {
				t.Helper()
				snap, err := settings.DBSource{DB: reg.e.appPool()}.Snapshot(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, d := range defs {
					if d.Floor == nil || (len(d.FloorFamilies) > 0 && !slices.Contains(d.FloorFamilies, family)) {
						continue
					}
					v, err := settings.DecodeValue(d, snap.Instance[d.Key])
					if err != nil {
						t.Fatalf("step %d: %s: %v", step, d.Key, err)
					}
					if c, _ := d.Compare(v, d.Floor); c < 0 {
						t.Fatalf("step %d: %s = %v is below its hard floor %v in %s", step, d.Key, v, d.Floor, profile)
					}
				}
			}
			check(0)
			applied, pending, refused := 0, 0, 0
			for step := 1; step <= 60; step++ {
				d := defs[r.IntN(len(defs))]
				res, err := reg.set.Set(ctx, admin, settings.Request{Key: d.Key, Value: value(r, d), Explanation: "property test"})
				switch {
				case err != nil:
					refused++
				case res.Outcome == settings.PendingApproval:
					pending++
					if r.IntN(2) == 0 {
						if _, err := appr.Decide(ctx, admin2, res.ApprovalID, true, ""); err != nil {
							t.Fatal(err)
						}
						_, _ = reg.set.ApplyApproved(ctx, res.ChangeID) // may be refused if the floor moved
					}
				default:
					applied++
				}
				check(step)
			}
			if applied == 0 || pending == 0 || refused == 0 {
				t.Fatalf("the random walk did not exercise every path (applied %d, pending %d, refused %d)", applied, pending, refused)
			}
			if got := mustAs(reg.e, "app_posture", "SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
				t.Fatalf("%s MAC mismatches", got)
			}
		})
	}
}
