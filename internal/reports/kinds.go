package reports

// Kinds are the built-in report kinds with their readers (design §3.4):
// register, acceptances and treatment (T-10), risk and portfolio (T-11).
func Kinds() map[string]Kind {
	out := map[string]Kind{}
	for _, k := range []Kind{RegisterKind, AcceptancesKind, TreatmentKind, RiskKind, PortfolioKind} {
		out[k.Name] = k
	}
	return out
}
