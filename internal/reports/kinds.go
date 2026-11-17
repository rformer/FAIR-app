package reports

// Kinds are the built-in report kinds with their readers (design §3.4):
// register, acceptances and treatment (T-10), risk and portfolio (T-11).
// A kind without a reader is not offered and its requests are refused.
func Kinds() map[string]Kind {
	return map[string]Kind{}
}
