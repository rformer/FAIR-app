package infraplan

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DryRun runs the drift job's decision over recorded plans without AWS
// (design §6: "drift job dry run in CI"): every directory under dir is one
// recorded run (the layout ReadDrift reads) with a file expect naming the
// verdict it must reach (clean, drift, error) and, for drift and error,
// lines of expect.issue the issue body must contain. It writes each case's
// verdict and issue body to w and fails on the first mismatch.
func DryRun(dir string, w io.Writer) error {
	cases, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, c := range cases {
		if c.IsDir() {
			names = append(names, c.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fmt.Errorf("no recorded runs in %s", dir)
	}
	for _, name := range names {
		run := filepath.Join(dir, name)
		want, err := os.ReadFile(filepath.Join(run, "expect")) // #nosec G304 -- the repository's fixtures
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		results, err := ReadDrift(filepath.Join(run, "plans"))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		got := Overall(results)
		fmt.Fprintf(w, "== %s: %s\n", name, got)
		if string(got) != strings.TrimSpace(string(want)) {
			return fmt.Errorf("%s: verdict %s, want %s", name, got, strings.TrimSpace(string(want)))
		}
		if got == Clean {
			continue
		}
		body := IssueBody(results, "https://github.example/run/0")
		fmt.Fprintf(w, "-- issue %q\n%s\n", IssueTitle, body)
		lines, err := os.ReadFile(filepath.Join(run, "expect.issue")) // #nosec G304 -- the repository's fixtures
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		for _, l := range strings.Split(strings.TrimSpace(string(lines)), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.Contains(body, l) {
				return fmt.Errorf("%s: the issue body lacks %q", name, l)
			}
		}
	}
	return nil
}
