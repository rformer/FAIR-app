// Command infraplan reads OpenTofu plans for the instance pipeline (F-012
// T-14, F-012-AC-14, AC-16; .github/workflows/infra-instances.yml,
// scripts/infra-instance.sh, scripts/infra-drift.sh):
//
//	infraplan summary -title TITLE PLAN.json      Markdown for the pull request
//	infraplan digest PLAN.json                    the changes' digest
//	infraplan create-only PLAN.json               fail unless the plan only creates
//	infraplan drift -plans DIR [-issue FILE] [-run URL]
//	    the drift verdict: exit 0 clean, 2 drift or not checked (FILE: the issue body)
//	infraplan drift -dry-run DIR                  the decision over recorded runs
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rformer/fair-app/internal/infraplan"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "summary":
		fs := flag.NewFlagSet("summary", flag.ExitOnError)
		title := fs.String("title", "Plan", "the summary's heading")
		_ = fs.Parse(os.Args[2:])
		fmt.Print(load(fs.Arg(0)).Summary(*title))
	case "digest":
		fmt.Println(load(arg(2)).Digest())
	case "create-only":
		if err := load(arg(2)).CreateOnly(); err != nil {
			fail(err)
		}
	case "drift":
		drift(os.Args[2:])
	default:
		usage()
	}
}

func drift(args []string) {
	fs := flag.NewFlagSet("drift", flag.ExitOnError)
	plans := fs.String("plans", "", "the drift job's plans (DIR/<instance>/<root>.exitcode, .json)")
	issue := fs.String("issue", "", "write the issue body here when an instance drifted or was not checked")
	run := fs.String("run", "", "the run's URL, linked from the issue")
	dry := fs.String("dry-run", "", "check the decision over the recorded runs in DIR instead")
	_ = fs.Parse(args)
	if *dry != "" {
		if err := infraplan.DryRun(*dry, os.Stdout); err != nil {
			fail(err)
		}
		fmt.Println("infraplan: drift dry run OK")
		return
	}
	if *plans == "" {
		usage()
	}
	rs, err := infraplan.ReadDrift(*plans)
	if err != nil {
		fail(err)
	}
	for _, r := range rs {
		fmt.Printf("%s: %s\n", r.Instance, r.Verdict)
	}
	if infraplan.Overall(rs) == infraplan.Clean {
		return
	}
	if *issue != "" {
		if err := os.WriteFile(*issue, []byte(infraplan.IssueBody(rs, *run)), 0o600); err != nil {
			fail(err)
		}
	}
	os.Exit(2)
}

func load(path string) *infraplan.Plan {
	if path == "" {
		usage()
	}
	p, err := infraplan.Load(path)
	if err != nil {
		fail(err)
	}
	return p
}

func arg(i int) string {
	if len(os.Args) <= i {
		usage()
	}
	return os.Args[i]
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "infraplan:", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: infraplan summary|digest|create-only PLAN.json | drift -plans DIR [-issue FILE] [-run URL] | drift -dry-run DIR")
	os.Exit(1)
}
