// Command vulnex checks security/vuln-exceptions.yaml and writes the image
// scan's ignore file for one component (F-012 T-03, F-012-AC-07). An
// expired or malformed exception fails it.
//
//	vulnex [-file security/vuln-exceptions.yaml] -component NAME -out .trivyignore
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rformer/fair-app/internal/vulnex"
)

func main() {
	file := flag.String("file", "security/vuln-exceptions.yaml", "the exceptions file")
	component := flag.String("component", "", "the image's component")
	out := flag.String("out", ".trivyignore", "the ignore file to write")
	flag.Parse()
	if *component == "" {
		fmt.Fprintln(os.Stderr, "vulnex: -component is required")
		os.Exit(2)
	}
	f, err := vulnex.Load(*file, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, f.TrivyIgnore(*component), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
