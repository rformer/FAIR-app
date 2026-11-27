// Command pincheck fails when a build input is not pinned: an action not
// referenced by a full commit, an image not referenced by digest, or a
// dependency without its lock (F-012 T-01, F-012-AC-03).
//
//	pincheck [-root DIR]
//	pincheck [-root DIR] -spdx COMPONENT
//
// With -spdx it prints, instead, the SPDX document of a bundled
// dependency image's pinned sources (deploy/bundled/sources.json; F-014
// T-07), which the image carries for its SBOM.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rformer/fair-app/internal/pincheck"
)

func main() {
	root := flag.String("root", ".", "repository root")
	spdx := flag.String("spdx", "", "print the SPDX document of this bundled component's sources")
	flag.Parse()
	if *spdx != "" {
		s, problems, err := pincheck.LoadBundledSources(filepath.Join(*root, filepath.FromSlash(pincheck.BundledSourcesFile)))
		if err == nil && len(problems) > 0 {
			err = fmt.Errorf("%s", problems[0])
		}
		var b []byte
		if err == nil {
			b, err = s.SPDX(*spdx)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "pincheck:", err)
			os.Exit(2)
		}
		_, _ = os.Stdout.Write(b)
		return
	}
	problems, err := pincheck.Check(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pincheck:", err)
		os.Exit(2)
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "pincheck: %d unpinned inputs\n", len(problems))
		os.Exit(1)
	}
}
