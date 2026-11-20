// Command pincheck fails when a build input is not pinned: an action not
// referenced by a full commit, an image not referenced by digest, or a
// dependency without its lock (F-012 T-01, F-012-AC-03).
//
//	pincheck [-root DIR]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rformer/fair-app/internal/pincheck"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
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
