// Command profilegen is the build-time profile tool (F-015 design §2, §4).
//
//	profilegen profiles   regenerate the in-repo OSCAL profiles under profiles/
//
// Packaging and signing arrive with T-06.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/rformer/fair-app/internal/profilegen"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "profiles" {
		fmt.Fprintln(os.Stderr, "usage: profilegen profiles   (run from the repository root)")
		os.Exit(2)
	}
	files, err := profilegen.InRepoProfiles("third_party/oscal", "profiles")
	if err != nil {
		fmt.Fprintln(os.Stderr, "profilegen:", err)
		os.Exit(1)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		p := filepath.Join("profiles", filepath.FromSlash(n))
		if err := os.WriteFile(p, files[n], 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "profilegen:", err)
			os.Exit(1)
		}
		fmt.Println("wrote", p)
	}
}
