// Command releasegen builds and signs the platform release manifest
// (F-015 T-28, design §6.8), the expected state posture-scanner compares the
// cluster with.
//
//	releasegen manifest -release VERSION -images FILE [-deploy deploy/k8s] -out FILE
//	    images FILE is JSON {"component": "repository@sha256:<digest>"} from the
//	    image builds; RBAC hashes come from the reference manifests in -deploy.
//	releasegen sign -key FILE -in FILE
//	    writes FILE.sig with the release signing key (PEM, ECDSA P-256).
//	releasegen verify -pub FILE -in FILE
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "releasegen:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: releasegen manifest | sign | verify (see the command documentation)")
	}
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	switch args[0] {
	case "manifest":
		release := fs.String("release", "", "release version")
		images := fs.String("images", "", "JSON file: component -> repository@sha256:<digest>")
		deploy := fs.String("deploy", "deploy/k8s", "reference manifests")
		out := fs.String("out", "", "output file")
		_ = fs.Parse(args[1:])
		b, err := os.ReadFile(*images) // #nosec G304 G703 -- release-pipeline operator input
		if err != nil {
			return err
		}
		m := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: *release}
		if err := json.Unmarshal(b, &m.Images); err != nil {
			return fmt.Errorf("%s: %w", *images, err)
		}
		if m.RBAC, err = releasemanifest.RBACFromDir(*deploy); err != nil {
			return err
		}
		enc, err := releasemanifest.Encode(m)
		if err != nil {
			return err
		}
		return os.WriteFile(*out, enc, 0o644) // #nosec G306 G703 -- a public release artifact at the operator's path
	case "sign":
		keyFile := fs.String("key", "", "release signing key (PEM)")
		in := fs.String("in", "", "manifest file")
		_ = fs.Parse(args[1:])
		key, err := profilepkg.LoadPrivateKey(*keyFile)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(*in) // #nosec G304 G703 -- release-pipeline operator input
		if err != nil {
			return err
		}
		var m releasemanifest.Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		if err := m.Validate(); err != nil {
			return err
		}
		sig, err := profilepkg.Sign(key, b)
		if err != nil {
			return err
		}
		return os.WriteFile(*in+".sig", sig, 0o644) // #nosec G306 G703 -- a public release artifact at the operator's path
	case "verify":
		pubFile := fs.String("pub", "", "release public key (PEM)")
		in := fs.String("in", "", "manifest file")
		_ = fs.Parse(args[1:])
		pub, err := profilepkg.LoadPublicKey(*pubFile)
		if err != nil {
			return err
		}
		m, err := releasemanifest.Load(pub, *in)
		if err != nil {
			return err
		}
		fmt.Printf("release %s: %d images, %d RBAC objects, signature verified\n", m.Release, len(m.Images), len(m.RBAC))
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
