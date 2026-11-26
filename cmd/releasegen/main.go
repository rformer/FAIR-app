// Command releasegen builds and signs the platform release manifest
// (F-015 T-28, design §6.8), the expected state posture-scanner compares the
// cluster with.
//
//	releasegen manifest -release VERSION -images FILE [-deploy deploy/k8s] -out FILE
//	    images FILE is JSON {"component": "repository@sha256:<digest>"} from the
//	    image builds; RBAC hashes come from the reference manifests in -deploy,
//	    a comma-separated list (OpenShift releases: deploy/k8s,deploy/k8s/openshift).
//	releasegen sign -key FILE -in FILE
//	releasegen sign -kms KEY -region REGION -in FILE
//	    writes FILE.sig with the release signing key: a PEM file (ECDSA
//	    P-256), or the release key in AWS KMS (F-012 T-06; key id, ARN or
//	    alias; credentials from AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE).
//	    Both write the same format. -any signs any file, not only a manifest
//	    (SHA256SUMS, profile packages).
//	releasegen public -kms KEY -region REGION -out FILE
//	    the KMS release key's public half as PEM (the release's cosign.pub).
//	releasegen verify -pub FILE -in FILE [-list] [-any]
//	    checks FILE.sig; -list then prints "component image" for each image
//	    of the verified manifest (scripts/verify-release.sh); -any checks the
//	    signature of any file (SHA256SUMS) without reading it as a manifest.
//	releasegen fleet -release VERSION -images FILE -out DIR [-deploy deploy/k8s]
//	    [-keys deploy/k8s/keys] [-observability deploy/observability]
//	    the per-release platform manifests Flux reconciles (F-012 T-15,
//	    internal/fleet): published as a signed OCI artifact by release.yml.
//	releasegen permissions [-out deploy/k8s/permission-manifest.json]
//	    the scanner's permission manifest for consent (T-30); a test keeps
//	    the committed file current.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/rformer/fair-app/internal/fleet"
	"github.com/rformer/fair-app/internal/kmssign"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/scanner"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "releasegen:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: releasegen manifest | fleet | sign | verify | public | permissions | notes | profiles | component-definition (see the command documentation)")
	}
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	switch args[0] {
	case "manifest":
		release := fs.String("release", "", "release version")
		images := fs.String("images", "", "JSON file: component -> repository@sha256:<digest>")
		deploy := fs.String("deploy", "deploy/k8s", "reference manifest directories, comma-separated")
		out := fs.String("out", "", "output file")
		engineRecord := fs.String("engine-validation", "", "the engine image's /engine/validation.json (required when -images names the engine)")
		_ = fs.Parse(args[1:])
		b, err := os.ReadFile(*images) // #nosec G304 G703 -- release-pipeline operator input
		if err != nil {
			return err
		}
		m := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: *release}
		if err := json.Unmarshal(b, &m.Images); err != nil {
			return fmt.Errorf("%s: %w", *images, err)
		}
		if m.RBAC, err = releasemanifest.RBACFromDir(strings.Split(*deploy, ",")...); err != nil {
			return err
		}
		if *engineRecord != "" {
			rec, err := os.ReadFile(*engineRecord) // #nosec G304 G703 -- release-pipeline operator input
			if err != nil {
				return err
			}
			if m.EngineValidation, err = releasemanifest.EngineValidationFromRecord(m.Images[releasemanifest.EngineComponent], rec); err != nil {
				return err
			}
		}
		if err := m.Validate(); err != nil {
			return err
		}
		enc, err := releasemanifest.Encode(m)
		if err != nil {
			return err
		}
		return os.WriteFile(*out, enc, 0o644) // #nosec G306 G703 -- a public release artifact at the operator's path
	case "sign":
		keyFile := fs.String("key", "", "release signing key (PEM)")
		kmsKey := fs.String("kms", "", "release key in AWS KMS (key id, ARN or alias)")
		region := fs.String("region", "", "AWS region of the KMS key")
		in := fs.String("in", "", "manifest file")
		anyFile := fs.Bool("any", false, "sign any file, not only a release manifest")
		_ = fs.Parse(args[1:])
		if (*keyFile == "") == (*kmsKey == "") {
			return errors.New("sign: exactly one of -key and -kms")
		}
		b, err := os.ReadFile(*in) // #nosec G304 G703 -- release-pipeline operator input
		if err != nil {
			return err
		}
		if !*anyFile {
			var m releasemanifest.Manifest
			if err := json.Unmarshal(b, &m); err != nil {
				return err
			}
			if err := m.Validate(); err != nil {
				return err
			}
		}
		var sig []byte
		if *kmsKey != "" {
			s, err := kmsSigner(*kmsKey, *region)
			if err != nil {
				return err
			}
			sig, err = s.Sign(context.Background(), b)
			if err != nil {
				return err
			}
		} else {
			key, err := profilepkg.LoadPrivateKey(*keyFile)
			if err != nil {
				return err
			}
			if sig, err = profilepkg.Sign(key, b); err != nil {
				return err
			}
		}
		return os.WriteFile(*in+".sig", sig, 0o644) // #nosec G306 G703 -- a public release artifact at the operator's path
	case "public":
		kmsKey := fs.String("kms", "", "release key in AWS KMS (key id, ARN or alias)")
		region := fs.String("region", "", "AWS region of the KMS key")
		out := fs.String("out", "", "output file")
		_ = fs.Parse(args[1:])
		s, err := kmsSigner(*kmsKey, *region)
		if err != nil {
			return err
		}
		p, err := s.PublicPEM()
		if err != nil {
			return err
		}
		return os.WriteFile(*out, p, 0o644) // #nosec G306 G703 -- a public key at the operator's path
	case "permissions":
		out := fs.String("out", "deploy/k8s/permission-manifest.json", "output file")
		_ = fs.Parse(args[1:])
		m, err := scanner.Manifest()
		if err != nil {
			return err
		}
		b, err := m.Encode()
		if err != nil {
			return err
		}
		return os.WriteFile(*out, b, 0o644) // #nosec G306 G703 -- a public release artifact at the operator's path
	case "verify":
		pubFile := fs.String("pub", "", "release public key (PEM)")
		in := fs.String("in", "", "manifest file")
		list := fs.Bool("list", false, "print each image of the verified manifest")
		anyFile := fs.Bool("any", false, "verify the signature of any file")
		_ = fs.Parse(args[1:])
		pub, err := profilepkg.LoadPublicKey(*pubFile)
		if err != nil {
			return err
		}
		if *anyFile {
			b, err := os.ReadFile(*in) // #nosec G304 G703 -- release-pipeline operator input
			if err != nil {
				return err
			}
			sig, err := os.ReadFile(*in + ".sig") // #nosec G304 G703 -- release-pipeline operator input
			if err != nil {
				return err
			}
			if err := profilepkg.VerifySignature(pub, b, sig); err != nil {
				return fmt.Errorf("%s: %w", *in, err)
			}
			fmt.Fprintf(os.Stderr, "%s: signature verified\n", *in)
			return nil
		}
		m, err := releasemanifest.Load(pub, *in)
		if err != nil {
			return err
		}
		if *list {
			cs := make([]string, 0, len(m.Images))
			for c := range m.Images {
				cs = append(cs, c)
			}
			slices.Sort(cs)
			for _, c := range cs {
				fmt.Println(c, m.Images[c])
			}
		}
		fmt.Fprintf(os.Stderr, "release %s: %d images, %d RBAC objects, signature verified\n", m.Release, len(m.Images), len(m.RBAC))
		return nil
	case "fleet":
		release := fs.String("release", "", "release version")
		images := fs.String("images", "", "JSON file: component -> repository@sha256:<digest>")
		deploy := fs.String("deploy", "deploy/k8s", "reference manifests")
		keys := fs.String("keys", "deploy/k8s/keys", "key store manifests")
		obs := fs.String("observability", "deploy/observability", "Collector configurations and objects (\"\": none)")
		out := fs.String("out", "", "output directory (must not exist)")
		_ = fs.Parse(args[1:])
		b, err := os.ReadFile(*images) // #nosec G304 G703 -- release-pipeline operator input
		if err != nil {
			return err
		}
		var imgs map[string]string
		if err := json.Unmarshal(b, &imgs); err != nil {
			return fmt.Errorf("%s: %w", *images, err)
		}
		return fleet.Render(fleet.Options{Release: *release, Images: imgs, Deploy: *deploy, Keys: *keys, Observability: *obs}, *out)
	case "notes":
		return notes(args[1:])
	case "profiles":
		return profiles(args[1:])
	case "component-definition":
		return componentDefinition(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// kmsSigner is the KMS release key's signer (F-012 T-06).
func kmsSigner(key, region string) (*kmssign.Signer, error) {
	c, err := kmssign.Client(region)
	if err != nil {
		return nil, err
	}
	return kmssign.New(context.Background(), c, key)
}
