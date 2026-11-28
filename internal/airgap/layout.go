package airgap

import (
	"archive/tar"
	"bufio"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/rformer/fair-app/internal/releaseverify"
)

// Limits of a Zarf package's extraction.
const (
	maxEntries = 1 << 20
	maxBytes   = 64 << 30
	// zstdWindow bounds the decoder's memory (Zarf compresses with the
	// default window, 8 MiB).
	zstdWindow = 128 << 20
)

// ErrNoZarf is returned when a package lists no Zarf package.
var ErrNoZarf = errors.New("airgap: the package lists no Zarf package")

// ZarfIn returns the Zarf package a package manifest lists (its path in
// the package and its SHA-256), the one file whose name ZarfFileRE matches.
func ZarfIn(pm *releaseverify.PackageManifest) (releaseverify.PackageFile, error) {
	var found []releaseverify.PackageFile
	for _, f := range pm.Files {
		if ZarfFileRE.MatchString(path.Base(f.Path)) {
			found = append(found, f)
		}
	}
	switch len(found) {
	case 0:
		return releaseverify.PackageFile{}, ErrNoZarf
	case 1:
		return found[0], nil
	}
	return releaseverify.PackageFile{}, fmt.Errorf("airgap: the package lists %d Zarf packages, want one", len(found))
}

// Layout extracts the image layout of the package in dir into a new
// directory under tmp and returns that layout's path (for
// releaseverify.Options.Layout). It reads nothing it has not checked: the
// package manifest's signature with key, then the Zarf package's SHA-256
// against it, then only the Zarf package's images/ entries. The caller
// removes the returned directory's parent (cleanup) when done.
func Layout(dir string, key *ecdsa.PublicKey, tmp string) (layout string, cleanup func(), err error) {
	b, err := os.ReadFile(filepath.Join(dir, releaseverify.PackageManifestFile)) // #nosec G304 -- the package being verified
	if err != nil {
		return "", nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, releaseverify.PackageManifestFile+".sig")) // #nosec G304 -- its signature
	if err != nil {
		return "", nil, err
	}
	if err := releaseverify.VerifySignature(key, b, sig); err != nil {
		return "", nil, fmt.Errorf("airgap: %s: %w", releaseverify.PackageManifestFile, err)
	}
	pm, err := releaseverify.DecodePackageManifest(b)
	if err != nil {
		return "", nil, fmt.Errorf("airgap: %s: %w", releaseverify.PackageManifestFile, err)
	}
	zf, err := ZarfIn(pm)
	if err != nil {
		return "", nil, err
	}
	file := filepath.Join(dir, filepath.FromSlash(zf.Path))
	got, err := fileSHA256(file)
	if err != nil {
		return "", nil, err
	}
	if got != zf.SHA256 {
		return "", nil, fmt.Errorf("airgap: %s does not match package-manifest.json", zf.Path)
	}
	into, err := os.MkdirTemp(tmp, "fair-zarf-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(into) }
	if err := ExtractImages(file, into); err != nil {
		cleanup()
		return "", nil, err
	}
	return filepath.Join(into, "images"), cleanup, nil
}

func fileSHA256(file string) (string, error) {
	f, err := os.Open(file) // #nosec G304 -- a file of the package being verified
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ExtractImages unpacks the images/ directory of a Zarf package (.tar.zst,
// or .tar for an uncompressed one) into dir: regular files and directories
// only, paths inside dir only, bounded in count and size. Everything else
// in the Zarf package (its zarf.yaml, components, signature) is skipped.
func ExtractImages(file, dir string) error {
	f, err := os.Open(file) // #nosec G304 -- the operator's package
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var r io.Reader = bufio.NewReader(f)
	if strings.HasSuffix(file, ".zst") {
		zr, err := zstd.NewReader(r, zstd.WithDecoderMaxWindow(zstdWindow), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	}
	tr := tar.NewReader(r)
	var total int64
	found := false
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(file), err)
		}
		if n >= maxEntries {
			return fmt.Errorf("%s: more than %d entries", filepath.Base(file), maxEntries)
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name != "images" && !strings.HasPrefix(name, "images/") {
			continue
		}
		if path.IsAbs(name) || strings.Contains(name, "..") || strings.Contains(name, `\`) {
			return fmt.Errorf("%s: entry %q is outside the layout", filepath.Base(file), h.Name)
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if total += h.Size; h.Size < 0 || total > maxBytes {
				return fmt.Errorf("%s: images larger than %d bytes", filepath.Base(file), int64(maxBytes))
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
				return err
			}
			out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- path checked above
			if err != nil {
				return err
			}
			_, cerr := io.CopyN(out, tr, h.Size)
			if err := errors.Join(cerr, out.Close()); err != nil {
				return err
			}
			found = true
		default:
			return fmt.Errorf("%s: entry %q is not a file or directory", filepath.Base(file), h.Name)
		}
	}
	if !found {
		return fmt.Errorf("%s: no images/ layout", filepath.Base(file))
	}
	return nil
}
