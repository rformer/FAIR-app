package report

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Text extracts the text this package's PDFs show, in drawing order, one
// line per text-showing operation, through each font's ToUnicode map: what
// a reader or assistive technology recovers from the file (F-010-AC-12).
// It reads only PDFs written by this package; artifacts (the marking,
// repeated headers, page numbers) are included unless contentOnly.
func Text(pdf []byte, contentOnly bool) (string, error) {
	objs, err := pdfObjects(pdf)
	if err != nil {
		return "", err
	}
	ref := regexp.MustCompile(`/(F\d) (\d+) 0 R`)
	pageRE := regexp.MustCompile(`/Type /Page /Parent`)
	contRE := regexp.MustCompile(`/Contents (\d+) 0 R`)
	var out []string
	cmaps := map[int]map[uint16]string{}
	for n := 1; n < len(objs); n++ {
		body := objs[n]
		if !pageRE.MatchString(body) {
			continue
		}
		fonts := map[string]map[uint16]string{}
		for _, m := range ref.FindAllStringSubmatch(body, -1) {
			fo, _ := strconv.Atoi(m[2])
			cm, err := toUnicode(objs, fo, cmaps)
			if err != nil {
				return "", err
			}
			fonts[m[1]] = cm
		}
		cm := contRE.FindStringSubmatch(body)
		if cm == nil {
			return "", errors.New("report: a page without contents")
		}
		cn, _ := strconv.Atoi(cm[1])
		content, err := streamData(objs[cn])
		if err != nil {
			return "", err
		}
		out = append(out, showText(content, fonts, contentOnly)...)
	}
	return strings.Join(out, "\n"), nil
}

var objRE = regexp.MustCompile(`(?s)(\d+) 0 obj\n(.*?)\nendobj\n`)

func pdfObjects(pdf []byte) ([]string, error) {
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		return nil, errors.New("report: not a PDF")
	}
	var objs []string
	for _, m := range objRE.FindAllSubmatch(pdf, -1) {
		n, _ := strconv.Atoi(string(m[1]))
		for len(objs) <= n {
			objs = append(objs, "")
		}
		objs[n] = string(m[2])
	}
	return objs, nil
}

func streamData(obj string) ([]byte, error) {
	i := strings.Index(obj, "\nstream\n")
	j := strings.LastIndex(obj, "\nendstream")
	if i < 0 || j < i {
		return nil, errors.New("report: not a stream")
	}
	data := []byte(obj[i+len("\nstream\n") : j])
	if !strings.Contains(obj[:i], "/FlateDecode") {
		return data, nil
	}
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func toUnicode(objs []string, fontObj int, cache map[int]map[uint16]string) (map[uint16]string, error) {
	m := regexp.MustCompile(`/ToUnicode (\d+) 0 R`).FindStringSubmatch(objs[fontObj])
	if m == nil {
		return nil, fmt.Errorf("report: font %d has no ToUnicode map", fontObj)
	}
	n, _ := strconv.Atoi(m[1])
	if c, ok := cache[n]; ok {
		return c, nil
	}
	data, err := streamData(objs[n])
	if err != nil {
		return nil, err
	}
	out := map[uint16]string{}
	for _, e := range regexp.MustCompile(`<([0-9A-F]{4})> <([0-9A-F]+)>`).FindAllStringSubmatch(string(data), -1) {
		g, _ := strconv.ParseUint(e[1], 16, 16)
		var units []uint16
		for k := 0; k+4 <= len(e[2]); k += 4 {
			u, _ := strconv.ParseUint(e[2][k:k+4], 16, 16)
			units = append(units, uint16(u))
		}
		out[uint16(g)] = string(utf16.Decode(units))
	}
	cache[n] = out
	return out, nil
}

var opRE = regexp.MustCompile(`/Artifact BMC|EMC|/(F\d) [\d.]+ Tf|<([0-9A-F]*)> Tj`)

func showText(content []byte, fonts map[string]map[uint16]string, contentOnly bool) []string {
	var out []string
	cur := map[uint16]string{}
	depth := 0 // inside an artifact
	for _, m := range opRE.FindAllSubmatch(content, -1) {
		switch {
		case string(m[0]) == "/Artifact BMC":
			depth++
		case string(m[0]) == "EMC":
			if depth > 0 {
				depth--
			}
		case len(m[1]) > 0:
			cur = fonts[string(m[1])]
		default:
			if contentOnly && depth > 0 {
				continue
			}
			var b strings.Builder
			h := string(m[2])
			for k := 0; k+4 <= len(h); k += 4 {
				g, _ := strconv.ParseUint(h[k:k+4], 16, 16)
				b.WriteString(cur[uint16(g)])
			}
			out = append(out, b.String())
		}
	}
	return out
}
