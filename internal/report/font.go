package report

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"unicode"
)

// Noto Sans Regular and Bold (SIL Open Font License 1.1, fonts/OFL.txt),
// from the Noto Project's NotoSans-v2.013 release (unhinted TTF; digests in
// fonts/README.md). They are embedded whole in every PDF (F-010 design
// §3.5, PDF/UA-1 needs embedded fonts).
var (
	//go:embed fonts/NotoSans-Regular.ttf
	notoRegular []byte
	//go:embed fonts/NotoSans-Bold.ttf
	notoBold []byte
)

// font is what the writer needs of a TrueType font.
type font struct {
	name        string // the PostScript name
	data        []byte
	unitsPerEm  int
	ascent      int // in font units
	descent     int // negative
	capHeight   int
	bbox        [4]int
	italicAngle float64
	numGlyphs   int
	advance     []int // per glyph, font units
	cmap        map[rune]uint16
}

var (
	fontsOnce sync.Once
	fontReg   *font
	fontBold  *font
	fontErr   error
)

func fonts() (*font, *font, error) {
	fontsOnce.Do(func() {
		fontReg, fontErr = parseFont("NotoSans-Regular", notoRegular)
		if fontErr == nil {
			fontBold, fontErr = parseFont("NotoSans-Bold", notoBold)
		}
	})
	return fontReg, fontBold, fontErr
}

var errFont = errors.New("report: not a usable TrueType font")

// parseFont reads the tables the writer needs: head, hhea, maxp, hmtx,
// cmap (a Unicode subtable: format 12, else format 4), OS/2 and post.
func parseFont(name string, b []byte) (*font, error) {
	be := binary.BigEndian
	if len(b) < 12 {
		return nil, errFont
	}
	tables := map[string][]byte{}
	n := int(be.Uint16(b[4:]))
	for i := range n {
		rec := 12 + 16*i
		if rec+16 > len(b) {
			return nil, errFont
		}
		tag := string(b[rec : rec+4])
		off, ln := int(be.Uint32(b[rec+8:])), int(be.Uint32(b[rec+12:]))
		if off < 0 || ln < 0 || off+ln > len(b) {
			return nil, fmt.Errorf("%w: table %s out of range", errFont, tag)
		}
		tables[tag] = b[off : off+ln]
	}
	need := func(tag string, size int) ([]byte, error) {
		t, ok := tables[tag]
		if !ok || len(t) < size {
			return nil, fmt.Errorf("%w: no %s table", errFont, tag)
		}
		return t, nil
	}
	head, err := need("head", 54)
	if err != nil {
		return nil, err
	}
	hhea, err := need("hhea", 36)
	if err != nil {
		return nil, err
	}
	maxp, err := need("maxp", 6)
	if err != nil {
		return nil, err
	}
	f := &font{name: name, data: b, unitsPerEm: int(be.Uint16(head[18:])), numGlyphs: int(be.Uint16(maxp[4:]))}
	if f.unitsPerEm == 0 {
		return nil, errFont
	}
	for i := range 4 {
		f.bbox[i] = int(int16(be.Uint16(head[36+2*i:]))) // #nosec G115 -- TrueType FWORD: a signed 16-bit value read as two's complement
	}
	f.ascent, f.descent = int(int16(be.Uint16(hhea[4:]))), int(int16(be.Uint16(hhea[6:]))) // #nosec G115 -- TrueType FWORD: a signed 16-bit value read as two's complement
	metrics := int(be.Uint16(hhea[34:]))
	hmtx, err := need("hmtx", 4*metrics)
	if err != nil {
		return nil, err
	}
	f.advance = make([]int, f.numGlyphs)
	last := 0
	for g := range f.numGlyphs {
		if g < metrics {
			last = int(be.Uint16(hmtx[4*g:]))
		}
		f.advance[g] = last
	}
	f.capHeight = f.ascent * 7 / 10
	if os2, ok := tables["OS/2"]; ok && len(os2) >= 90 && be.Uint16(os2) >= 2 {
		f.capHeight = int(int16(be.Uint16(os2[88:]))) // #nosec G115 -- TrueType FWORD: a signed 16-bit value read as two's complement
	}
	if post, ok := tables["post"]; ok && len(post) >= 8 {
		f.italicAngle = float64(int32(be.Uint32(post[4:]))) / 65536 // #nosec G115 -- TrueType signed 32-bit value read as two's complement
	}
	cm, err := need("cmap", 4)
	if err != nil {
		return nil, err
	}
	if f.cmap, err = parseCmap(cm, f.numGlyphs); err != nil {
		return nil, err
	}
	return f, nil
}

func parseCmap(cm []byte, numGlyphs int) (map[rune]uint16, error) {
	be := binary.BigEndian
	var f4, f12 []byte
	for i := range int(be.Uint16(cm[2:])) {
		rec := 4 + 8*i
		if rec+8 > len(cm) {
			return nil, errFont
		}
		plat, enc, off := be.Uint16(cm[rec:]), be.Uint16(cm[rec+2:]), int(be.Uint32(cm[rec+4:]))
		if off+4 > len(cm) {
			continue
		}
		sub := cm[off:]
		switch be.Uint16(sub) {
		case 12:
			if (plat == 3 && enc == 10) || plat == 0 {
				f12 = sub
			}
		case 4:
			if (plat == 3 && enc == 1) || plat == 0 {
				f4 = sub
			}
		}
	}
	out := map[rune]uint16{}
	switch {
	case len(f12) >= 16:
		groups := int(be.Uint32(f12[12:]))
		if 16+12*groups > len(f12) {
			return nil, errFont
		}
		for i := range groups {
			g := f12[16+12*i:]
			start, end, gid := be.Uint32(g), be.Uint32(g[4:]), be.Uint32(g[8:])
			for c := start; c <= end && c <= unicode.MaxRune; c++ {
				if id := gid + (c - start); id < uint32(numGlyphs) { // #nosec G115 -- numGlyphs is a 16-bit count
					out[rune(c)] = uint16(id) // #nosec G115 -- id < numGlyphs, a 16-bit count
				}
			}
		}
	case len(f4) >= 14:
		segs := int(be.Uint16(f4[6:])) / 2
		if 16+8*segs > len(f4) {
			return nil, errFont
		}
		ends, starts := f4[14:], f4[16+2*segs:]
		deltas, ranges := f4[16+4*segs:], f4[16+6*segs:]
		for s := range segs {
			end, start := be.Uint16(ends[2*s:]), be.Uint16(starts[2*s:])
			delta, ro := be.Uint16(deltas[2*s:]), int(be.Uint16(ranges[2*s:]))
			for c := uint32(start); c <= uint32(end) && c != 0xFFFF; c++ {
				var gid uint16
				if ro == 0 {
					gid = uint16(c) + delta // #nosec G115 -- TrueType cmap format 4 arithmetic is modulo 65536
				} else {
					p := 16 + 6*segs + 2*s + ro + 2*int(c-uint32(start))
					if p+2 > len(f4) {
						continue
					}
					if gid = be.Uint16(f4[p:]); gid != 0 {
						gid += delta
					}
				}
				if gid != 0 && int(gid) < numGlyphs {
					out[rune(c)] = gid // #nosec G115 -- c <= unicode.MaxRune
				}
			}
		}
	default:
		return nil, fmt.Errorf("%w: no Unicode cmap", errFont)
	}
	return out, nil
}

// glyph is the glyph for r; ok is false when the font lacks it (the writer
// then draws U+FFFD, never .notdef: PDF/UA-1 forbids it).
func (f *font) glyph(r rune) (uint16, bool) {
	if g, ok := f.cmap[r]; ok {
		return g, true
	}
	if g, ok := f.cmap['�']; ok {
		return g, false
	}
	return f.cmap['?'], false
}

// width is the advance of s at size points.
func (f *font) width(s string, size float64) float64 {
	w := 0
	for _, r := range s {
		g, _ := f.glyph(r)
		w += f.advance[g]
	}
	return float64(w) * size / float64(f.unitsPerEm)
}

// Missing lists the characters of the texts the report fonts cannot draw
// (each once, in order); the writer shows them as U+FFFD.
func Missing(texts ...string) []rune {
	reg, bold, err := fonts()
	if err != nil {
		return nil
	}
	seen := map[rune]bool{}
	var out []rune
	for _, s := range texts {
		for _, r := range s {
			if seen[r] || unicode.IsControl(r) || r == ' ' {
				continue
			}
			seen[r] = true
			_, a := reg.cmap[r]
			_, b := bold.cmap[r]
			if !a || !b {
				out = append(out, r)
			}
		}
	}
	return out
}
