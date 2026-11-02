// Package report renders tabular reports as CSV and as tagged PDF (F-001
// T-38; AC-48). The PDF writer is our own and small: US Letter landscape,
// the standard Helvetica fonts (WinAnsi), text wrapped within columns, the
// header row repeated on every page, page numbers. It is a tagged PDF (a
// structure tree of Document, headings, paragraphs and Table/TR/TH/TD, with
// marked content, the document language and title), so assistive
// technology reads it in order with its table semantics; repeated headers,
// rules and page numbers are artifacts. It is not PDF/UA-conformant: the
// standard fonts are not embedded. Output is deterministic for a given
// document.
package report

import (
	"bytes"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Column is a table column; Weight is its share of the table width.
type Column struct {
	Title  string
	Weight float64
}

// Section is a heading, an optional note and a table.
type Section struct {
	Heading string
	Note    string
	Columns []Column
	Rows    [][]string
}

// Document is a report.
type Document struct {
	Title    string
	Subtitle string
	Author   string
	Lang     string // default en-US
	Created  time.Time
	Sections []Section
}

const (
	pageW, pageH  = 792.0, 612.0 // Letter, landscape
	margin        = 36.0
	cellSize      = 7.0
	headSize      = 7.0
	lineH         = 8.6
	padX, padY    = 2.5, 2.5
	titleSize     = 14.0
	headingSize   = 10.5
	noteSize      = 8.0
	footerReserve = 20.0
)

// helvetica holds the Helvetica advance widths (1/1000 em) of WinAnsi 32..126.
var helvetica = [95]int{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556,
	556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722,
	778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556,
	278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260,
	334, 584,
}

// winAnsi maps a rune to its WinAnsi byte ('?' when it has none).
func winAnsi(r rune) byte {
	switch {
	case r >= 32 && r <= 126:
		return byte(r)
	case r >= 0xA0 && r <= 0xFF:
		return byte(r)
	}
	switch r {
	case '€':
		return 0x80
	case '‚':
		return 0x82
	case '„':
		return 0x84
	case '…':
		return 0x85
	case '‘':
		return 0x91
	case '’':
		return 0x92
	case '“':
		return 0x93
	case '”':
		return 0x94
	case '•':
		return 0x95
	case '–':
		return 0x96
	case '—':
		return 0x97
	case '™':
		return 0x99
	}
	return '?'
}

func width(s string, size float64, bold bool) float64 {
	w := 0
	for _, r := range s {
		b := winAnsi(r)
		if b >= 32 && b <= 126 {
			w += helvetica[b-32]
		} else {
			w += 556
		}
	}
	f := 1.0
	if bold {
		f = 1.07 // Helvetica-Bold is a little wider
	}
	return float64(w) * size / 1000 * f
}

// wrap breaks s into lines no wider than w (words longer than a line are
// split).
func wrap(s string, w, size float64, bold bool) []string {
	var lines []string
	for _, para := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		cur := ""
		for _, word := range strings.Fields(para) {
			for width(word, size, bold) > w && utf8.RuneCountInString(word) > 1 {
				n := 1
				rs := []rune(word)
				for n < len(rs) && width(string(rs[:n+1]), size, bold) <= w {
					n++
				}
				if cur != "" {
					lines = append(lines, cur)
					cur = ""
				}
				lines = append(lines, string(rs[:n]))
				word = string(rs[n:])
			}
			switch {
			case cur == "":
				cur = word
			case width(cur+" "+word, size, bold) <= w:
				cur += " " + word
			default:
				lines = append(lines, cur)
				cur = word
			}
		}
		lines = append(lines, cur)
	}
	return lines
}

func pdfString(s string) string {
	var b strings.Builder
	b.WriteByte('(')
	for _, r := range s {
		switch c := winAnsi(r); c {
		case '(', ')', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			if c < 32 || c > 126 {
				fmt.Fprintf(&b, "\\%03o", c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte(')')
	return b.String()
}

// utf16String is a PDF text string (UTF-16BE with BOM) for metadata and
// structure attributes.
func utf16String(s string) string {
	var b strings.Builder
	b.WriteString("<FEFF")
	for _, r := range s {
		if r > 0xFFFF {
			r -= 0x10000
			fmt.Fprintf(&b, "%04X%04X", 0xD800+(r>>10), 0xDC00+(r&0x3FF))
			continue
		}
		fmt.Fprintf(&b, "%04X", r)
	}
	b.WriteString(">")
	return b.String()
}

// The structure tree as it is built: elements with kids that are either
// other elements or marked content on a page.
type elem struct {
	typ   string // Document, H1, H2, P, Table, TR, TH, TD
	attrs string // e.g. the /A dictionary
	kids  []any  // *elem or mcr
	obj   int
}

type mcr struct{ page, mcid int }

type page struct {
	content bytes.Buffer
	mcids   []*elem // the element owning each MCID
}

type layout struct {
	pages []*page
	y     float64
}

func (l *layout) cur() *page { return l.pages[len(l.pages)-1] }

func (l *layout) newPage() {
	l.pages = append(l.pages, &page{})
	l.y = pageH - margin
}

// text writes lines as one marked-content sequence of el.
func (l *layout) text(el *elem, x float64, lines []string, size float64, bold bool) {
	p := l.cur()
	mcid := len(p.mcids)
	p.mcids = append(p.mcids, el)
	el.kids = append(el.kids, mcr{len(l.pages) - 1, mcid})
	font := "F1"
	if bold {
		font = "F2"
	}
	fmt.Fprintf(&p.content, "/%s <</MCID %d>> BDC\nBT /%s %.1f Tf\n", tagOf(el), mcid, font, size)
	y := l.y - size
	for _, ln := range lines {
		fmt.Fprintf(&p.content, "1 0 0 1 %.2f %.2f Tm %s Tj\n", x, y, pdfString(ln))
		y -= size * 1.23
	}
	p.content.WriteString("ET\nEMC\n")
}

func tagOf(el *elem) string { return el.typ }

// artifact writes text or graphics that are not content (repeated headers,
// rules, page numbers).
func (l *layout) artifact(ops string) {
	fmt.Fprintf(&l.cur().content, "/Artifact BMC\n%sEMC\n", ops)
}

// PDF renders the document.
func (d Document) PDF() ([]byte, error) {
	if d.Lang == "" {
		d.Lang = "en-US"
	}
	root := &elem{typ: "Document"}
	l := &layout{}
	l.newPage()
	tableW := pageW - 2*margin
	bottom := margin + footerReserve

	h1 := &elem{typ: "H1"}
	root.kids = append(root.kids, h1)
	l.text(h1, margin, []string{d.Title}, titleSize, true)
	l.y -= titleSize * 1.6
	if d.Subtitle != "" {
		p := &elem{typ: "P"}
		root.kids = append(root.kids, p)
		lines := wrap(d.Subtitle, tableW, noteSize, false)
		l.text(p, margin, lines, noteSize, false)
		l.y -= float64(len(lines))*noteSize*1.23 + 6
	}
	for _, s := range d.Sections {
		if len(s.Columns) == 0 {
			return nil, fmt.Errorf("report: section %q has no columns", s.Heading)
		}
		total := 0.0
		for _, c := range s.Columns {
			total += c.Weight
		}
		widths := make([]float64, len(s.Columns))
		xs := make([]float64, len(s.Columns))
		x := margin
		for i, c := range s.Columns {
			widths[i] = tableW * c.Weight / total
			xs[i] = x
			x += widths[i]
		}
		headLines := make([][]string, len(s.Columns))
		headH := 0.0
		for i, c := range s.Columns {
			headLines[i] = wrap(c.Title, widths[i]-2*padX, headSize, true)
			headH = max(headH, float64(len(headLines[i]))*lineH)
		}
		headH += 2 * padY
		if l.y-headingSize*2-headH-lineH-2*padY < bottom {
			l.newPage()
		}
		h2 := &elem{typ: "H2"}
		root.kids = append(root.kids, h2)
		l.text(h2, margin, []string{s.Heading}, headingSize, true)
		l.y -= headingSize * 1.6
		if s.Note != "" {
			p := &elem{typ: "P"}
			root.kids = append(root.kids, p)
			lines := wrap(s.Note, tableW, noteSize, false)
			l.text(p, margin, lines, noteSize, false)
			l.y -= float64(len(lines))*noteSize*1.23 + 4
		}
		table := &elem{typ: "Table"}
		root.kids = append(root.kids, table)
		// The header row: content on the table's first page, an artifact
		// when repeated.
		header := func(tagged bool) {
			if tagged {
				tr := &elem{typ: "TR"}
				table.kids = append(table.kids, tr)
				for i := range s.Columns {
					th := &elem{typ: "TH", attrs: "/A <</O /Table /Scope /Column>>"}
					tr.kids = append(tr.kids, th)
					l.text(th, xs[i]+padX, headLines[i], headSize, true)
				}
			} else {
				var ops strings.Builder
				for i := range s.Columns {
					fmt.Fprintf(&ops, "BT /F2 %.1f Tf\n", headSize)
					y := l.y - headSize - padY
					for _, ln := range headLines[i] {
						fmt.Fprintf(&ops, "1 0 0 1 %.2f %.2f Tm %s Tj\n", xs[i]+padX, y, pdfString(ln))
						y -= lineH
					}
					ops.WriteString("ET\n")
				}
				l.artifact(ops.String())
			}
			l.artifact(fmt.Sprintf("0.85 g %.2f %.2f %.2f %.2f re f 0 g\n", margin, l.y-headH, tableW, 0.6))
			l.y -= headH
		}
		l.y -= padY // the text sits below the row's top
		header(true)
		if len(s.Rows) == 0 {
			p := &elem{typ: "P"}
			root.kids = append(root.kids, p)
			l.y -= padY
			l.text(p, margin+padX, []string{"No rows."}, cellSize, false)
			l.y -= lineH + 6
			continue
		}
		for _, row := range s.Rows {
			cells := make([][]string, len(s.Columns))
			h := 0.0
			for i := range s.Columns {
				v := ""
				if i < len(row) {
					v = row[i]
				}
				cells[i] = wrap(v, widths[i]-2*padX, cellSize, false)
				h = max(h, float64(len(cells[i]))*lineH)
			}
			h += 2 * padY
			if l.y-h < bottom {
				l.newPage()
				header(false)
			}
			tr := &elem{typ: "TR"}
			table.kids = append(table.kids, tr)
			top := l.y
			l.y -= padY
			for i := range s.Columns {
				td := &elem{typ: "TD"}
				tr.kids = append(tr.kids, td)
				l.text(td, xs[i]+padX, cells[i], cellSize, false)
			}
			l.y = top - h
			l.artifact(fmt.Sprintf("0.92 g %.2f %.2f %.2f %.2f re f 0 g\n", margin, l.y, tableW, 0.4))
		}
		l.y -= 10
	}
	// Page numbers.
	for i, p := range l.pages {
		label := fmt.Sprintf("Page %d of %d", i+1, len(l.pages))
		fmt.Fprintf(&p.content, "/Artifact BMC\nBT /F1 7.0 Tf 1 0 0 1 %.2f %.2f Tm %s Tj ET\nEMC\n",
			pageW-margin-width(label, 7, false), margin-4, pdfString(label))
	}
	return d.write(root, l)
}

type writer struct {
	buf     bytes.Buffer
	offsets []int
}

func (w *writer) obj(n int, body string) {
	for len(w.offsets) <= n {
		w.offsets = append(w.offsets, 0)
	}
	w.offsets[n] = w.buf.Len()
	fmt.Fprintf(&w.buf, "%d 0 obj\n%s\nendobj\n", n, body)
}

func (d Document) write(root *elem, l *layout) ([]byte, error) {
	// Object numbers: 1 catalog, 2 pages, 3 F1, 4 F2, 5 info, 6 struct
	// tree root, 7 parent tree, then pages and contents, then elements.
	next := 8
	pageObj := make([]int, len(l.pages))
	contentObj := make([]int, len(l.pages))
	for i := range l.pages {
		pageObj[i], contentObj[i] = next, next+1
		next += 2
	}
	var all []*elem
	var number func(e *elem)
	number = func(e *elem) {
		e.obj = next
		next++
		all = append(all, e)
		for _, k := range e.kids {
			if c, ok := k.(*elem); ok {
				number(c)
			}
		}
	}
	number(root)
	parent := map[*elem]int{}
	for _, e := range all {
		for _, k := range e.kids {
			if c, ok := k.(*elem); ok {
				parent[c] = e.obj
			}
		}
	}

	w := &writer{}
	w.buf.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	w.obj(1, fmt.Sprintf("<< /Type /Catalog /Pages 2 0 R /StructTreeRoot 6 0 R /MarkInfo << /Marked true >> /Lang %s "+
		"/ViewerPreferences << /DisplayDocTitle true >> >>", pdfString(d.Lang)))
	kids := make([]string, len(pageObj))
	for i, n := range pageObj {
		kids[i] = fmt.Sprintf("%d 0 R", n)
	}
	w.obj(2, fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>", len(pageObj), strings.Join(kids, " ")))
	w.obj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	w.obj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	created := d.Created.UTC().Format("20060102150405") + "Z"
	w.obj(5, fmt.Sprintf("<< /Title %s /Author %s /Creator %s /Producer %s /CreationDate (D:%s) >>",
		utf16String(d.Title), utf16String(d.Author), utf16String("FAIR platform"), utf16String("FAIR report writer"), created))
	w.obj(6, fmt.Sprintf("<< /Type /StructTreeRoot /K %d 0 R /ParentTree 7 0 R /ParentTreeNextKey %d >>", root.obj, len(l.pages)))
	var nums strings.Builder
	for i, p := range l.pages {
		refs := make([]string, len(p.mcids))
		for j, e := range p.mcids {
			refs[j] = fmt.Sprintf("%d 0 R", e.obj)
		}
		fmt.Fprintf(&nums, "%d [%s] ", i, strings.Join(refs, " "))
	}
	w.obj(7, fmt.Sprintf("<< /Nums [%s] >>", strings.TrimSpace(nums.String())))
	for i, p := range l.pages {
		w.obj(pageObj[i], fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "+
			"/Contents %d 0 R /StructParents %d /Tabs /S >>", pageW, pageH, contentObj[i], i))
		w.obj(contentObj[i], fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", p.content.Len(), p.content.String()))
	}
	for _, e := range all {
		var k []string
		for _, c := range e.kids {
			switch x := c.(type) {
			case *elem:
				k = append(k, fmt.Sprintf("%d 0 R", x.obj))
			case mcr:
				k = append(k, fmt.Sprintf("<< /Type /MCR /Pg %d 0 R /MCID %d >>", pageObj[x.page], x.mcid))
			}
		}
		p := 6
		if n, ok := parent[e]; ok {
			p = n
		}
		attrs := ""
		if e.attrs != "" {
			attrs = " " + e.attrs
		}
		w.obj(e.obj, fmt.Sprintf("<< /Type /StructElem /S /%s /P %d 0 R /K [%s]%s >>", e.typ, p, strings.Join(k, " "), attrs))
	}
	xref := w.buf.Len()
	fmt.Fprintf(&w.buf, "xref\n0 %d\n0000000000 65535 f \n", next)
	for i := 1; i < next; i++ {
		fmt.Fprintf(&w.buf, "%010d 00000 n \n", w.offsets[i])
	}
	fmt.Fprintf(&w.buf, "trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n", next, xref)
	return w.buf.Bytes(), nil
}
