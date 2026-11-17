// Package report renders reports as CSV and as PDF (F-001 T-38; F-010
// T-07). The PDF writer is our own and small: US Letter landscape, Noto
// Sans Regular and Bold embedded whole as CID fonts with ToUnicode maps,
// Unicode text wrapped within its block, tables with the header row
// repeated on every page, figures drawn as vector paths, a marking in the
// header and footer, page numbers. It writes PDF/UA-1 (F-010 design §3.5):
// a full structure tree (Document, H1 to H3, P, L/LI/Lbl/LBody,
// Table/Caption/TR/TH(scope)/TD, Figure with Alt), the document language and
// title shown, XMP metadata with the PDF/UA identifier; repeated headers,
// rules, the marking and page numbers are artifacts. Characters the fonts
// lack are drawn as U+FFFD (Missing lists them). Output is deterministic for
// a given document, and making it needs no network.
package report

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Column is a table column; Weight is its share of the table width.
type Column struct {
	Title  string
	Weight float64
	Right  bool // right-aligned (numbers)
}

// Section is a heading, an optional note and a table (F-001's reports).
type Section struct {
	Heading string
	Note    string
	Columns []Column
	Rows    [][]string
}

// Document is a tabular report (F-001's entitlement reports): a title, a
// subtitle and sections, each a heading, a note and a table.
type Document struct {
	Title    string
	Subtitle string
	Author   string
	Lang     string // default en-US
	Created  time.Time
	Sections []Section
}

// PDF renders the document (through Doc).
func (d Document) PDF() ([]byte, error) {
	doc := Doc{Title: d.Title, Author: d.Author, Lang: d.Lang, Created: d.Created}
	doc.Blocks = append(doc.Blocks, Block{Kind: Heading, Level: 1, Text: d.Title})
	if d.Subtitle != "" {
		doc.Blocks = append(doc.Blocks, Block{Kind: Paragraph, Text: d.Subtitle, Small: true})
	}
	for _, s := range d.Sections {
		if len(s.Columns) == 0 {
			return nil, fmt.Errorf("report: section %q has no columns", s.Heading)
		}
		doc.Blocks = append(doc.Blocks, Block{Kind: Heading, Level: 2, Text: s.Heading})
		if s.Note != "" {
			doc.Blocks = append(doc.Blocks, Block{Kind: Paragraph, Text: s.Note, Small: true})
		}
		doc.Blocks = append(doc.Blocks, Block{Kind: TableBlock, Table: &Table{Columns: s.Columns, Rows: s.Rows}})
	}
	return doc.PDF()
}

// Block kinds.
const (
	Heading     = "heading"
	Paragraph   = "paragraph"
	List        = "list"
	TableBlock  = "table"
	FigureBlock = "figure"
)

// Block is one piece of a Doc.
type Block struct {
	Kind   string
	Level  int    // headings: 1 to 3
	Text   string // headings, paragraphs
	Small  bool   // paragraphs: note size
	Items  []string
	Table  *Table
	Figure *Figure
}

// Table is a table. With RowHeaders, each row's first cell is a header
// for its row (TH, scope Row), as for label and value pairs.
type Table struct {
	Caption    string
	Columns    []Column
	Rows       [][]string
	RowHeaders bool
	NoHeader   bool // no header row (pairs)
}

// Figure is a chart: drawn by Draw into a box of the page's width and
// Height points, tagged as a Figure with Alt as its alternative text.
type Figure struct {
	Alt     string
	Caption string
	Height  float64
	Draw    func(c *Canvas)
}

// Doc is a report document of blocks.
type Doc struct {
	Title   string
	Author  string
	Subject string
	Lang    string // default en-US
	Created time.Time
	Marking string // in every page's header and footer, and once in the text
	Blocks  []Block
}

const (
	pageW, pageH  = 792.0, 612.0 // Letter, landscape
	margin        = 36.0
	bodySize      = 8.5
	cellSize      = 7.0
	headSize      = 7.0
	lineH         = 8.6
	padX, padY    = 2.5, 2.5
	noteSize      = 8.0
	footerReserve = 20.0
	headerReserve = 14.0
)

var headingSizes = map[int]float64{1: 14, 2: 10.5, 3: 9}

// The structure tree as it is built: elements with kids that are either
// other elements or marked content on a page.
type elem struct {
	typ   string // Document, H1, H2, H3, P, L, LI, Lbl, LBody, Table, Caption, TR, TH, TD, Figure
	attrs string // e.g. the /A dictionary
	kids  []any  // *elem or mcr
	obj   int
}

func (e *elem) add(typ, attrs string) *elem {
	c := &elem{typ: typ, attrs: attrs}
	e.kids = append(e.kids, c)
	return c
}

type mcr struct{ page, mcid int }

type page struct {
	content bytes.Buffer
	mcids   []*elem // the element owning each MCID
}

type layout struct {
	pages     []*page
	y         float64
	reg, bold *font
	used      [2]map[uint16]rune // per font, glyph -> the character it was drawn for
	marking   string
}

func (l *layout) cur() *page { return l.pages[len(l.pages)-1] }

func (l *layout) newPage() {
	l.pages = append(l.pages, &page{})
	l.y = pageH - margin
	if l.marking != "" {
		l.y -= headerReserve
	}
}

func (l *layout) font(bold bool) (*font, int) {
	if bold {
		return l.bold, 1
	}
	return l.reg, 0
}

func (l *layout) width(s string, size float64, bold bool) float64 {
	f, _ := l.font(bold)
	return f.width(s, size)
}

// enc is s as a hex string of glyph ids, recording each glyph's character
// for the ToUnicode map.
func (l *layout) enc(s string, bold bool) string {
	f, i := l.font(bold)
	var b strings.Builder
	b.WriteByte('<')
	for _, r := range s {
		g, ok := f.glyph(r)
		if !ok {
			r = '�'
		}
		if _, seen := l.used[i][g]; !seen {
			l.used[i][g] = r
		}
		fmt.Fprintf(&b, "%04X", g)
	}
	b.WriteByte('>')
	return b.String()
}

func fontRes(bold bool) string {
	if bold {
		return "F2"
	}
	return "F1"
}

// clean removes control characters (a line break is the caller's).
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

// wrap breaks s into lines no wider than w (words longer than a line are
// split).
func (l *layout) wrap(s string, w, size float64, bold bool) []string {
	var lines []string
	for _, para := range strings.Split(strings.ReplaceAll(clean(s), "\r", ""), "\n") {
		cur := ""
		for _, word := range strings.Fields(para) {
			for l.width(word, size, bold) > w && utf8.RuneCountInString(word) > 1 {
				n := 1
				rs := []rune(word)
				for n < len(rs) && l.width(string(rs[:n+1]), size, bold) <= w {
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
			case l.width(cur+" "+word, size, bold) <= w:
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

// text writes lines as one marked-content sequence of el; right aligns
// each line's end at x+w.
func (l *layout) text(el *elem, x, w float64, lines []string, size float64, bold, right bool) {
	p := l.cur()
	mcid := len(p.mcids)
	p.mcids = append(p.mcids, el)
	el.kids = append(el.kids, mcr{len(l.pages) - 1, mcid})
	fmt.Fprintf(&p.content, "/%s <</MCID %d>> BDC\nBT /%s %.1f Tf\n", el.typ, mcid, fontRes(bold), size)
	y := l.y - size
	for _, ln := range lines {
		lx := x
		if right {
			lx = x + w - l.width(ln, size, bold)
		}
		fmt.Fprintf(&p.content, "1 0 0 1 %.2f %.2f Tm %s Tj\n", lx, y, l.enc(ln, bold))
		y -= size * 1.23
	}
	p.content.WriteString("ET\nEMC\n")
}

// artifactText draws text that is not content.
func (l *layout) artifactText(x, y float64, s string, size float64, bold bool) string {
	return fmt.Sprintf("BT /%s %.1f Tf 1 0 0 1 %.2f %.2f Tm %s Tj ET\n", fontRes(bold), size, x, y, l.enc(s, bold))
}

// artifact writes text or graphics that are not content (repeated headers,
// rules, the marking, page numbers).
func (l *layout) artifact(ops string) {
	fmt.Fprintf(&l.cur().content, "/Artifact BMC\n%sEMC\n", ops)
}

var errEmpty = fmt.Errorf("report: a document needs a title and at least one block")

// PDF renders the document as PDF/UA-1.
func (d Doc) PDF() ([]byte, error) {
	if d.Title == "" || len(d.Blocks) == 0 {
		return nil, errEmpty
	}
	if d.Lang == "" {
		d.Lang = "en-US"
	}
	reg, bold, err := fonts()
	if err != nil {
		return nil, err
	}
	root := &elem{typ: "Document"}
	l := &layout{reg: reg, bold: bold, marking: clean(d.Marking), used: [2]map[uint16]rune{{}, {}}}
	l.newPage()
	fullW := pageW - 2*margin
	bottom := margin + footerReserve
	if l.marking != "" {
		p := root.add("P", "")
		l.text(p, margin, fullW, []string{l.marking}, noteSize, true, false)
		l.y -= noteSize * 1.6
	}
	level := 0 // the last heading's level: headings never skip one
	for bi, b := range d.Blocks {
		switch b.Kind {
		case Heading:
			if b.Level < 1 || b.Level > 3 || b.Level > level+1 {
				return nil, fmt.Errorf("report: block %d: heading level %d after %d", bi, b.Level, level)
			}
			level = b.Level
			size := headingSizes[b.Level]
			lines := l.wrap(b.Text, fullW, size, true)
			h := float64(len(lines))*size*1.23 + size*0.6
			if l.y-h-4*lineH < bottom { // keep with what follows
				l.newPage()
			}
			l.text(root.add(fmt.Sprintf("H%d", b.Level), ""), margin, fullW, lines, size, true, false)
			l.y -= h
		case Paragraph:
			size := bodySize
			if b.Small {
				size = noteSize
			}
			lines := l.wrap(b.Text, fullW, size, false)
			p := root.add("P", "")
			for len(lines) > 0 {
				fit := max(1, int((l.y-bottom)/(size*1.23)))
				if fit > len(lines) {
					fit = len(lines)
				}
				if l.y-size*1.23 < bottom {
					l.newPage()
					continue
				}
				l.text(p, margin, fullW, lines[:fit], size, false, false)
				l.y -= float64(fit) * size * 1.23
				lines = lines[fit:]
				if len(lines) > 0 {
					l.newPage()
				}
			}
			l.y -= 5
		case List:
			list := root.add("L", "/A <</O /List /ListNumbering /Disc>>")
			for _, it := range b.Items {
				lines := l.wrap(it, fullW-14, bodySize, false)
				h := float64(len(lines)) * bodySize * 1.23
				if l.y-h < bottom {
					l.newPage()
				}
				li := list.add("LI", "")
				l.text(li.add("Lbl", ""), margin+2, 10, []string{"•"}, bodySize, false, false)
				l.text(li.add("LBody", ""), margin+14, fullW-14, lines, bodySize, false, false)
				l.y -= h + 2
			}
			l.y -= 4
		case TableBlock:
			if b.Table == nil || len(b.Table.Columns) == 0 {
				return nil, fmt.Errorf("report: block %d: a table needs columns", bi)
			}
			l.table(root, b.Table, fullW, bottom)
		case FigureBlock:
			f := b.Figure
			if f == nil || strings.TrimSpace(f.Alt) == "" {
				return nil, fmt.Errorf("report: block %d: a figure needs alternative text", bi)
			}
			h := f.Height
			if h <= 0 {
				h = 200
			}
			h = min(h, pageH-2*margin-footerReserve-headerReserve-20)
			if l.y-h < bottom {
				l.newPage()
			}
			x0, y0 := margin, l.y-h
			fig := root.add("Figure", fmt.Sprintf("/Alt %s /A <</O /Layout /BBox [%.2f %.2f %.2f %.2f]>>", utf16String(clean(f.Alt)), x0, y0, x0+fullW, l.y))
			p := l.cur()
			mcid := len(p.mcids)
			p.mcids = append(p.mcids, fig)
			fig.kids = append(fig.kids, mcr{len(l.pages) - 1, mcid})
			fmt.Fprintf(&p.content, "/Figure <</MCID %d>> BDC\nq\n", mcid)
			if f.Draw != nil {
				c := &Canvas{l: l, X: x0, Y: y0, W: fullW, H: h}
				f.Draw(c)
				p.content.WriteString(c.ops.String())
			}
			p.content.WriteString("Q\nEMC\n")
			l.y = y0 - 4
			if f.Caption != "" {
				lines := l.wrap(f.Caption, fullW, noteSize, false)
				if l.y-float64(len(lines))*noteSize*1.23 < bottom {
					l.newPage()
				}
				l.text(root.add("P", ""), margin, fullW, lines, noteSize, false, false)
				l.y -= float64(len(lines))*noteSize*1.23 + 6
			}
		default:
			return nil, fmt.Errorf("report: block %d: unknown kind %q", bi, b.Kind)
		}
	}
	// The marking and page numbers, on every page.
	for i := range l.pages {
		var ops strings.Builder
		if l.marking != "" {
			ops.WriteString(l.artifactText(margin, pageH-margin-noteSize, l.marking, noteSize, true))
			ops.WriteString(l.artifactText(margin, margin-4, l.marking, 7, true))
		}
		label := fmt.Sprintf("Page %d of %d", i+1, len(l.pages))
		ops.WriteString(l.artifactText(pageW-margin-l.width(label, 7, false), margin-4, label, 7, false))
		fmt.Fprintf(&l.pages[i].content, "/Artifact BMC\n%sEMC\n", ops.String())
	}
	return d.write(root, l)
}

func (l *layout) table(root *elem, t *Table, tableW, bottom float64) {
	total := 0.0
	for _, c := range t.Columns {
		total += max(c.Weight, 0.0001)
	}
	widths := make([]float64, len(t.Columns))
	xs := make([]float64, len(t.Columns))
	x := margin
	for i, c := range t.Columns {
		widths[i] = tableW * max(c.Weight, 0.0001) / total
		xs[i] = x
		x += widths[i]
	}
	table := root.add("Table", "")
	if t.Caption != "" {
		lines := l.wrap(t.Caption, tableW, noteSize, true)
		if l.y-float64(len(lines))*noteSize*1.23-3*lineH < bottom {
			l.newPage()
		}
		l.text(table.add("Caption", ""), margin, tableW, lines, noteSize, true, false)
		l.y -= float64(len(lines))*noteSize*1.23 + 3
	}
	headLines := make([][]string, len(t.Columns))
	headH := 0.0
	if !t.NoHeader {
		for i, c := range t.Columns {
			headLines[i] = l.wrap(c.Title, widths[i]-2*padX, headSize, true)
			headH = max(headH, float64(len(headLines[i]))*lineH)
		}
		headH += 2 * padY
	}
	if l.y-headH-lineH-2*padY < bottom {
		l.newPage()
	}
	// The header row: content on the table's first page, an artifact when
	// repeated.
	header := func(tagged bool) {
		if t.NoHeader {
			return
		}
		l.y -= padY
		if tagged {
			tr := table.add("TR", "")
			for i := range t.Columns {
				th := tr.add("TH", "/A <</O /Table /Scope /Column>>")
				l.text(th, xs[i]+padX, widths[i]-2*padX, headLines[i], headSize, true, t.Columns[i].Right)
			}
		} else {
			var ops strings.Builder
			for i, c := range t.Columns {
				y := l.y - headSize
				for _, ln := range headLines[i] {
					lx := xs[i] + padX
					if c.Right {
						lx = xs[i] + widths[i] - padX - l.width(ln, headSize, true)
					}
					ops.WriteString(l.artifactText(lx, y, ln, headSize, true))
					y -= lineH
				}
			}
			l.artifact(ops.String())
		}
		l.y -= headH - padY
		l.artifact(fmt.Sprintf("0.5 g %.2f %.2f %.2f %.2f re f 0 g\n", margin, l.y, tableW, 0.6))
	}
	header(true)
	if len(t.Rows) == 0 {
		l.y -= padY
		l.text(root.add("P", ""), margin+padX, tableW, []string{"No rows."}, cellSize, false, false)
		l.y -= lineH + 6
		return
	}
	for _, row := range t.Rows {
		cells := make([][]string, len(t.Columns))
		h := 0.0
		for i := range t.Columns {
			v := ""
			if i < len(row) {
				v = row[i]
			}
			cells[i] = l.wrap(v, widths[i]-2*padX, cellSize, t.RowHeaders && i == 0)
			h = max(h, float64(len(cells[i]))*lineH)
		}
		h += 2 * padY
		if l.y-h < bottom {
			l.newPage()
			header(false)
		}
		tr := table.add("TR", "")
		top := l.y
		l.y -= padY
		for i, c := range t.Columns {
			typ, attrs := "TD", ""
			if t.RowHeaders && i == 0 {
				typ, attrs = "TH", "/A <</O /Table /Scope /Row>>"
			}
			l.text(tr.add(typ, attrs), xs[i]+padX, widths[i]-2*padX, cells[i], cellSize, typ == "TH", c.Right)
		}
		l.y = top - h
		l.artifact(fmt.Sprintf("0.75 g %.2f %.2f %.2f %.2f re f 0 g\n", margin, l.y, tableW, 0.4))
	}
	l.y -= 10
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

// pdfName escapes a PDF name.
func pdfLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('(')
	for _, r := range s {
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r >= 32 && r < 127:
			b.WriteRune(r)
		}
	}
	b.WriteByte(')')
	return b.String()
}

type writer struct {
	buf     bytes.Buffer
	offsets []int
	next    int
}

func (w *writer) alloc() int {
	w.next++
	return w.next
}

func (w *writer) obj(n int, body string) {
	for len(w.offsets) <= n {
		w.offsets = append(w.offsets, 0)
	}
	w.offsets[n] = w.buf.Len()
	fmt.Fprintf(&w.buf, "%d 0 obj\n%s\nendobj\n", n, body)
}

// stream writes a stream object, compressed unless raw.
func (w *writer) stream(n int, dict string, data []byte, raw bool) {
	if !raw {
		var z bytes.Buffer
		zw, _ := zlib.NewWriterLevel(&z, zlib.BestCompression)
		_, _ = zw.Write(data)
		_ = zw.Close()
		data = z.Bytes()
		dict += " /Filter /FlateDecode"
	}
	for len(w.offsets) <= n {
		w.offsets = append(w.offsets, 0)
	}
	w.offsets[n] = w.buf.Len()
	fmt.Fprintf(&w.buf, "%d 0 obj\n<< %s /Length %d >>\nstream\n", n, dict, len(data))
	w.buf.Write(data)
	w.buf.WriteString("\nendstream\nendobj\n")
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

func (d Doc) write(root *elem, l *layout) ([]byte, error) {
	w := &writer{}
	catalog, pages, info, structRoot, parentTree, meta := w.alloc(), w.alloc(), w.alloc(), w.alloc(), w.alloc(), w.alloc()
	fontObj := [2]int{w.alloc(), w.alloc()}
	pageObj := make([]int, len(l.pages))
	contentObj := make([]int, len(l.pages))
	for i := range l.pages {
		pageObj[i], contentObj[i] = w.alloc(), w.alloc()
	}
	var all []*elem
	var number func(e *elem)
	number = func(e *elem) {
		e.obj = w.alloc()
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

	w.buf.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	w.obj(catalog, fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R /StructTreeRoot %d 0 R /MarkInfo << /Marked true >> /Lang %s "+
		"/Metadata %d 0 R /ViewerPreferences << /DisplayDocTitle true >> >>", pages, structRoot, pdfLiteral(d.Lang), meta))
	kids := make([]string, len(pageObj))
	for i, n := range pageObj {
		kids[i] = fmt.Sprintf("%d 0 R", n)
	}
	w.obj(pages, fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>", len(pageObj), strings.Join(kids, " ")))
	created := d.Created.UTC()
	w.obj(info, fmt.Sprintf("<< /Title %s /Author %s /Subject %s /Creator %s /Producer %s /CreationDate (D:%sZ) >>",
		utf16String(d.Title), utf16String(d.Author), utf16String(d.Subject), utf16String("FAIR platform"), utf16String("FAIR report writer"),
		created.Format("20060102150405")))
	xmp := fmt.Sprintf(`<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:pdf="http://ns.adobe.com/pdf/1.3/" xmlns:pdfuaid="http://www.aiim.org/pdfua/ns/id/">
<dc:title><rdf:Alt><rdf:li xml:lang="x-default">%s</rdf:li></rdf:Alt></dc:title>
<dc:creator><rdf:Seq><rdf:li>%s</rdf:li></rdf:Seq></dc:creator>
<dc:format>application/pdf</dc:format>
<xmp:CreateDate>%s</xmp:CreateDate>
<xmp:CreatorTool>FAIR platform</xmp:CreatorTool>
<pdf:Producer>FAIR report writer</pdf:Producer>
<pdfuaid:part>1</pdfuaid:part>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>`, xmlEscape(d.Title), xmlEscape(d.Author), created.Format(time.RFC3339))
	w.stream(meta, "/Type /Metadata /Subtype /XML", []byte(xmp), true)
	w.obj(structRoot, fmt.Sprintf("<< /Type /StructTreeRoot /K %d 0 R /ParentTree %d 0 R /ParentTreeNextKey %d >>", root.obj, parentTree, len(l.pages)))
	var nums strings.Builder
	for i, p := range l.pages {
		refs := make([]string, len(p.mcids))
		for j, e := range p.mcids {
			refs[j] = fmt.Sprintf("%d 0 R", e.obj)
		}
		fmt.Fprintf(&nums, "%d [%s] ", i, strings.Join(refs, " "))
	}
	w.obj(parentTree, fmt.Sprintf("<< /Nums [%s] >>", strings.TrimSpace(nums.String())))
	for i, p := range l.pages {
		w.obj(pageObj[i], fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.0f %.0f] /Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> "+
			"/Contents %d 0 R /StructParents %d /Tabs /S >>", pages, pageW, pageH, fontObj[0], fontObj[1], contentObj[i], i))
		w.stream(contentObj[i], "", p.content.Bytes(), false)
	}
	for i, f := range []*font{l.reg, l.bold} {
		w.font(fontObj[i], f, l.used[i])
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
		p := structRoot
		if n, ok := parent[e]; ok {
			p = n
		}
		attrs := ""
		if e.attrs != "" {
			attrs = " " + e.attrs
		}
		w.obj(e.obj, fmt.Sprintf("<< /Type /StructElem /S /%s /P %d 0 R /K [%s]%s >>", e.typ, p, strings.Join(k, " "), attrs))
	}
	size := w.next + 1
	xref := w.buf.Len()
	fmt.Fprintf(&w.buf, "xref\n0 %d\n0000000000 65535 f \n", size)
	for i := 1; i < size; i++ {
		fmt.Fprintf(&w.buf, "%010d 00000 n \n", w.offsets[i])
	}
	fmt.Fprintf(&w.buf, "trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", size, catalog, info, xref)
	return w.buf.Bytes(), nil
}

// font writes a Type0 font over a CIDFontType2 with the whole TrueType
// program embedded, the widths of the glyphs used and a ToUnicode map.
func (w *writer) font(n int, f *font, used map[uint16]rune) {
	cid, desc, file, tu := w.alloc(), w.alloc(), w.alloc(), w.alloc()
	scale := func(v int) int { return v * 1000 / f.unitsPerEm }
	gids := make([]uint16, 0, len(used))
	for g := range used {
		gids = append(gids, g)
	}
	slices.Sort(gids)
	var wa strings.Builder
	for _, g := range gids {
		fmt.Fprintf(&wa, "%d [%d] ", g, scale(f.advance[g]))
	}
	w.obj(n, fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /%s /Encoding /Identity-H /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>", f.name, cid, tu))
	w.obj(cid, fmt.Sprintf("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /%s /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "+
		"/FontDescriptor %d 0 R /DW %d /W [%s] /CIDToGIDMap /Identity >>", f.name, desc, scale(f.advance[0]), strings.TrimSpace(wa.String())))
	w.obj(desc, fmt.Sprintf("<< /Type /FontDescriptor /FontName /%s /Flags 32 /FontBBox [%d %d %d %d] /ItalicAngle %.1f /Ascent %d /Descent %d "+
		"/CapHeight %d /StemV 80 /FontFile2 %d 0 R >>", f.name, scale(f.bbox[0]), scale(f.bbox[1]), scale(f.bbox[2]), scale(f.bbox[3]),
		f.italicAngle, scale(f.ascent), scale(f.descent), scale(f.capHeight), file))
	w.stream(file, fmt.Sprintf("/Length1 %d", len(f.data)), f.data, false)
	var cm strings.Builder
	cm.WriteString("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n" +
		"/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n")
	for i := 0; i < len(gids); i += 100 {
		chunk := gids[i:min(i+100, len(gids))]
		fmt.Fprintf(&cm, "%d beginbfchar\n", len(chunk))
		for _, g := range chunk {
			fmt.Fprintf(&cm, "<%04X> <%s\n", g, strings.TrimPrefix(utf16String(string(used[g])), "<FEFF"))
		}
		cm.WriteString("endbfchar\n")
	}
	cm.WriteString("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n")
	w.stream(tu, "", []byte(cm.String()), false)
}
