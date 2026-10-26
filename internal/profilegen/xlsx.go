package profilegen

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// readSheet returns the cells of one worksheet of an .xlsx file as rows of
// column-letter -> text. It handles shared and inline strings, which is all
// NIST's change-analysis workbook uses; it is not a general xlsx reader.
func readSheet(file, sheet string) ([]map[string]string, error) {
	z, err := zip.OpenReader(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = z.Close() }()
	read := func(name string) ([]byte, error) {
		for _, f := range z.File {
			if f.Name == name {
				r, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer func() { _ = r.Close() }()
				return io.ReadAll(io.LimitReader(r, 64<<20))
			}
		}
		return nil, fmt.Errorf("xlsx: %s has no %s", file, name)
	}

	var shared []string
	if b, err := read("xl/sharedStrings.xml"); err == nil {
		var sst struct {
			SI []struct {
				Inner []byte `xml:",innerxml"`
			} `xml:"si"`
		}
		if err := xml.Unmarshal(b, &sst); err != nil {
			return nil, err
		}
		for _, si := range sst.SI {
			shared = append(shared, textOf(si.Inner))
		}
	}

	wb, err := read("xl/workbook.xml")
	if err != nil {
		return nil, err
	}
	var workbook struct {
		Sheets []struct {
			Name string `xml:"name,attr"`
			RID  string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/relationships id,attr"`
		} `xml:"sheets>sheet"`
	}
	if err := xml.Unmarshal(wb, &workbook); err != nil {
		return nil, err
	}
	rb, err := read("xl/_rels/workbook.xml.rels")
	if err != nil {
		return nil, err
	}
	var rels struct {
		Rel []struct {
			ID     string `xml:"Id,attr"`
			Target string `xml:"Target,attr"`
		} `xml:"Relationship"`
	}
	if err := xml.Unmarshal(rb, &rels); err != nil {
		return nil, err
	}
	var target string
	for _, s := range workbook.Sheets {
		if s.Name != sheet {
			continue
		}
		for _, r := range rels.Rel {
			if r.ID == s.RID {
				target = strings.TrimPrefix(r.Target, "/")
				if !strings.HasPrefix(target, "xl/") {
					target = path.Join("xl", target)
				}
			}
		}
	}
	if target == "" {
		return nil, fmt.Errorf("xlsx: %s has no sheet %q", file, sheet)
	}
	sb, err := read(target)
	if err != nil {
		return nil, err
	}
	var ws struct {
		Rows []struct {
			Cells []struct {
				Ref    string `xml:"r,attr"`
				Type   string `xml:"t,attr"`
				Value  string `xml:"v"`
				Inline struct {
					Inner []byte `xml:",innerxml"`
				} `xml:"is"`
			} `xml:"c"`
		} `xml:"sheetData>row"`
	}
	if err := xml.Unmarshal(sb, &ws); err != nil {
		return nil, err
	}
	col := regexp.MustCompile(`^[A-Z]+`)
	var out []map[string]string
	for _, row := range ws.Rows {
		cells := map[string]string{}
		for _, c := range row.Cells {
			var v string
			switch c.Type {
			case "s":
				i, err := strconv.Atoi(c.Value)
				if err != nil || i < 0 || i >= len(shared) {
					return nil, fmt.Errorf("xlsx: bad shared string %q at %s", c.Value, c.Ref)
				}
				v = shared[i]
			case "inlineStr":
				v = textOf(c.Inline.Inner)
			default:
				v = c.Value
			}
			cells[col.FindString(c.Ref)] = v
		}
		out = append(out, cells)
	}
	return out, nil
}

// textOf concatenates the <t> runs of a rich-text fragment.
func textOf(inner []byte) string {
	dec := xml.NewDecoder(strings.NewReader("<x>" + string(inner) + "</x>"))
	var b strings.Builder
	inT := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			inT = t.Name.Local == "t"
		case xml.EndElement:
			inT = false
		case xml.CharData:
			if inT {
				b.Write(t)
			}
		}
	}
	return b.String()
}
