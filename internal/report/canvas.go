package report

import (
	"fmt"
	"strings"
)

// Canvas draws a figure (F-010 ADR-015) into its box: X, Y is the box's
// lower left corner on the page, W and H its size, in points. Everything
// drawn is part of the figure's marked content; its text uses the embedded
// fonts. Colours are 0 to 1 per channel.
type Canvas struct {
	l          *layout
	ops        strings.Builder
	X, Y, W, H float64
}

// Save saves the graphics state.
func (c *Canvas) Save() { c.ops.WriteString("q\n") }

// Restore restores the graphics state Save saved.
func (c *Canvas) Restore() { c.ops.WriteString("Q\n") }

// Stroke sets the stroke colour, the line width and a dash pattern (none
// for a solid line).
func (c *Canvas) Stroke(r, g, b, width float64, dash ...float64) {
	ds := make([]string, len(dash))
	for i, d := range dash {
		ds[i] = fmt.Sprintf("%.2f", d)
	}
	fmt.Fprintf(&c.ops, "%.3f %.3f %.3f RG %.2f w [%s] 0 d\n", r, g, b, width, strings.Join(ds, " "))
}

// Fill sets the fill colour.
func (c *Canvas) Fill(r, g, b float64) { fmt.Fprintf(&c.ops, "%.3f %.3f %.3f rg\n", r, g, b) }

// Line strokes a polyline through the points (x0, y0, x1, y1, ...),
// relative to the box.
func (c *Canvas) Line(pts ...float64) {
	for i := 0; i+1 < len(pts); i += 2 {
		op := "l"
		if i == 0 {
			op = "m"
		}
		fmt.Fprintf(&c.ops, "%.2f %.2f %s\n", c.X+pts[i], c.Y+pts[i+1], op)
	}
	c.ops.WriteString("S\n")
}

// Rect fills (and, with stroke, outlines) a rectangle relative to the box.
func (c *Canvas) Rect(x, y, w, h float64, stroke bool) {
	op := "f"
	if stroke {
		op = "B"
	}
	fmt.Fprintf(&c.ops, "%.2f %.2f %.2f %.2f re %s\n", c.X+x, c.Y+y, w, h, op)
}

// Marker draws a small square, triangle or circle centred at x, y.
func (c *Canvas) Marker(shape string, x, y, size float64) {
	x, y, s := c.X+x, c.Y+y, size/2
	switch shape {
	case "triangle":
		fmt.Fprintf(&c.ops, "%.2f %.2f m %.2f %.2f l %.2f %.2f l h f\n", x, y+s, x-s, y-s, x+s, y-s)
	case "diamond":
		fmt.Fprintf(&c.ops, "%.2f %.2f m %.2f %.2f l %.2f %.2f l %.2f %.2f l h f\n", x, y+s, x-s, y, x, y-s, x+s, y)
	case "cross":
		fmt.Fprintf(&c.ops, "%.2f %.2f m %.2f %.2f l %.2f %.2f m %.2f %.2f l S\n", x-s, y-s, x+s, y+s, x-s, y+s, x+s, y-s)
	case "bar":
		fmt.Fprintf(&c.ops, "%.2f %.2f %.2f %.2f re f\n", x-s/3, y-s, 2*s/3, size)
	case "circle":
		k := s * 0.5523 // four Béziers
		fmt.Fprintf(&c.ops, "%.2f %.2f m %.2f %.2f %.2f %.2f %.2f %.2f c %.2f %.2f %.2f %.2f %.2f %.2f c %.2f %.2f %.2f %.2f %.2f %.2f c %.2f %.2f %.2f %.2f %.2f %.2f c f\n",
			x+s, y, x+s, y+k, x+k, y+s, x, y+s, x-k, y+s, x-s, y+k, x-s, y, x-s, y-k, x-k, y-s, x, y-s, x+k, y-s, x+s, y-k, x+s, y)
	default:
		fmt.Fprintf(&c.ops, "%.2f %.2f %.2f %.2f re f\n", x-s, y-s, size, size)
	}
}

// Text draws s at x, y (its baseline) relative to the box; align is
// "left", "center" or "right" of x.
func (c *Canvas) Text(x, y float64, s string, size float64, bold bool, align string) {
	s = clean(s)
	w := c.l.width(s, size, bold)
	switch align {
	case "center":
		x -= w / 2
	case "right":
		x -= w
	}
	fmt.Fprintf(&c.ops, "BT /%s %.1f Tf 1 0 0 1 %.2f %.2f Tm %s Tj ET\n", fontRes(bold), size, c.X+x, c.Y+y, c.l.enc(s, bold))
}

// TextWidth is the width of s at size.
func (c *Canvas) TextWidth(s string, size float64, bold bool) float64 {
	return c.l.width(clean(s), size, bold)
}
