package chart

import (
	"math"
	"strconv"
	"strings"

	"github.com/rformer/fair-app/internal/report"
	"github.com/rformer/fair-app/internal/reports/doc"
)

// Style is a series' look (ADR-014's light-theme tokens --series-1 to -6).
type Style struct {
	R, G, B float64
	Dash    []float64
	Marker  string
}

func hex(s string) (float64, float64, float64) {
	v, _ := strconv.ParseUint(strings.TrimPrefix(s, "#"), 16, 32)
	return float64(v>>16&0xff) / 255, float64(v>>8&0xff) / 255, float64(v&0xff) / 255
}

// Styles follow web/src/charts/palette.ts and styles.css (light theme).
var Styles = func() []Style {
	colours := []string{"#0b57c4", "#b4400c", "#04704f", "#7e22ce", "#8a5a00", "#b0175a"}
	dashes := [][]float64{nil, {8, 4}, {2, 4}, {10, 3, 2, 3}, {4, 2}, {1, 3, 6, 3}}
	markers := []string{"circle", "square", "triangle", "diamond", "cross", "bar"}
	out := make([]Style, len(colours))
	for i, c := range colours {
		r, g, b := hex(c)
		out[i] = Style{R: r, G: g, B: b, Dash: dashes[i], Marker: markers[i]}
	}
	return out
}()

// Plot margins inside a figure's box, in points.
const (
	padLeft, padRight, padBottom, padTop = 58.0, 14.0, 30.0, 22.0
	tickSize, labelSize                  = 6.5, 7.0
)

// Draw returns the drawing of a report chart, or nil when its data cannot
// be drawn (the figure then stays blank; its data table and alternative text
// still carry it).
func Draw(ch *doc.Chart) func(*report.Canvas) {
	if ch == nil || ch.Data == nil || len(ch.Data.Rows) == 0 {
		return nil
	}
	col := map[string]int{}
	for i, c := range ch.Data.Columns {
		col[c.Key] = i
	}
	xi, ok := col[ch.XKey]
	if !ok {
		return nil
	}
	ys := make([]int, 0, len(ch.Series))
	for _, s := range ch.Series {
		i, ok := col[s.ID]
		if !ok {
			return nil
		}
		ys = append(ys, i)
	}
	num := func(r []string, i int) (float64, bool) {
		if i >= len(r) || r[i] == "" {
			return 0, false
		}
		v, err := strconv.ParseFloat(r[i], 64)
		return v, err == nil && !math.IsInf(v, 0) && !math.IsNaN(v)
	}
	yType := ch.Data.Columns[ys[0]].Type
	switch ch.Kind {
	case doc.ChartExceedance:
		return func(c *report.Canvas) { exceedance(c, ch, xi, ys, num) }
	case doc.ChartHistogram:
		return func(c *report.Canvas) { histogram(c, ch, xi, ys[0], yType, num) }
	case doc.ChartBars:
		return func(c *report.Canvas) { bars(c, ch, xi, ys[0], yType, num) }
	}
	return nil
}

type numFn func([]string, int) (float64, bool)

func axes(c *report.Canvas) (x0, y0, w, h float64) {
	x0, y0 = padLeft, padBottom
	w, h = c.W-padLeft-padRight, c.H-padBottom-padTop
	c.Stroke(0.25, 0.25, 0.25, 0.6)
	c.Line(x0, y0+h, x0, y0, x0+w, y0)
	return
}

func grid(c *report.Canvas, x0, y0, w, h float64, xs, ys []float64) {
	c.Stroke(0.85, 0.85, 0.85, 0.4)
	for _, x := range xs {
		c.Line(x, y0, x, y0+h)
	}
	for _, y := range ys {
		c.Line(x0, y, x0+w, y)
	}
}

func legend(c *report.Canvas, ch *doc.Chart) {
	x := padLeft
	for i, s := range ch.Series {
		st := Styles[i%len(Styles)]
		c.Stroke(st.R, st.G, st.B, 1.4, st.Dash...)
		c.Line(x, c.H-10, x+18, c.H-10)
		c.Fill(st.R, st.G, st.B)
		c.Marker(st.Marker, x+9, c.H-10, 4)
		c.Fill(0, 0, 0)
		c.Text(x+22, c.H-12.5, s.Name, labelSize, false, "left")
		x += 30 + c.TextWidth(s.Name, labelSize, false)
	}
}

func exceedance(c *report.Canvas, ch *doc.Chart, xi int, ys []int, num numFn) {
	x0, y0, w, h := axes(c)
	lo, hi := math.Inf(1), math.Inf(-1)
	for _, r := range ch.Data.Rows {
		if v, ok := num(r, xi); ok && (!ch.Log || v > 0) {
			lo, hi = math.Min(lo, v), math.Max(hi, v)
		}
	}
	if math.IsInf(lo, 0) {
		return
	}
	xs := Linear([2]float64{math.Min(0, lo), hi}, [2]float64{x0, x0 + w})
	if ch.Log {
		if s, ok := LogScale([2]float64{lo, hi}, [2]float64{x0, x0 + w}); ok {
			xs = s
		}
	}
	yscale := Linear([2]float64{0, 1}, [2]float64{y0, y0 + h})
	xt, yt := xs.Ticks(6), yscale.Ticks(5)
	xp, yp := make([]float64, len(xt)), make([]float64, len(yt))
	for i, t := range xt {
		xp[i] = xs.Map(t)
	}
	for i, t := range yt {
		yp[i] = yscale.Map(t)
	}
	grid(c, x0, y0, w, h, xp, yp)
	c.Fill(0, 0, 0)
	for i, t := range xt {
		c.Text(xp[i], y0-10, Compact(t), tickSize, false, "center")
	}
	for i, t := range yt {
		c.Text(x0-4, yp[i]-2, Percent(t), tickSize, false, "right")
	}
	c.Text(x0+w/2, y0-22, ch.Data.Columns[xi].Title, labelSize, true, "center")
	for si, yi := range ys {
		st := Styles[si%len(Styles)]
		var pts []float64
		for _, r := range ch.Data.Rows {
			x, okx := num(r, xi)
			y, oky := num(r, yi)
			if okx && oky && (!ch.Log || x > 0) {
				pts = append(pts, xs.Map(x), yscale.Map(y))
			}
		}
		if len(pts) < 4 {
			continue
		}
		c.Stroke(st.R, st.G, st.B, 1.4, st.Dash...)
		c.Line(pts...)
		c.Fill(st.R, st.G, st.B)
		step := max(1, len(pts)/2/12) // about a dozen markers
		for i := 0; i < len(pts)/2; i += step {
			c.Marker(st.Marker, pts[2*i], pts[2*i+1], 3.5)
		}
	}
	c.Fill(0, 0, 0)
	legend(c, ch)
}

func valueLabel(t float64, typ string) string {
	if typ == doc.ColPercent {
		return Percent(t)
	}
	return Compact(t)
}

func histogram(c *report.Canvas, ch *doc.Chart, xi, yi int, yType string, num numFn) {
	x0, y0, w, h := axes(c)
	type bin struct{ x, y float64 }
	var bins []bin
	for _, r := range ch.Data.Rows {
		x, okx := num(r, xi)
		y, oky := num(r, yi)
		if okx && oky {
			bins = append(bins, bin{x, y})
		}
	}
	if len(bins) == 0 {
		return
	}
	width := 1.0
	if len(bins) > 1 {
		width = bins[1].x - bins[0].x
	}
	top := 0.0
	for _, b := range bins {
		top = math.Max(top, b.y)
	}
	xs := Linear([2]float64{bins[0].x, bins[len(bins)-1].x + width}, [2]float64{x0, x0 + w})
	if step := NiceStep(top, 5); top > 0 {
		top = math.Ceil(top/step-1e-9) * step // the top tick above the tallest bar
	}
	yscale := Linear([2]float64{0, top}, [2]float64{y0, y0 + h})
	xt, yt := xs.Ticks(6), yscale.Ticks(5)
	var xp, yp []float64
	for _, t := range xt {
		xp = append(xp, xs.Map(t))
	}
	for _, t := range yt {
		yp = append(yp, yscale.Map(t))
	}
	grid(c, x0, y0, w, h, nil, yp)
	st := Styles[0]
	c.Fill(st.R, st.G, st.B)
	c.Stroke(1, 1, 1, 0.5)
	for i, b := range bins {
		next := b.x + width
		if i+1 < len(bins) {
			next = bins[i+1].x
		}
		l, r := xs.Map(b.x), xs.Map(next)
		c.Rect(l, y0, math.Max(r-l, 0.5), yscale.Map(b.y)-y0, true)
	}
	c.Fill(0, 0, 0)
	for i, t := range xt {
		c.Text(xp[i], y0-10, Compact(t), tickSize, false, "center")
	}
	for i, t := range yt {
		c.Text(x0-4, yp[i]-2, valueLabel(t, yType), tickSize, false, "right")
	}
	c.Text(x0+w/2, y0-22, ch.Data.Columns[xi].Title, labelSize, true, "center")
	legend(c, ch)
}

func bars(c *report.Canvas, ch *doc.Chart, li, vi int, vType string, num numFn) {
	type bar struct {
		label string
		v     float64
	}
	var bs []bar
	for _, r := range ch.Data.Rows {
		if v, ok := num(r, vi); ok && li < len(r) {
			bs = append(bs, bar{r[li], v})
		}
	}
	if len(bs) == 0 {
		return
	}
	labelW := 150.0
	x0, y0 := labelW, 18.0
	w, h := c.W-labelW-60, c.H-y0-padTop
	lo, hi := 0.0, 0.0
	for _, b := range bs {
		lo, hi = math.Min(lo, b.v), math.Max(hi, b.v)
	}
	xs := Linear([2]float64{lo, hi}, [2]float64{x0, x0 + w})
	rowH := math.Min(16, h/float64(len(bs)))
	st := Styles[0]
	for i, b := range bs {
		y := y0 + h - float64(i+1)*rowH
		label := b.label
		for c.TextWidth(label, labelSize, false) > labelW-8 && len([]rune(label)) > 2 {
			rs := []rune(label)
			label = string(rs[:len(rs)-2]) + "…"
		}
		c.Fill(0, 0, 0)
		c.Text(x0-6, y+rowH*0.3, label, labelSize, false, "right")
		c.Fill(st.R, st.G, st.B)
		l, r := xs.Map(math.Min(0, b.v)), xs.Map(math.Max(0, b.v))
		c.Rect(l, y+rowH*0.15, math.Max(r-l, 0.5), rowH*0.7, false)
		c.Fill(0, 0, 0)
		c.Text(r+4, y+rowH*0.3, valueLabel(b.v, vType), tickSize, false, "left")
	}
	c.Stroke(0.25, 0.25, 0.25, 0.6)
	c.Line(xs.Map(0), y0, xs.Map(0), y0+h)
	legend(c, ch)
}

// Compact formats an amount with three significant digits and a K, M, B or
// T suffix ("2.1M"), as the app's compact notation does.
func Compact(v float64) string {
	a := math.Abs(v)
	units := []struct {
		f float64
		s string
	}{{1e12, "T"}, {1e9, "B"}, {1e6, "M"}, {1e3, "K"}, {1, ""}}
	for _, u := range units {
		if a >= u.f || u.f == 1 {
			x := v / u.f
			s := strconv.FormatFloat(sig3(x), 'f', -1, 64)
			return s + u.s
		}
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func sig3(x float64) float64 {
	if x == 0 {
		return 0
	}
	d := 3 - int(math.Floor(math.Log10(math.Abs(x)))) - 1
	p := math.Pow(10, float64(d))
	return math.Round(x*p) / p
}

// Percent formats a probability with two significant digits ("10%",
// "1.2%"); tiny ones as "<0.01%".
func Percent(p float64) string {
	if p > 0 && p < 0.0001 {
		return "<0.01%"
	}
	v := p * 100
	if v == 0 {
		return "0%"
	}
	d := max(0, 2-int(math.Floor(math.Log10(math.Abs(v))))-1)
	return strconv.FormatFloat(math.Round(v*math.Pow(10, float64(d)))/math.Pow(10, float64(d)), 'f', -1, 64) + "%"
}
