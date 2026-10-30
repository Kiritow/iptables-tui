package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"unicode"
)

// Color is one of the 16 basic ANSI colors, or cDefault.
type Color int8

const (
	cDefault Color = -1
	cBlack   Color = 0
	cRed     Color = 1
	cGreen   Color = 2
	cYellow  Color = 3
	cBlue    Color = 4
	cMagenta Color = 5
	cCyan    Color = 6
	cWhite   Color = 7
	cGray    Color = 8
)

const (
	AttrBold uint8 = 1 << iota
	AttrDim
	AttrUnderline
	AttrReverse
)

type Style struct {
	Fg, Bg Color
	Attr   uint8
}

var stDefault = Style{Fg: cDefault, Bg: cDefault}

func fg(c Color) Style               { return Style{Fg: c, Bg: cDefault} }
func (s Style) with(a uint8) Style   { s.Attr |= a; return s }
func (s Style) withBg(c Color) Style { s.Bg = c; return s }

func (s Style) sgr() string {
	var b strings.Builder
	b.WriteString("\x1b[0")
	if s.Attr&AttrBold != 0 {
		b.WriteString(";1")
	}
	if s.Attr&AttrDim != 0 {
		b.WriteString(";2")
	}
	if s.Attr&AttrUnderline != 0 {
		b.WriteString(";4")
	}
	if s.Attr&AttrReverse != 0 {
		b.WriteString(";7")
	}
	if s.Fg >= 0 {
		if s.Fg < 8 {
			b.WriteString(";3" + strconv.Itoa(int(s.Fg)))
		} else {
			b.WriteString(";9" + strconv.Itoa(int(s.Fg-8)))
		}
	}
	if s.Bg >= 0 {
		if s.Bg < 8 {
			b.WriteString(";4" + strconv.Itoa(int(s.Bg)))
		} else {
			b.WriteString(";10" + strconv.Itoa(int(s.Bg-8)))
		}
	}
	b.WriteByte('m')
	return b.String()
}

// cell is one terminal column. A wide rune occupies a head cell (w == 2)
// followed by a continuation cell (w == 0).
type cell struct {
	r  rune
	w  int8
	st Style
}

// Screen is a double-buffered cell grid; Flush only rewrites rows that changed.
type Screen struct {
	w, h       int
	cells      []cell
	prev       []string
	out        *bufio.Writer
	curX, curY int
	curOn      bool
}

func newScreen(f *os.File) *Screen {
	return &Screen{out: bufio.NewWriterSize(f, 64*1024)}
}

func (s *Screen) Resize(w, h int) {
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	s.w, s.h = w, h
	s.cells = make([]cell, w*h)
	s.Invalidate()
}

// Invalidate forces a full repaint on the next Flush.
func (s *Screen) Invalidate() {
	s.prev = make([]string, s.h)
	s.out.WriteString("\x1b[0m\x1b[2J")
}

func (s *Screen) Clear() {
	for i := range s.cells {
		s.cells[i] = cell{r: ' ', w: 1, st: stDefault}
	}
	s.curOn = false
}

func (s *Screen) SetCursor(x, y int) { s.curX, s.curY, s.curOn = x, y, true }

func (s *Screen) set(x, y int, r rune, w int, st Style) {
	if y < 0 || y >= s.h || x < 0 || x+w > s.w {
		return
	}
	s.breakWide(x, y)
	if w == 2 {
		s.breakWide(x+1, y)
	}
	i := y*s.w + x
	s.cells[i] = cell{r: r, w: int8(w), st: st}
	if w == 2 {
		s.cells[i+1] = cell{r: 0, w: 0, st: st}
	}
}

// breakWide blanks the other half of a wide rune that is about to be overwritten.
func (s *Screen) breakWide(x, y int) {
	i := y*s.w + x
	c := s.cells[i]
	if c.w == 0 && x > 0 {
		s.cells[i-1] = cell{r: ' ', w: 1, st: s.cells[i-1].st}
	}
	if c.w == 2 && x+1 < s.w {
		s.cells[i+1] = cell{r: ' ', w: 1, st: c.st}
	}
}

// Text draws str at (x, y), clipped to columns [x, maxX). It returns the column
// after the last cell drawn.
func (s *Screen) Text(x, y, maxX int, str string, st Style) int {
	if maxX > s.w {
		maxX = s.w
	}
	for _, r := range str {
		if x >= maxX {
			break
		}
		r = sanitizeRune(r)
		w := runeWidth(r)
		if w == 0 {
			continue
		}
		if x+w > maxX {
			for ; x < maxX; x++ {
				s.set(x, y, ' ', 1, st)
			}
			break
		}
		s.set(x, y, r, w, st)
		x += w
	}
	return x
}

func (s *Screen) Fill(x, y, w, h int, r rune, st Style) {
	for yy := y; yy < y+h; yy++ {
		for xx := x; xx < x+w; xx++ {
			s.set(xx, yy, r, 1, st)
		}
	}
}

func (s *Screen) Flush() {
	var b strings.Builder
	for y := 0; y < s.h; y++ {
		b.Reset()
		last := Style{Fg: -2}
		row := s.cells[y*s.w : (y+1)*s.w]
		for _, c := range row {
			if c.w == 0 {
				continue
			}
			if c.st != last {
				b.WriteString(c.st.sgr())
				last = c.st
			}
			b.WriteRune(c.r)
		}
		line := b.String()
		if line != s.prev[y] {
			s.out.WriteString("\x1b[" + strconv.Itoa(y+1) + ";1H")
			s.out.WriteString(line)
			s.prev[y] = line
		}
	}
	s.out.WriteString("\x1b[0m")
	if s.curOn {
		s.out.WriteString("\x1b[" + strconv.Itoa(s.curY+1) + ";" + strconv.Itoa(s.curX+1) + "H\x1b[?25h")
	} else {
		s.out.WriteString("\x1b[?25l")
	}
	s.out.Flush()
}

func sanitizeRune(r rune) rune {
	switch {
	case r == '\t':
		return ' '
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
		return '?'
	}
	return r
}

var wideRanges = [][2]rune{
	{0x1100, 0x115F}, {0x2E80, 0x303E}, {0x3041, 0x33FF}, {0x3400, 0x4DBF},
	{0x4E00, 0x9FFF}, {0xA000, 0xA4CF}, {0xAC00, 0xD7A3}, {0xF900, 0xFAFF},
	{0xFE30, 0xFE4F}, {0xFF00, 0xFF60}, {0xFFE0, 0xFFE6}, {0x1F300, 0x1F64F},
	{0x1F900, 0x1F9FF}, {0x20000, 0x2FFFD}, {0x30000, 0x3FFFD},
}

// runeWidth approximates the terminal column width of r (East Asian wide = 2,
// combining marks = 0).
func runeWidth(r rune) int {
	if r < 0x300 {
		return 1
	}
	if r == 0x200B || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
		return 0
	}
	for _, rg := range wideRanges {
		if r < rg[0] {
			break
		}
		if r <= rg[1] {
			return 2
		}
	}
	return 1
}

func cellWidth(r rune) int { return runeWidth(sanitizeRune(r)) }

func strWidth(s string) int {
	n := 0
	for _, r := range s {
		n += cellWidth(r)
	}
	return n
}

// splitWidth returns the longest prefix of s that fits in w columns, and the rest.
func splitWidth(s string, w int) (string, string) {
	n := 0
	for i, r := range s {
		rw := cellWidth(r)
		if n+rw > w {
			return s[:i], s[i:]
		}
		n += rw
	}
	return s, ""
}

// fit truncates s to w columns, marking truncation with an ellipsis.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if strWidth(s) <= w {
		return s
	}
	head, _ := splitWidth(s, w-1)
	return head + "…"
}

func pad(s string, w int) string {
	s = fit(s, w)
	if n := strWidth(s); n < w {
		s += strings.Repeat(" ", w-n)
	}
	return s
}

func lpad(s string, w int) string {
	s = fit(s, w)
	if n := strWidth(s); n < w {
		s = strings.Repeat(" ", w-n) + s
	}
	return s
}

// wrapText word-wraps s to width columns. Continuation lines keep the
// paragraph's indentation plus two spaces; overlong words are hard-split.
func wrapText(s string, width int) []string {
	if width < 4 {
		width = 4
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		if strWidth(para) <= width {
			out = append(out, strings.TrimRight(para, " "))
			continue
		}
		trimmed := strings.TrimLeft(para, " ")
		indent := para[:len(para)-len(trimmed)]
		if len(indent) > width/2 {
			indent = ""
		}
		cont := indent + "  "
		if len(cont) > width/2 {
			cont = ""
		}
		words := strings.Fields(trimmed)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		line, lineW, empty := indent, len(indent), true
		for _, word := range words {
			ww := strWidth(word)
			if !empty && lineW+1+ww > width {
				out = append(out, line)
				line, lineW, empty = cont, len(cont), true
			}
			if !empty {
				line += " "
				lineW++
			}
			for lineW+ww > width {
				head, rest := splitWidth(word, width-lineW)
				if head == "" {
					_, size := firstRune(word)
					head, rest = word[:size], word[size:]
				}
				out = append(out, line+head)
				line, lineW = cont, len(cont)
				word, ww = rest, strWidth(rest)
			}
			line += word
			lineW += ww
			empty = false
		}
		out = append(out, line)
	}
	return out
}

func firstRune(s string) (rune, int) {
	for i, r := range s {
		if i == 0 {
			return r, len(string(r))
		}
	}
	return 0, len(s)
}
