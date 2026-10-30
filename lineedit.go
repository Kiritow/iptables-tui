package main

// LineEdit is a single-line text editor with emacs-style bindings and optional history.
type LineEdit struct {
	buf   []rune
	pos   int
	off   int // first visible rune
	hist  *[]string
	hpos  int
	draft []rune
}

const (
	editNone = iota
	editSubmit
	editCancel
)

func (e *LineEdit) Reset(s string, hist *[]string) {
	e.buf = []rune(s)
	e.pos = len(e.buf)
	e.off = 0
	e.hist = hist
	e.hpos = 0
	if hist != nil {
		e.hpos = len(*hist)
	}
	e.draft = nil
}

func (e *LineEdit) Value() string { return string(e.buf) }

// Handle applies k and reports whether the edit was submitted or cancelled,
// and whether the text changed.
func (e *LineEdit) Handle(k Key) (action int, changed bool) {
	switch k.Code {
	case KeyEnter:
		return editSubmit, false
	case KeyEsc:
		return editCancel, false
	case KeyRune:
		if k.Alt {
			return editNone, false
		}
		e.buf = append(e.buf, 0)
		copy(e.buf[e.pos+1:], e.buf[e.pos:])
		e.buf[e.pos] = k.Rune
		e.pos++
		return editNone, true
	case KeyBackspace:
		return editNone, e.backspace()
	case KeyDelete:
		return editNone, e.del()
	case KeyLeft:
		if e.pos > 0 {
			e.pos--
		}
	case KeyRight:
		if e.pos < len(e.buf) {
			e.pos++
		}
	case KeyHome:
		e.pos = 0
	case KeyEnd:
		e.pos = len(e.buf)
	case KeyUp:
		return editNone, e.histMove(-1)
	case KeyDown:
		return editNone, e.histMove(1)
	case KeyCtrl:
		switch k.Rune {
		case 'c', 'g':
			return editCancel, false
		case 'a':
			e.pos = 0
		case 'e':
			e.pos = len(e.buf)
		case 'b':
			if e.pos > 0 {
				e.pos--
			}
		case 'f':
			if e.pos < len(e.buf) {
				e.pos++
			}
		case 'd':
			return editNone, e.del()
		case 'u':
			e.buf = append([]rune(nil), e.buf[e.pos:]...)
			e.pos = 0
			return editNone, true
		case 'k':
			e.buf = e.buf[:e.pos]
			return editNone, true
		case 'w':
			i := e.pos
			for i > 0 && e.buf[i-1] == ' ' {
				i--
			}
			for i > 0 && e.buf[i-1] != ' ' {
				i--
			}
			e.buf = append(e.buf[:i], e.buf[e.pos:]...)
			e.pos = i
			return editNone, true
		}
	}
	return editNone, false
}

func (e *LineEdit) backspace() bool {
	if e.pos == 0 {
		return false
	}
	e.buf = append(e.buf[:e.pos-1], e.buf[e.pos:]...)
	e.pos--
	return true
}

func (e *LineEdit) del() bool {
	if e.pos >= len(e.buf) {
		return false
	}
	e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
	return true
}

func (e *LineEdit) histMove(d int) bool {
	if e.hist == nil || len(*e.hist) == 0 {
		return false
	}
	h := *e.hist
	np := e.hpos + d
	if np < 0 || np > len(h) {
		return false
	}
	if e.hpos == len(h) {
		e.draft = append([]rune(nil), e.buf...)
	}
	e.hpos = np
	if np == len(h) {
		e.buf = append([]rune(nil), e.draft...)
	} else {
		e.buf = []rune(h[np])
	}
	e.pos = len(e.buf)
	return true
}

// clickAt moves the cursor to display column col of the field. keepOffset
// says the field was drawn scrolled (it had focus); otherwise it was drawn
// from the start.
func (e *LineEdit) clickAt(col int, keepOffset bool) {
	if !keepOffset {
		e.off = 0
	}
	w, i := 0, e.off
	for i < len(e.buf) {
		rw := cellWidth(e.buf[i])
		if w+rw > col {
			break
		}
		w += rw
		i++
	}
	e.pos = i
}

func runesWidth(rs []rune) int {
	n := 0
	for _, r := range rs {
		n += cellWidth(r)
	}
	return n
}

// Draw renders the field in w columns at (x, y), scrolling horizontally to keep
// the cursor visible, and places the terminal cursor.
func (e *LineEdit) Draw(s *Screen, x, y, w int, st Style) {
	if w < 2 {
		return
	}
	if e.pos < e.off {
		e.off = e.pos
	}
	for e.off < e.pos && runesWidth(e.buf[e.off:e.pos]) > w-1 {
		e.off++
	}
	s.Fill(x, y, w, 1, ' ', st)
	s.Text(x, y, x+w, string(e.buf[e.off:]), st)
	s.SetCursor(x+runesWidth(e.buf[e.off:e.pos]), y)
}
