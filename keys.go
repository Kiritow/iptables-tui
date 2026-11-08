package main

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

type KeyCode int

const (
	KeyRune KeyCode = iota
	KeyCtrl         // Rune holds the lowercase letter
	KeyEnter
	KeyEsc
	KeyBackspace
	KeyTab
	KeyBacktab
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyHome
	KeyEnd
	KeyPgUp
	KeyPgDn
	KeyInsert
	KeyDelete
	KeyF1
	KeyF2
	KeyF5
	KeyMouse
	KeyUnknown
)

// Mouse is a mouse event; X and Y are 0-based cells.
type Mouse struct {
	Btn    int // 0 left, 1 middle, 2 right, 3 release (X10), 64 wheel up, 65 wheel down
	X, Y   int
	Press  bool
	Motion bool
}

type Key struct {
	Code  KeyCode
	Rune  rune
	Shift bool
	Alt   bool
	Ctrl  bool
	Mouse Mouse
}

func runeKey(r rune) Key { return Key{Code: KeyRune, Rune: r} }

func (k Key) is(r rune) bool       { return k.Code == KeyRune && k.Rune == r && !k.Alt }
func (k Key) ctrl(r rune) bool     { return k.Code == KeyCtrl && k.Rune == r }
func (k Key) plain(c KeyCode) bool { return k.Code == c && !k.Shift && !k.Alt && !k.Ctrl }

// parseKeys decodes terminal input. Unless final is set, an incomplete trailing
// escape sequence or UTF-8 rune is returned in rest so it can be completed by
// the next read; with final set it is resolved as best as possible (a lone ESC
// becomes the Esc key).
func parseKeys(b []byte, final bool) (keys []Key, rest []byte) {
	i := 0
	for i < len(b) {
		if b[i] == 0x1b {
			if i+1 >= len(b) {
				if !final {
					return keys, b[i:]
				}
				keys = append(keys, Key{Code: KeyEsc})
				i++
				continue
			}
			switch b[i+1] {
			case '[', 'O':
				k, n := parseEscape(b[i:])
				if n == 0 {
					if !final {
						return keys, b[i:]
					}
					keys = append(keys, Key{Code: KeyEsc})
					i++
					continue
				}
				keys = append(keys, k)
				i += n
			case 0x1b:
				keys = append(keys, Key{Code: KeyEsc})
				i++
			default:
				k, n, ok := parseChar(b[i+1:], final)
				if !ok {
					return keys, b[i:]
				}
				k.Alt = true
				keys = append(keys, k)
				i += 1 + n
			}
			continue
		}
		k, n, ok := parseChar(b[i:], final)
		if !ok {
			return keys, b[i:]
		}
		keys = append(keys, k)
		i += n
	}
	return keys, nil
}

func parseChar(b []byte, final bool) (Key, int, bool) {
	c := b[0]
	switch {
	case c == '\r' || c == '\n':
		return Key{Code: KeyEnter}, 1, true
	case c == '\t':
		return Key{Code: KeyTab}, 1, true
	case c == 0x7f || c == 0x08:
		return Key{Code: KeyBackspace}, 1, true
	case c == 0:
		return Key{Code: KeyCtrl, Rune: ' '}, 1, true
	case c < 0x20:
		return Key{Code: KeyCtrl, Rune: rune('a' + c - 1)}, 1, true
	case c < 0x80:
		return Key{Code: KeyRune, Rune: rune(c)}, 1, true
	}
	if !final && !utf8.FullRune(b) {
		return Key{}, 0, false
	}
	r, n := utf8.DecodeRune(b)
	return Key{Code: KeyRune, Rune: r}, n, true
}

// parseEscape decodes a CSI or SS3 sequence starting at b[0] == ESC.
// It returns n == 0 if the sequence is incomplete.
func parseEscape(b []byte) (Key, int) {
	if len(b) < 3 {
		return Key{}, 0
	}
	k := Key{Code: KeyUnknown}
	if b[1] == 'O' {
		switch b[2] {
		case 'A':
			k.Code = KeyUp
		case 'B':
			k.Code = KeyDown
		case 'C':
			k.Code = KeyRight
		case 'D':
			k.Code = KeyLeft
		case 'H':
			k.Code = KeyHome
		case 'F':
			k.Code = KeyEnd
		case 'P':
			k.Code = KeyF1
		case 'Q':
			k.Code = KeyF2
		}
		return k, 3
	}
	if b[2] == '[' {
		// Linux console: ESC [ [ A..E are F1..F5
		if len(b) < 4 {
			return Key{}, 0
		}
		switch b[3] {
		case 'A':
			k.Code = KeyF1
		case 'B':
			k.Code = KeyF2
		case 'E':
			k.Code = KeyF5
		}
		return k, 4
	}
	j := 2
	for j < len(b) && b[j] >= 0x30 && b[j] <= 0x3f {
		j++
	}
	for j < len(b) && b[j] >= 0x20 && b[j] <= 0x2f {
		j++
	}
	if j >= len(b) {
		if j > 32 { // runaway garbage, drop it
			return k, j
		}
		return Key{}, 0
	}
	if b[j] == 'M' && j == 2 {
		// legacy X10 mouse report: ESC [ M Cb Cx Cy with raw bytes. These must be
		// consumed here, or the coordinates would be read as keystrokes.
		if len(b) < 6 {
			return Key{}, 0
		}
		cb := int(b[3]) - 32
		btn := cb &^ (4 | 8 | 16 | 32)
		return Key{Code: KeyMouse, Mouse: Mouse{Btn: btn, X: int(b[4]) - 33, Y: int(b[5]) - 33,
			Press: btn != 3, Motion: cb&32 != 0}}, 6
	}
	if b[2] == '<' && (b[j] == 'M' || b[j] == 'm') {
		// SGR mouse report: ESC [ < Cb ; X ; Y M (press) or m (release)
		f := strings.Split(string(b[3:j]), ";")
		if len(f) != 3 {
			return k, j + 1
		}
		cb, err1 := strconv.Atoi(f[0])
		x, err2 := strconv.Atoi(f[1])
		y, err3 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil || err3 != nil {
			return k, j + 1
		}
		return Key{Code: KeyMouse, Shift: cb&4 != 0, Alt: cb&8 != 0, Ctrl: cb&16 != 0,
			Mouse: Mouse{Btn: cb &^ (4 | 8 | 16 | 32), X: x - 1, Y: y - 1, Press: b[j] == 'M', Motion: cb&32 != 0}}, j + 1
	}
	params := strings.Split(string(b[2:j]), ";")
	switch b[j] {
	case 'A':
		k.Code = KeyUp
	case 'B':
		k.Code = KeyDown
	case 'C':
		k.Code = KeyRight
	case 'D':
		k.Code = KeyLeft
	case 'H':
		k.Code = KeyHome
	case 'F':
		k.Code = KeyEnd
	case 'Z':
		k.Code = KeyBacktab
	case '~':
		switch params[0] {
		case "1", "7":
			k.Code = KeyHome
		case "4", "8":
			k.Code = KeyEnd
		case "2":
			k.Code = KeyInsert
		case "3":
			k.Code = KeyDelete
		case "5":
			k.Code = KeyPgUp
		case "6":
			k.Code = KeyPgDn
		case "11":
			k.Code = KeyF1
		case "12":
			k.Code = KeyF2
		case "15":
			k.Code = KeyF5
		}
	}
	if len(params) > 1 {
		if m, err := strconv.Atoi(params[1]); err == nil && m > 1 {
			m--
			k.Shift = m&1 != 0
			k.Alt = m&2 != 0
			k.Ctrl = m&4 != 0
		}
	}
	return k, j + 1
}
