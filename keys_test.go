package main

import "testing"

func TestParseKeys(t *testing.T) {
	keys, rest := parseKeys([]byte("a\x1b[A\x1b[1;2B\x1b[3~\r中"), false)
	if len(rest) != 0 || len(keys) != 6 {
		t.Fatalf("keys=%+v rest=%q", keys, rest)
	}
	if keys[1].Code != KeyUp || keys[2].Code != KeyDown || !keys[2].Shift || keys[3].Code != KeyDelete ||
		keys[4].Code != KeyEnter || keys[5].Rune != '中' {
		t.Errorf("keys=%+v", keys)
	}
	// a lone ESC is held back until it is known not to start a sequence
	if keys, rest := parseKeys([]byte("\x1b"), false); len(keys) != 0 || len(rest) != 1 {
		t.Errorf("lone esc: keys=%+v rest=%q", keys, rest)
	}
	if keys, _ := parseKeys([]byte("\x1b"), true); len(keys) != 1 || keys[0].Code != KeyEsc {
		t.Errorf("final esc: %+v", keys)
	}
}

func TestParseMouse(t *testing.T) {
	keys, _ := parseKeys([]byte("\x1b[<0;10;5M\x1b[<0;10;5m\x1b[<65;3;4M"), false)
	if len(keys) != 3 {
		t.Fatalf("keys=%+v", keys)
	}
	if m := keys[0].Mouse; keys[0].Code != KeyMouse || m.Btn != 0 || m.X != 9 || m.Y != 4 || !m.Press {
		t.Errorf("press=%+v", keys[0])
	}
	if keys[1].Mouse.Press {
		t.Errorf("release=%+v", keys[1])
	}
	if keys[2].Mouse.Btn != 65 {
		t.Errorf("wheel=%+v", keys[2])
	}
	// X10: coordinates are raw bytes ('d' = column 68) and must not leak as keys
	keys, rest := parseKeys([]byte("\x1b[M d$"), false)
	if len(keys) != 1 || len(rest) != 0 || keys[0].Code != KeyMouse || keys[0].Mouse.X != 67 || keys[0].Mouse.Y != 3 {
		t.Errorf("x10 keys=%+v rest=%q", keys, rest)
	}
}
