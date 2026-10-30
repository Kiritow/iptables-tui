package main

import (
	"errors"
	"fmt"
	"strings"
)

type fieldKind int

const (
	fieldText fieldKind = iota
	fieldChoice
)

type formField struct {
	key     string
	label   string
	kind    fieldKind
	edit    LineEdit
	choices []string
	sel     int
	hint    string
}

func textField(key, label, hint string) *formField {
	return &formField{key: key, label: label, kind: fieldText, hint: hint}
}

func choiceField(key, label string, choices ...string) *formField {
	return &formField{key: key, label: label, kind: fieldChoice, choices: choices}
}

func (f *formField) value() string {
	if f.kind == fieldChoice {
		if len(f.choices) == 0 {
			return ""
		}
		return f.choices[f.sel]
	}
	return f.edit.Value()
}

func (f *formField) set(v string) {
	if f.kind == fieldText {
		f.edit.Reset(v, f.edit.hist)
		return
	}
	for i, c := range f.choices {
		if c == v {
			f.sel = i
			return
		}
	}
	f.choices = append(f.choices, v)
	f.sel = len(f.choices) - 1
}

type ruleTemplate struct {
	name   string
	tables []string          // tables the template applies to; nil = all
	note   string            // usage hint shown next to the template name
	vals   map[string]string // field key -> value
	vals6  map[string]string // IPv6 overrides
}

var (
	tFilterish = []string{"filter", "mangle", "raw", "security"}
	tFwd       = []string{"filter", "mangle"}
	tNat       = []string{"nat"}
	tMangle    = []string{"mangle"}
	tRaw       = []string{"raw"}
)

var ruleTemplates = []ruleTemplate{
	{name: "Custom", vals: map[string]string{}},
	{name: "Allow TCP port", tables: tFilterish, vals: map[string]string{"proto": "tcp", "dport": "22", "target": "ACCEPT"}},
	{name: "Allow UDP port", tables: tFilterish, vals: map[string]string{"proto": "udp", "dport": "53", "target": "ACCEPT"}},
	{name: "Allow established/related", tables: tFilterish, vals: map[string]string{"state": "ESTABLISHED,RELATED", "target": "ACCEPT"}},
	{name: "Allow loopback", tables: tFilterish, vals: map[string]string{"in": "lo", "target": "ACCEPT"}},
	{name: "Allow ping", tables: tFilterish,
		vals:  map[string]string{"proto": "icmp", "extra": "--icmp-type echo-request", "target": "ACCEPT"},
		vals6: map[string]string{"proto": "ipv6-icmp", "extra": "--icmpv6-type echo-request"}},
	{name: "Allow from network", tables: tFilterish,
		vals: map[string]string{"src": "192.168.0.0/16", "target": "ACCEPT"}, vals6: map[string]string{"src": "fd00::/8"}},
	{name: "Block source address", tables: tFilterish,
		vals: map[string]string{"src": "203.0.113.10", "target": "DROP"}, vals6: map[string]string{"src": "2001:db8::10"}},
	{name: "Reject TCP port", tables: tFilterish,
		vals: map[string]string{"proto": "tcp", "dport": "23", "target": "REJECT", "topts": "--reject-with tcp-reset"}},
	{name: "Drop invalid packets", tables: tFilterish, vals: map[string]string{"state": "INVALID", "target": "DROP"}},
	{name: "Rate-limit new connections", tables: tFilterish,
		vals: map[string]string{"proto": "tcp", "dport": "22", "state": "NEW", "limit": "6/min", "target": "ACCEPT"}},
	{name: "Log packets", tables: tFilterish, vals: map[string]string{"target": "LOG", "topts": `--log-prefix "iptables: "`}},
	{name: "Clamp TCP MSS to PMTU", tables: tFwd, note: "FORWARD / OUTPUT / POSTROUTING only",
		vals: map[string]string{"proto": "tcp", "extra": "--tcp-flags SYN,RST SYN", "target": "TCPMSS", "topts": "--clamp-mss-to-pmtu"}},
	{name: "Port forward (DNAT)", tables: tNat, note: "PREROUTING / OUTPUT only",
		vals:  map[string]string{"proto": "tcp", "in": "eth0", "dport": "8080", "target": "DNAT", "topts": "--to-destination 192.168.1.10:80"},
		vals6: map[string]string{"topts": "--to-destination [fd00::10]:80"}},
	{name: "Masquerade (outgoing NAT)", tables: tNat, note: "POSTROUTING only",
		vals: map[string]string{"src": "192.168.1.0/24", "out": "eth0", "target": "MASQUERADE"}, vals6: map[string]string{"src": "fd00::/64"}},
	{name: "Source NAT (SNAT)", tables: tNat, note: "POSTROUTING / INPUT only",
		vals:  map[string]string{"src": "192.168.1.0/24", "out": "eth0", "target": "SNAT", "topts": "--to-source 203.0.113.1"},
		vals6: map[string]string{"src": "fd00::/64", "topts": "--to-source 2001:db8::1"}},
	{name: "Redirect port", tables: tNat, note: "PREROUTING / OUTPUT only",
		vals: map[string]string{"proto": "tcp", "dport": "80", "target": "REDIRECT", "topts": "--to-ports 8080"}},
	{name: "Set packet mark", tables: tMangle, vals: map[string]string{"target": "MARK", "topts": "--set-mark 0x1"}},
	{name: "Skip conntrack (NOTRACK)", tables: tRaw,
		vals: map[string]string{"proto": "udp", "dport": "53", "target": "CT", "topts": "--notrack"}},
}

var tableTargets = map[string][]string{
	"filter":   {"ACCEPT", "DROP", "REJECT", "RETURN", "LOG", "TCPMSS"},
	"nat":      {"DNAT", "SNAT", "MASQUERADE", "REDIRECT", "RETURN", "ACCEPT", "LOG"},
	"mangle":   {"ACCEPT", "DROP", "RETURN", "MARK", "CONNMARK", "TCPMSS", "DSCP", "LOG"},
	"raw":      {"ACCEPT", "DROP", "RETURN", "CT", "NOTRACK", "LOG"},
	"security": {"ACCEPT", "DROP", "RETURN", "SECMARK", "CONNSECMARK", "LOG"},
}

const noTarget = "(none)"

// ruleForm is the add/edit rule dialog. Simple mode builds a rule from
// templates and fields; advanced mode takes raw iptables arguments.
type ruleForm struct {
	title     string
	cmdPrefix []string // e.g. -A INPUT, shown in the preview
	editing   bool     // editing an existing rule: advanced mode only
	advanced  bool
	simple    []*formField
	adv       []*formField
	focus     int
	err       string
	fam       Family
	table     string
	chain     string
	templates []ruleTemplate
	// describe returns the confirmation dialog for a submission; nil lines
	// mean there is nothing to confirm (e.g. no changes).
	describe func(args []string, disabled bool) (string, []textLine)
	submit   func(args []string, disabled bool)
}

func newRuleForm(fam Family, table, chain string, userChains []string, hist *[]string) *ruleForm {
	f := &ruleForm{fam: fam, table: table, chain: chain}
	var names []string
	for _, t := range ruleTemplates {
		if t.tables == nil || contains(t.tables, table) {
			f.templates = append(f.templates, t)
			names = append(names, t.name)
		}
	}
	protos := []string{"any", "tcp", "udp", "icmp", "sctp"}
	if fam == V6 {
		protos[3] = "ipv6-icmp"
	}
	targets := append(append(append([]string{}, tableTargets[table]...), userChains...), noTarget)
	as := choiceField("as", "Add as", "enabled", "disabled")
	f.simple = []*formField{
		choiceField("template", "Template", names...),
		choiceField("proto", "Protocol", protos...),
		textField("src", "Source", "addr[/mask][,...]; prefix ! to negate"),
		textField("dst", "Destination", "addr[/mask][,...]; prefix ! to negate"),
		textField("in", "In interface", "e.g. eth0, lo, br+"),
		textField("out", "Out interface", "e.g. eth0, wg0"),
		textField("sport", "Source port", "22 | 80,443 | 1000:2000"),
		textField("dport", "Dest port", "22 | 80,443 | 1000:2000"),
		choiceField("state", "Conn state", "any", "NEW", "ESTABLISHED,RELATED", "NEW,ESTABLISHED,RELATED", "INVALID"),
		textField("limit", "Rate limit", "e.g. 10/min, 5/s"),
		textField("extra", "Extra matches", "raw args, e.g. -m mac --mac-source ..."),
		textField("comment", "Comment", ""),
		choiceField("target", "Target", targets...),
		textField("topts", "Target options", "e.g. --reject-with tcp-reset"),
		as,
	}
	rule := textField("rule", "Rule", "")
	rule.edit.hist = hist
	f.adv = []*formField{rule, as}
	f.applyTemplate(f.templates[0])
	return f
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (f *ruleForm) field(key string) *formField {
	for _, fl := range f.simple {
		if fl.key == key {
			return fl
		}
	}
	for _, fl := range f.adv {
		if fl.key == key {
			return fl
		}
	}
	return nil
}

func (f *ruleForm) get(key string) string { return f.field(key).value() }

func (f *ruleForm) fields() []*formField {
	if f.advanced {
		return f.adv
	}
	return f.simple
}

func (f *ruleForm) disabled() bool { return f.get("as") == "disabled" }

func (f *ruleForm) applyTemplate(t ruleTemplate) {
	for _, fl := range f.simple {
		switch fl.key {
		case "template", "as":
		case "proto", "state":
			fl.sel = 0
		case "target":
			fl.sel = 0
		default:
			fl.set("")
		}
	}
	for k, v := range t.vals {
		f.field(k).set(v)
	}
	if f.fam == V6 {
		for k, v := range t.vals6 {
			f.field(k).set(v)
		}
	}
}

func (f *ruleForm) setAdvanced(on bool) {
	if f.editing || on == f.advanced {
		return
	}
	if on {
		if args, err := f.buildSimple(); err == nil {
			f.field("rule").set(joinArgs(args))
		}
	}
	f.advanced = on
	f.focus = 0
}

// handleKey returns whether the form should be submitted or cancelled.
func (f *ruleForm) handleKey(k Key) (submit, cancel bool) {
	fs := f.fields()
	if f.focus >= len(fs) {
		f.focus = len(fs) - 1
	}
	cur := fs[f.focus]
	f.err = ""
	switch {
	case k.Code == KeyEsc || k.ctrl('c'):
		return false, true
	case k.Code == KeyEnter:
		return true, false
	case k.Code == KeyF2 || k.ctrl('t'):
		f.setAdvanced(!f.advanced)
	case k.Code == KeyTab || k.plain(KeyDown):
		f.focus = (f.focus + 1) % len(fs)
	case k.Code == KeyBacktab || k.plain(KeyUp):
		f.focus = (f.focus + len(fs) - 1) % len(fs)
	case cur.kind == fieldChoice:
		n := len(cur.choices)
		switch {
		case k.Code == KeyRight || k.is(' '):
			cur.sel = (cur.sel + 1) % n
		case k.Code == KeyLeft:
			cur.sel = (cur.sel + n - 1) % n
		case k.Code == KeyRune && !k.Alt && cur.key != "template":
			// type-ahead: next choice starting with the typed letter
			want := strings.ToLower(string(k.Rune))
			for i := 1; i <= n; i++ {
				j := (cur.sel + i) % n
				if strings.HasPrefix(strings.ToLower(cur.choices[j]), want) {
					cur.sel = j
					break
				}
			}
		default:
			return false, false
		}
		if cur.key == "template" {
			f.applyTemplate(f.templates[cur.sel])
		}
	default:
		switch {
		case k.ctrl('p'):
			cur.edit.histMove(-1)
		case k.ctrl('n'):
			cur.edit.histMove(1)
		default:
			cur.edit.Handle(k)
		}
	}
	return false, false
}

func (f *ruleForm) build() ([]string, error) {
	if f.advanced {
		return parseRuleInput(f.get("rule"), f.table, f.chain)
	}
	args, err := f.buildSimple()
	if err == nil && len(args) == 0 {
		err = errors.New("rule is empty")
	}
	return args, err
}

func (f *ruleForm) buildSimple() ([]string, error) {
	var a []string
	val := func(key string) string { return strings.TrimSpace(f.get(key)) }
	opt := func(name, v string) {
		if v == "" {
			return
		}
		if strings.HasPrefix(v, "!") {
			if v = strings.TrimSpace(v[1:]); v == "" {
				return
			}
			a = append(a, "!")
		}
		a = append(a, name, v)
	}
	opt("-s", val("src"))
	opt("-d", val("dst"))
	opt("-i", val("in"))
	opt("-o", val("out"))
	proto := val("proto")
	if proto != "any" {
		a = append(a, "-p", proto)
	}
	sport, dport := normPorts(val("sport")), normPorts(val("dport"))
	if sport != "" || dport != "" {
		if proto != "tcp" && proto != "udp" && proto != "sctp" {
			return nil, errors.New("ports need protocol tcp, udp or sctp")
		}
		if strings.Contains(sport+dport, ",") {
			a = append(a, "-m", "multiport")
			opt("--sports", sport)
			opt("--dports", dport)
		} else {
			a = append(a, "-m", proto)
			opt("--sport", sport)
			opt("--dport", dport)
		}
	}
	if st := val("state"); st != "any" {
		a = append(a, "-m", "conntrack", "--ctstate", st)
	}
	if lim := val("limit"); lim != "" {
		a = append(a, "-m", "limit", "--limit", lim)
	}
	if ex := val("extra"); ex != "" {
		toks, err := splitArgs(ex)
		if err != nil {
			return nil, fmt.Errorf("extra matches: %v", err)
		}
		a = append(a, toks...)
	}
	if c := f.get("comment"); strings.TrimSpace(c) != "" {
		if len(c) > 255 {
			return nil, errors.New("comment is longer than 255 bytes")
		}
		a = append(a, "-m", "comment", "--comment", c)
	}
	if t := val("target"); t != noTarget {
		a = append(a, "-j", t)
		if to := val("topts"); to != "" {
			toks, err := splitArgs(to)
			if err != nil {
				return nil, fmt.Errorf("target options: %v", err)
			}
			a = append(a, toks...)
		}
	}
	return a, nil
}

// normPorts accepts "1000-2000" as an alias for iptables' "1000:2000".
func normPorts(s string) string {
	if s == "" {
		return ""
	}
	neg := strings.HasPrefix(s, "!")
	if neg {
		s = strings.TrimSpace(s[1:])
	}
	parts := strings.Split(s, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if lo, hi, ok := strings.Cut(p, "-"); ok && isDigits(lo) && isDigits(hi) {
			p = lo + ":" + hi
		}
		parts[i] = p
	}
	s = strings.Join(parts, ",")
	if neg {
		s = "!" + s
	}
	return s
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseRuleInput tokenizes a user-written rule. A leading "iptables",
// "-t TABLE" or "-A CHAIN" (as copied from iptables-save) is accepted if it
// matches the target table and chain.
func parseRuleInput(s, table, chain string) ([]string, error) {
	args, err := splitArgs(s)
	if err != nil {
		return nil, err
	}
	if len(args) > 0 && (strings.HasSuffix(args[0], "iptables") || strings.HasSuffix(args[0], "ip6tables")) {
		args = args[1:]
	}
	if len(args) >= 2 && (args[0] == "-t" || args[0] == "--table") {
		if args[1] != table {
			return nil, fmt.Errorf("rule is for table %s, but the current table is %s", args[1], table)
		}
		args = args[2:]
	}
	if len(args) >= 2 && (args[0] == "-A" || args[0] == "--append") {
		if args[1] != chain {
			return nil, fmt.Errorf("rule is for chain %s, but the current chain is %s", args[1], chain)
		}
		args = args[2:]
	}
	if len(args) == 0 {
		return nil, errors.New("rule is empty")
	}
	return args, nil
}

func (a *App) drawForm() {
	f, s := a.form, a.scr
	W, H := s.w, s.h
	fs := f.fields()
	bw := min(W-2, 100)
	inner := bw - 4

	var preview []string
	pst := fg(cGreen)
	if args, err := f.build(); err != nil {
		preview, pst = []string{"! " + err.Error()}, fg(cRed)
	} else {
		cmd := append(append([]string{a.be().Name(), "-t", f.table}, f.cmdPrefix...), args...)
		preview = wrapText(joinArgs(cmd), inner)
		if f.disabled() {
			preview = append(preview, "(disabled: stored in the state file, a placeholder keeps its position)")
		}
	}
	if f.err != "" {
		preview = append(wrapText("! "+f.err, inner), preview...)
	}
	if len(preview) > 5 {
		preview = preview[:5]
	}
	fixed := 4 + len(preview) // borders, blank line, buttons
	visible := clamp(H-2-fixed, 1, len(fs))
	bh := visible + fixed
	x0, y0 := (W-bw)/2, max(0, (H-bh)/2)
	mode := "simple · F2 advanced"
	if f.editing {
		mode = "advanced"
	} else if f.advanced {
		mode = "advanced · F2 simple"
	}
	drawBox(s, x0, y0, bw, bh, f.title+" ["+mode+"]", "Enter ok · Tab/↑↓ field · ←/→ choose · Esc cancel")
	// clicks outside the dialog do nothing (no accidental cancel); the wheel moves between fields
	a.modal(0, 0, 0, 0, nil, func(d int) { f.focus = clamp(f.focus+d, 0, len(fs)-1) })

	top := 0
	if f.focus >= visible {
		top = f.focus - visible + 1
	}
	const labelW = 15
	for i := 0; i < visible && top+i < len(fs); i++ {
		idx, fl := top+i, fs[top+i]
		y, x := y0+1+i, x0+2
		focused := idx == f.focus
		lst := stDefault
		if focused {
			lst = fg(cCyan).with(AttrBold)
		}
		label := fl.label
		if f.editing && fl.key == "as" {
			label = "State"
		}
		s.Text(x, y, x+labelW, label, lst)
		fx := x + labelW + 1
		fw := min(40, inner-labelW-1)
		if fl.key == "rule" {
			fw = inner - labelW - 1
		}
		valueEnd := fx + fw
		switch fl.kind {
		case fieldText:
			st := stDefault.with(AttrUnderline)
			if focused {
				fl.edit.Draw(s, fx, y, fw, Style{Fg: cWhite, Bg: cBlue})
			} else {
				s.Fill(fx, y, fw, 1, ' ', st)
				s.Text(fx, y, fx+fw, fl.edit.Value(), st)
			}
		case fieldChoice:
			st := stDefault
			if focused {
				st = Style{Fg: cBlack, Bg: cCyan}
			}
			valueEnd = s.Text(fx, y, fx+fw, "< "+fl.value()+" >", st)
			if fl.key == "template" {
				end := s.Text(valueEnd+1, y, x0+bw-2, fmt.Sprintf("%d/%d", fl.sel+1, len(fl.choices)), stDim)
				if note := f.templates[fl.sel].note; note != "" {
					s.Text(end+2, y, x0+bw-2, note, fg(cYellow))
				}
			}
		}
		if fl.hint != "" && fx+fw+2 < x0+bw-2 {
			s.Text(fx+fw+2, y, x0+bw-2, fl.hint, stDim)
		}
		a.hit(x, y, x0+bw-2, y+1, func(cx int, _ bool) {
			wasFocused := f.focus == idx
			f.focus = idx
			f.err = ""
			if cx < fx || cx >= valueEnd {
				return
			}
			switch {
			case fl.kind == fieldText:
				fl.edit.clickAt(cx-fx, wasFocused)
			case cx < fx+2:
				f.handleKey(Key{Code: KeyLeft})
			default:
				f.handleKey(Key{Code: KeyRight})
			}
		}, nil)
	}
	py := y0 + 1 + visible + 1
	for i, l := range preview {
		st := pst
		if strings.HasPrefix(l, "! ") {
			st = fg(cRed)
		} else if strings.HasPrefix(l, "(") {
			st = fg(cYellow)
		}
		s.Text(x0+2, py+i, x0+bw-2, l, st)
	}

	// buttons
	type button struct {
		label string
		st    Style
		key   Key
	}
	buttons := []button{
		{"  OK (Enter)  ", Style{Fg: cBlack, Bg: cGreen, Attr: AttrBold}, Key{Code: KeyEnter}},
		{"  Cancel (Esc)  ", Style{Fg: cBlack, Bg: cWhite, Attr: AttrBold}, Key{Code: KeyEsc}},
	}
	if !f.editing {
		other := "Advanced"
		if f.advanced {
			other = "Simple"
		}
		buttons = append(buttons, button{"  " + other + " (F2)  ", Style{Fg: cBlack, Bg: cCyan}, Key{Code: KeyF2}})
	}
	by, bx := y0+bh-2, x0+2
	for _, b := range buttons {
		key, start := b.key, bx
		bx = s.Text(bx, by, x0+bw-2, b.label, b.st)
		a.hit(start, by, bx, by+1, func(int, bool) { a.handleFormKey(key) }, nil)
		bx += 2
	}
}
