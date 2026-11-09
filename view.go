package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	stDim       = fg(cGray)
	stHeader    = Style{Fg: cWhite, Bg: cBlue, Attr: AttrBold}
	stWatchOn   = Style{Fg: cBlack, Bg: cGreen, Attr: AttrBold}
	stTabActive = Style{Fg: cBlack, Bg: cCyan, Attr: AttrBold}
	stBorder    = fg(cGray)
	stTitle     = fg(cCyan).with(AttrBold)
	stTitleFoc  = Style{Fg: cBlack, Bg: cCyan, Attr: AttrBold}
	stColHdr    = fg(cGray).with(AttrUnderline)
	stSel       = Style{Fg: cBlack, Bg: cCyan}
	stKey       = Style{Fg: cBlack, Bg: cWhite}
)

func fmtDur(d time.Duration) string {
	if d < time.Second {
		return strconv.Itoa(int(d/time.Millisecond)) + "ms"
	}
	return strings.TrimSuffix(d.String(), "0s")
}

func (a *App) num(n uint64) string {
	if a.exact || n < 100000 {
		return strconv.FormatUint(n, 10)
	}
	f, i := float64(n), -1
	for f >= 1000 && i < 5 {
		f /= 1000
		i++
	}
	if f < 10 {
		return fmt.Sprintf("%.1f%c", f, "KMGTPE"[i])
	}
	return fmt.Sprintf("%.0f%c", f, "KMGTPE"[i])
}

func targetStyle(t string, isChain bool) Style {
	switch t {
	case "ACCEPT":
		return fg(cGreen)
	case "DROP", "REJECT":
		return fg(cRed).with(AttrBold)
	case "RETURN":
		return fg(cYellow)
	case "LOG", "NFLOG", "TRACE":
		return fg(cCyan)
	case "":
		return stDim
	}
	if isChain {
		return fg(cBlue).with(AttrBold)
	}
	return fg(cMagenta)
}

// displayTarget is the target column text; NFLOG shows its group.
func displayTarget(r *Rule) string {
	if r.Target == "NFLOG" {
		return "NFLOG:" + strconv.Itoa(nflogGroup(r.Spec))
	}
	return r.Target
}

func policyStyle(p string) Style {
	switch p {
	case "ACCEPT":
		return fg(cGreen)
	case "DROP":
		return fg(cRed).with(AttrBold)
	}
	return stDim
}

func drawBox(s *Screen, x, y, w, h int, title, footer string) {
	s.Fill(x, y, w, h, ' ', stDefault)
	st := fg(cCyan)
	for xx := x + 1; xx < x+w-1; xx++ {
		s.set(xx, y, '─', 1, st)
		s.set(xx, y+h-1, '─', 1, st)
	}
	for yy := y + 1; yy < y+h-1; yy++ {
		s.set(x, yy, '│', 1, st)
		s.set(x+w-1, yy, '│', 1, st)
	}
	s.set(x, y, '┌', 1, st)
	s.set(x+w-1, y, '┐', 1, st)
	s.set(x, y+h-1, '└', 1, st)
	s.set(x+w-1, y+h-1, '┘', 1, st)
	if title != "" {
		s.Text(x+2, y, x+w-2, " "+title+" ", st.with(AttrBold))
	}
	if footer != "" {
		fw := strWidth(footer) + 2
		s.Text(max(x+2, x+w-2-fw), y+h-1, x+w-2, " "+footer+" ", stDim)
	}
}

func (a *App) draw() {
	s := a.scr
	s.Clear()
	a.hits = a.hits[:0]
	W, H := s.w, s.h
	if W < 60 || H < 16 {
		s.Text(0, 0, W, fmt.Sprintf("terminal too small (%dx%d, need 60x16)", W, H), fg(cRed))
		s.Flush()
		return
	}
	a.drawHeader(0)
	if a.view == viewMonitor {
		a.drawMonitor()
	} else {
		a.drawTabs(1)
		const detailH = 3
		bodyBot := H - 2 - detailH - 1
		lw := a.chainPaneWidth()
		a.drawChains(0, 2, lw, bodyBot)
		for y := 2; y < bodyBot; y++ {
			s.set(lw, y, '│', 1, stBorder)
		}
		a.drawRules(lw+1, 2, W, bodyBot)
		a.drawDetail(bodyBot, detailH)
	}
	a.drawStatus(H - 2)
	a.drawKeys(H - 1)
	switch a.mode {
	case modeText:
		a.drawText()
	case modeList:
		a.drawList()
	case modeForm:
		a.drawForm()
	case modeConfirm:
		a.drawConfirm()
	}
	s.Flush()
}

func (a *App) drawHeader(y int) {
	s, W := a.scr, a.scr.w
	s.Fill(0, y, W, 1, ' ', stHeader)
	x := s.Text(0, y, W, " iptables-tui ", stHeader)
	x = s.Text(x, y, W, a.version+" ", Style{Fg: cWhite, Bg: cBlue})
	fx := x
	x = s.Text(x, y, W, "│ "+a.fam.String()+" ", stHeader)
	a.hit(fx, y, x, y+1, func(int, bool) { a.handleKey(runeKey('6')) }, nil)
	s.Text(x, y, W, "│ "+a.be().Version, Style{Fg: cWhite, Bg: cBlue})

	right := " watch off "
	rst := stHeader
	if a.watch {
		right, rst = " WATCH "+fmtDur(a.interval)+" ", stWatchOn
	}
	info := ""
	if snap := a.snaps[a.fam]; snap != nil {
		info = " " + snap.Time.Format("15:04:05") + " "
	}
	if a.busy > 0 {
		info = " busy" + info
	}
	rx := W - strWidth(right) - strWidth(info)
	s.Text(rx, y, W, info, stHeader)
	s.Text(rx+strWidth(info), y, W, right, rst)
	a.hit(rx+strWidth(info), y, W, y+1, func(int, bool) { a.handleKey(runeKey('w')) }, nil)
}

func (a *App) drawTabs(y int) {
	s, W := a.scr, a.scr.w
	snap := a.snaps[a.fam]
	x := 0
	for _, fam := range []Family{V4, V6} {
		st := stDim
		if fam == a.fam {
			st = Style{Fg: cBlack, Bg: cMagenta, Attr: AttrBold}
		}
		fx := x
		x = s.Text(x, y, W, " "+fam.String()+" ", st)
		if fam != a.fam {
			a.hit(fx, y, x, y+1, func(int, bool) { a.handleKey(runeKey('6')) }, nil)
		}
	}
	x = s.Text(x, y, W, " │ ", stBorder)
	for i, name := range tableNames {
		st := stDefault
		if snap != nil && !snap.Tables[name].Loaded {
			st = stDim
		}
		if i == a.tIdx {
			st = stTabActive
		}
		tx, ti := x, i
		x = s.Text(x, y, W, fmt.Sprintf(" %d %s ", i+1, name), st)
		a.hit(tx, y, x, y+1, func(int, bool) { a.switchTable(ti) }, nil)
		x++
	}
	var info []string
	if a.chainFilter != "" {
		info = append(info, "chains~"+quoteArg(a.chainFilter))
	}
	if a.ruleFilter != "" {
		info = append(info, "rules~"+quoteArg(a.ruleFilter))
	}
	if a.clip != nil {
		info = append(info, fmt.Sprintf("clip: %d %s rule(s)", len(a.clip.rules), a.clip.fam))
	}
	for _, m := range []*monitor{a.nflog, a.trace} {
		m.mu.Lock()
		if m.running {
			info = append(info, fmt.Sprintf("%s on: %d", m.kind, m.total))
		}
		m.mu.Unlock()
	}
	text, st := strings.Join(info, " "), fg(cYellow).with(AttrBold)
	if text == "" && snap != nil && len(snap.Warnings) > 0 {
		text, st = "! "+snap.Warnings[0], fg(cYellow)
	}
	if text != "" {
		text = fit(text, W-x-1)
		s.Text(W-strWidth(text)-1, y, W, text, st)
	}
}

func (a *App) chainPaneWidth() int {
	nameW := 10
	if t := a.table(); t != nil {
		for _, c := range t.Chains {
			nameW = max(nameW, strWidth(c.Name))
		}
	}
	return clamp(nameW+15, 24, a.scr.w*2/5)
}

func scrollTo(sel, top, rows, n int) int {
	if rows <= 0 {
		return 0
	}
	if sel < top {
		top = sel
	}
	if sel >= top+rows {
		top = sel - rows + 1
	}
	return clamp(top, 0, max(0, n-rows))
}

func (a *App) drawChains(x0, y0, x1, y1 int) {
	s := a.scr
	w := x1 - x0
	cs := a.chains()
	focused := a.focus == paneChains
	tst := stTitle
	if focused {
		tst = stTitleFoc
		s.Fill(x0, y0, w, 1, ' ', tst)
	}
	s.Text(x0, y0, x1, fmt.Sprintf(" Chains (%d)", len(cs)), tst)
	a.hit(x0, y0, x1, y1, func(int, bool) { a.focus = paneChains }, func(d int) { a.setChainSel(a.chainSel + d) })

	nameW := w - 14
	s.Fill(x0, y0+1, w, 1, ' ', stColHdr)
	s.Text(x0, y0+1, x1, " "+pad("chain", nameW)+" "+pad("policy", 6)+" "+lpad("rules", 5), stColHdr)
	rows := y1 - y0 - 2
	a.chainRows = rows
	a.chainTop = scrollTo(a.chainSel, a.chainTop, rows, len(cs))
	if len(cs) == 0 {
		msg := "(no chains)"
		if a.chainFilter != "" {
			msg = "(no chain matches)"
		}
		s.Text(x0+1, y0+2, x1, msg, stDim)
	}
	for i := 0; i < rows && a.chainTop+i < len(cs); i++ {
		idx := a.chainTop + i
		c, y := cs[idx], y0+2+i
		sel := idx == a.chainSel
		seg := func(st Style) Style {
			if sel && focused {
				return stSel
			}
			if sel {
				return st.with(AttrBold)
			}
			return st
		}
		if sel && focused {
			s.Fill(x0, y, w, 1, ' ', stSel)
		}
		a.hit(x0, y, x1, y+1, func(_ int, dbl bool) {
			a.focus = paneChains
			a.setChainSel(idx)
			if dbl {
				a.focus = paneRules
			}
		}, nil)
		marker := " "
		if sel {
			marker = ">"
		}
		x := s.Text(x0, y, x1, marker, seg(fg(cCyan).with(AttrBold)))
		nst := stDefault
		switch {
		case c.Virtual:
			nst = stDim
		case c.Builtin:
			nst = nst.with(AttrBold)
		case c.Refs == 0:
			nst = fg(cYellow)
		}
		x = s.Text(x, y, x1, pad(c.Name, nameW)+" ", seg(nst))
		pol := c.Policy
		if pol == "" {
			pol = "-"
		}
		x = s.Text(x, y, x1, pad(pol, 6)+" ", seg(policyStyle(c.Policy)))
		cst := stDefault
		if len(c.Rules) == 0 {
			cst = stDim
		}
		s.Text(x, y, x1, lpad(strconv.Itoa(len(c.Rules)), 5), seg(cst))
	}
}

func (a *App) drawRules(x0, y0, x1, y1 int) {
	s := a.scr
	w := x1 - x0
	focused := a.focus == paneRules
	tst := stTitle
	if focused {
		tst = stTitleFoc
		s.Fill(x0, y0, w, 1, ' ', tst)
	}
	c := a.chain()
	a.hit(x0, y0, x1, y1, func(int, bool) { a.focus = paneRules }, func(d int) {
		a.ruleSel = clamp(a.ruleSel+3*d, 0, len(a.rules())-1)
	})
	if c == nil {
		s.Text(x0, y0, x1, " Rules", tst)
		if a.snaps[a.fam] == nil {
			s.Text(x0+1, y0+2, x1, "loading…", stDim)
		}
		return
	}
	rs := a.rules()
	title := fmt.Sprintf(" %s/%s · ", a.tableName(), c.Name)
	if c.Builtin {
		title += fmt.Sprintf("policy %s (%s pkts, %s bytes) · ", c.Policy, a.num(c.Pkts), a.num(c.Bytes))
	} else {
		title += fmt.Sprintf("%d reference(s) · ", c.Refs)
	}
	title += fmt.Sprintf("%d rules", len(c.Rules))
	if a.ruleFilter != "" {
		title += fmt.Sprintf(", %d shown", len(rs))
	}
	if t := a.table(); t != nil && !t.Loaded {
		title += " · table not loaded"
	}
	s.Text(x0, y0, x1, title, tst)

	// column widths
	numW, pktW, byW, dW, tW := 3, 4, 5, 6, 6
	for _, r := range c.Rules {
		pk, by := r.Counters()
		numW = max(numW, len(strconv.Itoa(r.Num)))
		pktW = max(pktW, len(a.num(pk)))
		byW = max(byW, len(a.num(by)))
		tW = max(tW, strWidth(displayTarget(r)))
		if r.HasDelta && r.DPkts > 0 {
			dW = max(dW, len(a.num(r.DPkts))+1)
		}
	}
	tW = min(tW, 20)
	hdr := " " + lpad("#", numW) + " st  " + lpad("pkts", pktW) + " " + lpad("bytes", byW) + " "
	if a.watch {
		hdr += lpad("+pkts", dW) + " "
	}
	hdr += pad("target", tW) + " rule"
	s.Fill(x0, y0+1, w, 1, ' ', stColHdr)
	s.Text(x0, y0+1, x1, hdr, stColHdr)

	rows := y1 - y0 - 2
	a.ruleRows = rows
	a.ruleTop = scrollTo(a.ruleSel, a.ruleTop, rows, len(rs))
	if len(rs) == 0 {
		msg := "(empty chain, press a to add a rule)"
		if a.ruleFilter != "" {
			msg = "(no rule matches the filter)"
		}
		s.Text(x0+1, y0+2, x1, msg, stDim)
	}
	t := a.table()
	for i := 0; i < rows && a.ruleTop+i < len(rs); i++ {
		idx := a.ruleTop + i
		r, y := rs[idx], y0+2+i
		sel := idx == a.ruleSel
		seg := func(st Style) Style {
			if sel && focused {
				return stSel
			}
			if r.Disabled {
				st = stDim
			}
			if sel {
				st = st.with(AttrBold)
			}
			return st
		}
		if sel && focused {
			s.Fill(x0, y, w, 1, ' ', stSel)
		}
		a.hit(x0, y, x1, y+1, func(_ int, dbl bool) {
			a.focus = paneRules
			a.ruleSel = idx
			if dbl {
				a.actEnter()
			}
		}, nil)
		active := !r.Disabled && r.HasDelta && r.DPkts > 0
		marker := " "
		if sel {
			marker = ">"
		}
		x := s.Text(x0, y, x1, marker, seg(fg(cCyan).with(AttrBold)))
		x = s.Text(x, y, x1, lpad(strconv.Itoa(r.Num), numW)+" ", seg(stDim))
		if r.Disabled {
			st := fg(cRed).with(AttrBold)
			if sel && focused {
				st = stSel
			}
			x = s.Text(x, y, x1, "OFF", st)
		} else {
			x = s.Text(x, y, x1, " on", seg(fg(cGreen)))
		}
		x++
		pk, by := r.Counters()
		pst := stDefault
		switch {
		case active:
			pst = fg(cYellow).with(AttrBold)
		case pk == 0:
			pst = stDim
		}
		x = s.Text(x, y, x1, lpad(a.num(pk), pktW)+" ", seg(pst))
		x = s.Text(x, y, x1, lpad(a.num(by), byW)+" ", seg(pst))
		if a.watch {
			d := ""
			if active {
				d = "+" + a.num(r.DPkts)
			}
			x = s.Text(x, y, x1, lpad(d, dW)+" ", seg(fg(cGreen).with(AttrBold)))
		}
		tc := t.Chain(r.Target)
		target := displayTarget(r)
		if r.Goto {
			target = "@" + target
		}
		if r.Disabled && r.Entry == nil {
			target = "?"
		}
		x = s.Text(x, y, x1, pad(target, tW)+" ", seg(targetStyle(r.Target, tc != nil && !tc.Builtin)))
		switch {
		case r.Disabled && r.Entry == nil:
			s.Text(x, y, x1, "original missing from state file (id "+r.DisabledID+")", seg(fg(cRed)))
		case r.MatchText == "" && r.TargetOpts == "":
			s.Text(x, y, x1, "(all packets)", seg(stDim))
		default:
			x = s.Text(x, y, x1, r.MatchText, seg(stDefault))
			if r.TargetOpts != "" {
				if r.MatchText != "" {
					x++
				}
				s.Text(x, y, x1, r.TargetOpts, seg(fg(cCyan)))
			}
		}
	}
}

func (a *App) drawDetail(y, h int) {
	s, W := a.scr, a.scr.w
	s.Fill(0, y, W, 1, '─', stBorder)
	c := a.chain()
	if c == nil {
		return
	}
	label, text, st := "", "", stDefault
	if r := a.rule(); a.focus == paneRules && r != nil {
		pk, by := r.Counters()
		label = fmt.Sprintf(" rule #%d · %d pkts · %d bytes ", r.Num, pk, by)
		switch {
		case r.Disabled && r.Entry == nil:
			label += "· DISABLED "
			text, st = "original rule "+r.DisabledID+" is missing from "+a.store.Path+"; the placeholder can only be deleted", fg(cRed)
		case r.Disabled:
			label += "· DISABLED since " + r.Entry.DisabledAt.Format("2006-01-02 15:04") + " "
			text, st = "# "+joinArgs(append([]string{a.be().Name(), "-t", a.tableName(), "-A", c.Name}, r.Spec...)), stDim
		default:
			text = joinArgs(append([]string{a.be().Name(), "-t", a.tableName(), "-A", c.Name}, r.Spec...))
		}
	} else {
		label = " chain " + c.Name + " "
		var parts []string
		switch {
		case c.Virtual:
			parts = append(parts, "built-in chain, not created in the kernel yet (policy ACCEPT)")
		case c.Builtin:
			parts = append(parts, fmt.Sprintf("built-in chain, policy %s (%d packets, %d bytes)", c.Policy, c.Pkts, c.Bytes))
		case c.Refs == 0:
			parts = append(parts, "user-defined chain, not referenced by any rule")
		default:
			parts = append(parts, fmt.Sprintf("user-defined chain, referenced by %d rule(s) in %s", c.Refs, strings.Join(c.RefBy, ", ")))
		}
		var jumps []string
		disabled := 0
		seen := map[string]bool{}
		for _, r := range c.Rules {
			if r.Disabled {
				disabled++
			}
			if tc := a.table().Chain(r.Target); tc != nil && !tc.Builtin && !seen[r.Target] {
				seen[r.Target] = true
				jumps = append(jumps, r.Target)
			}
		}
		parts = append(parts, fmt.Sprintf("%d rule(s), %d disabled", len(c.Rules), disabled))
		if len(jumps) > 0 {
			parts = append(parts, "jumps to "+strings.Join(jumps, ", "))
		}
		text = strings.Join(parts, " · ")
	}
	s.Text(2, y, W, label, stTitle)
	lines := wrapText(text, W-2)
	for i := 0; i < h && i < len(lines); i++ {
		l := lines[i]
		if i == h-1 && len(lines) > h {
			l = fit(l+" …", W-2)
		}
		s.Text(1, y+1+i, W, l, st)
	}
}

func (a *App) drawStatus(y int) {
	s, W := a.scr, a.scr.w
	switch a.mode {
	case modePrompt:
		x := s.Text(0, y, W, a.promptLabel, fg(cYellow).with(AttrBold))
		a.edit.Draw(s, x, y, W-x, stDefault)
		a.modal(0, 0, 0, 0, nil, nil)
		a.hit(x, y, W, y+1, func(cx int, _ bool) { a.edit.clickAt(cx-x, true) }, nil)
	case modeConfirm:
		s.Text(1, y, W, "press y to confirm, any other key to cancel", fg(cYellow).with(AttrBold))
	default:
		st := stDefault
		switch a.msgKind {
		case msgOK:
			st = fg(cGreen)
		case msgWarn:
			st = fg(cYellow)
		case msgErr:
			st = fg(cRed).with(AttrBold)
		}
		s.Text(1, y, W, a.msg, st)
	}
}

// keyHint is an entry of the key hint line; clicking it sends key.
type keyHint struct {
	k, d string
	key  Key // KeyUnknown: not clickable
}

func (a *App) drawKeys(y int) {
	s, W := a.scr, a.scr.w
	none := Key{Code: KeyUnknown}
	r := runeKey
	var hints []keyHint
	switch {
	case a.mode == modePrompt:
		hints = append([]keyHint{{"Enter", "ok", Key{Code: KeyEnter}}, {"Esc", "cancel", Key{Code: KeyEsc}}}, a.promptHints...)
	case a.mode == modeConfirm:
		hints = []keyHint{{"y", "yes", none}, {"other", "no", none}}
	case a.mode == modeText:
		hints = []keyHint{{"Up/Dn", "scroll", none}, {"Esc", "close", none}}
	case a.mode == modeList || a.mode == modeForm:
		hints = nil
	case a.view == viewMonitor:
		hints = []keyHint{{"?", "help", r('?')}, {"Esc", "rules", Key{Code: KeyEsc}}, {"Tab", "NFLOG/TRACE", Key{Code: KeyTab}},
			{"Space", "pause", r(' ')}, {"Enter", "details", Key{Code: KeyEnter}}, {"/", "filter", r('/')},
			{"c", "clear", r('c')}, {"x", "stop", r('x')}}
		if a.mon.kind == monNFLOG {
			hints = append(hints, keyHint{"n", "group", r('n')}, keyHint{"W", "pcap", r('W')})
		} else {
			hints = append(hints, keyHint{"T", "start", r('T')})
		}
		hints = append(hints, keyHint{"q", "quit", r('q')})
	case a.focus == paneChains:
		hints = []keyHint{{"?", "help", r('?')}, {"Enter", "rules", Key{Code: KeyEnter}}, {"a", "add", r('a')},
			{"Y", "copy all", r('Y')}, {"p", "paste", r('p')}, {"N", "new", r('N')}, {"R", "rename", r('R')},
			{"X", "delete", r('X')}, {"F", "flush", r('F')}, {"P", "policy", r('P')}, {"/", "filter", r('/')},
			{"s", "search", r('s')}, {"w", "watch", r('w')}, {"q", "quit", r('q')}}
	default:
		hints = []keyHint{{"?", "help", r('?')}, {"a/i/o", "add", r('a')}, {"e", "edit", r('e')}, {"d", "del", r('d')},
			{"y", "copy", r('y')}, {"p", "paste", r('p')}, {"Space", "on/off", r(' ')}, {"K/J", "move", none},
			{"Enter", "open", Key{Code: KeyEnter}}, {"/", "filter", r('/')}, {"s", "search", r('s')},
			{"D", "disabled", r('D')}, {"w", "watch", r('w')}, {"q", "quit", r('q')}}
	}
	x := 0
	for _, h := range hints {
		if x+strWidth(h.k)+strWidth(h.d)+3 > W {
			break
		}
		hx := x
		x = s.Text(x, y, W, " "+h.k+" ", stKey)
		x = s.Text(x, y, W, " "+h.d+" ", stDefault)
		if h.key.Code != KeyUnknown {
			key := h.key
			a.hit(hx, y, x, y+1, func(int, bool) { a.handleKey(key) }, nil)
		}
	}
}

func (a *App) drawText() {
	s, W, H := a.scr, a.scr.w, a.scr.h
	bw := min(W-4, 110)
	iw := bw - 4
	var lines []textLine
	for _, l := range a.txtLines {
		for _, w := range wrapText(l.text, iw) {
			lines = append(lines, textLine{w, l.st})
		}
	}
	bh := min(H-2, len(lines)+2)
	rows := bh - 2
	a.txtRows = rows
	a.txtTop = clamp(a.txtTop, 0, max(0, len(lines)-rows))
	x0, y0 := (W-bw)/2, (H-bh)/2
	footer := "Esc close"
	if len(lines) > rows {
		footer = fmt.Sprintf("%d-%d/%d · Up/Dn PgUp/PgDn · Esc close", a.txtTop+1, a.txtTop+rows, len(lines))
	}
	drawBox(s, x0, y0, bw, bh, a.txtTitle, footer)
	scroll := func(d int) { a.txtTop += 3 * d }
	a.modal(0, 0, 0, 0, func(int, bool) { a.mode = modeNormal }, scroll)
	a.modal(x0, y0, bw, bh, nil, scroll)
	for i := 0; i < rows && a.txtTop+i < len(lines); i++ {
		l := lines[a.txtTop+i]
		s.Text(x0+2, y0+1+i, x0+bw-2, l.text, l.st)
	}
}

func (a *App) drawConfirm() {
	s, W, H := a.scr, a.scr.w, a.scr.h
	bw := min(W-4, 100)
	iw := bw - 4
	var lines []textLine
	for _, l := range a.confirmLines {
		for _, w := range wrapText(l.text, iw) {
			lines = append(lines, textLine{w, l.st})
		}
	}
	bh := min(H-2, len(lines)+4)
	rows := bh - 4
	a.confirmRows = rows
	a.confirmTop = clamp(a.confirmTop, 0, max(0, len(lines)-rows))
	x0, y0 := (W-bw)/2, (H-bh)/2
	footer := "y confirm · n / Esc cancel"
	if len(lines) > rows {
		footer = fmt.Sprintf("%d-%d/%d · Up/Dn scroll · %s", a.confirmTop+1, a.confirmTop+rows, len(lines), footer)
	}
	drawBox(s, x0, y0, bw, bh, a.confirmTitle, footer)
	for i := 0; i < rows && a.confirmTop+i < len(lines); i++ {
		l := lines[a.confirmTop+i]
		s.Text(x0+2, y0+1+i, x0+bw-2, l.text, l.st)
	}
	by := y0 + bh - 2
	yes, no := "  Yes (y)  ", "  No (n)  "
	nx := x0 + bw - 2 - strWidth(no)
	yx := nx - 2 - strWidth(yes)
	s.Text(yx, by, x0+bw-2, yes, Style{Fg: cBlack, Bg: cRed, Attr: AttrBold})
	s.Text(nx, by, x0+bw-2, no, Style{Fg: cBlack, Bg: cWhite, Attr: AttrBold})
	a.modal(0, 0, 0, 0, nil, func(d int) { a.confirmTop += 3 * d })
	a.hit(yx, by, yx+strWidth(yes), by+1, func(int, bool) { a.handleKey(runeKey('y')) }, nil)
	a.hit(nx, by, nx+strWidth(no), by+1, func(int, bool) { a.handleKey(runeKey('n')) }, nil)
}

func (a *App) drawList() {
	s, W, H := a.scr, a.scr.w, a.scr.h
	bw := min(W-4, 140)
	bh := min(H-2, max(len(a.lstItems), 1)+2)
	rows := bh - 2
	a.lstRows = rows
	a.lstTop = scrollTo(a.lstSel, a.lstTop, rows, len(a.lstItems))
	x0, y0 := (W-bw)/2, (H-bh)/2
	footer := a.lstHint
	if len(a.lstItems) > 0 {
		footer = fmt.Sprintf("%d/%d · %s", a.lstSel+1, len(a.lstItems), a.lstHint)
	}
	drawBox(s, x0, y0, bw, bh, a.lstTitle, footer)
	scroll := func(d int) { a.lstSel = clamp(a.lstSel+3*d, 0, len(a.lstItems)-1) }
	a.modal(0, 0, 0, 0, func(int, bool) { a.mode = modeNormal }, scroll)
	a.modal(x0, y0, bw, bh, nil, scroll)
	if len(a.lstItems) == 0 {
		s.Text(x0+2, y0+1, x0+bw-2, "(nothing found)", stDim)
	}
	for i := 0; i < rows && a.lstTop+i < len(a.lstItems); i++ {
		idx := a.lstTop + i
		it, y := a.lstItems[idx], y0+1+i
		st := it.st
		if idx == a.lstSel {
			st = stSel
			s.Fill(x0+1, y, bw-2, 1, ' ', st)
		}
		a.hit(x0+1, y, x0+bw-1, y+1, func(_ int, dbl bool) {
			a.lstSel = idx
			if dbl && a.lstEnter != nil {
				a.lstEnter(idx)
			}
		}, nil)
		s.Text(x0+2, y, x0+bw-2, it.text, st)
	}
}

func (a *App) showHelp() {
	h := func(s string) textLine { return textLine{s, fg(cCyan).with(AttrBold)} }
	t := func(s string) textLine { return textLine{s, stDefault} }
	lines := []textLine{
		h("Navigation"),
		t("  Up/Down j/k  PgUp/PgDn  Home/End g/G   move the cursor"),
		t("  Tab  Left/Right h/l                     switch between chains and rules"),
		t("  1-5  [ ]                                switch table"),
		t("  6         switch between IPv4 (iptables) and IPv6 (ip6tables); also -6 on the command line"),
		t("  Enter     on a chain: show its rules; on a rule: jump to its target chain, or details"),
		t("  Backspace b                             go back after jumping to a chain"),
		t("  /         filter the focused pane (live; several words = all must match), Esc clears"),
		t("  s         search all tables, Enter jumps to the result"),
		t(""),
		h("View"),
		t("  w         watch mode (auto refresh; +pkts shows packets since the previous refresh)"),
		t("  + / -     change the refresh interval     r F5  refresh now"),
		t("  x         exact / abbreviated counters    L     log of executed commands"),
		t("  D         list of disabled rules (also orphaned ones)"),
		t(""),
		h("Rules"),
		t("  a         add a rule at the end of the chain"),
		t("  i / o     insert a rule above / below the cursor"),
		t("  e         edit (replace) the rule"),
		t("  d Del     delete the rule (asks first)"),
		t("  Space     disable / re-enable the rule"),
		t("  K / J     move up / down (also Shift+Up/Down)     m  move to a position"),
		t(""),
		h("Packet monitors"),
		t("  n         NFLOG: receive the packets that NFLOG rules send to a group (asks for the group;"),
		t("            the \"Log via NFLOG\" template adds such a rule). Packets are decoded (IPv4/IPv6,"),
		t("            TCP/UDP/ICMP); W writes them as a pcap file for Wireshark / tcpdump."),
		t("  T         TRACE: show the path of packets matched by a TRACE rule (raw table, \"Trace packets\""),
		t("            template) through every chain, with the verdict of each step. Uses"),
		t("            xtables-monitor --trace (nft backend) or the kernel log (legacy backend)."),
		t("  In a monitor: Space pause · Enter details · / filter · c clear · x stop · Tab other"),
		t("  monitor · Esc back to the rules (capture keeps running in the background)."),
		t(""),
		h("Copy & paste"),
		t("  y         copy the rule under the cursor"),
		t("  Y         copy every rule shown in the chain (with a / filter: only the matching ones)"),
		t("  p         paste below the cursor; in the chains pane: at the end of the chain"),
		t("  One rule opens the add dialog prefilled; several are confirmed and inserted atomically."),
		t("  Rules can go between IPv4 and IPv6: ICMP, REJECT and TTL/HL options are converted and"),
		t("  listed; addresses of the wrong family and missing jump targets must be fixed first."),
		t("  The clipboard is kept in memory only."),
		t(""),
		h("Add / edit dialog"),
		t("  Simple mode builds a rule from a template and fields; F2 (or Ctrl-T) switches to advanced"),
		t("  mode for raw iptables arguments, carrying the rule over. Tab/Up/Down move between fields,"),
		t("  Left/Right/Space or a letter change a choice, Ctrl-P/N recall earlier rules, Enter submits."),
		t("  \"Add as: disabled\" stores the rule without activating it."),
		t(""),
		h("Chains"),
		t("  N new   R rename   X delete   F flush   P set policy   Z zero counters"),
		t(""),
		h("Mouse"),
		t("  click a tab, chain or rule to select it; double-click opens a chain / jumps to the"),
		t("  target / shows details; the wheel scrolls; the key hints at the bottom, the dialog"),
		t("  buttons and WATCH / IPv4 in the title bar are clickable. M toggles the mouse; while"),
		t("  it is on, hold Shift to select text in the terminal."),
		t(""),
		h("Other"),
		t("  W         write the ruleset (iptables-save) to a file; defaults to rules.v4 / rules.v6 in"),
		t("            the current directory, overwriting an existing file asks first. Counters are"),
		t("            left out, also those of the chains; Ctrl-T in the prompt includes them (-c)"),
		t("  q Ctrl-C  quit"),
		t(""),
		h("How disabling works"),
		t("  iptables has no off switch, so a disabled rule is replaced in place by a placeholder rule"),
		t("  without a target: -m comment --comment " + disabledPrefix + "<id>. It matches nothing that"),
		t("  matters and keeps the position. The original rule is kept in the state file"),
		t("  " + a.store.Path + " under that id and is put back with its counters on re-enable."),
		t("  Keep that file together with saved rulesets; without it a placeholder cannot be restored."),
		t(""),
		h("Safety"),
		t("  Adding, editing and deleting rules (and chain, policy and file changes) show what will"),
		t("  change and the exact commands, and only run after y / Yes. Space (on/off) and K/J are immediate."),
		t("  Every change re-reads the chain first and is refused if the rule at that position is no"),
		t("  longer the same (e.g. changed by docker or fail2ban). Moves use iptables-restore and are atomic."),
		t("  Changes are live immediately and are NOT persistent until saved (W)."),
	}
	a.showText("iptables-tui "+a.version+" help", lines)
}
