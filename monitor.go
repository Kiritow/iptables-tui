package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type monKind int

const (
	monNFLOG monKind = iota
	monTRACE
)

func (k monKind) String() string {
	if k == monTRACE {
		return "TRACE"
	}
	return "NFLOG"
}

// monItem is one line of a live monitor: an NFLOG packet or a traced packet.
type monItem struct {
	time    time.Time
	summary string
	st      Style
	search  string
	pkt     *nflogPacket
	trace   *traceItem
	key     string
}

const monMax = 5000

// monitor collects items from a background source. All fields are guarded
// by mu; the UI is woken through notify.
type monitor struct {
	kind    monKind
	mu      sync.Mutex
	items   []*monItem
	total   int
	overrun int
	running bool
	err     string
	source  string
	group   uint16
	stopFn  func()
	notify  chan struct{}
	byKey   map[string]*monItem
}

func (m *monitor) ping() {
	select {
	case m.notify <- struct{}{}:
	default:
	}
}

// addLocked appends an item, keeping at most monMax.
func (m *monitor) addLocked(it *monItem) {
	m.items = append(m.items, it)
	m.total++
	if len(m.items) > monMax+monMax/10 {
		m.items = append([]*monItem(nil), m.items[len(m.items)-monMax:]...)
		keep := make(map[string]*monItem, len(m.byKey))
		for _, x := range m.items {
			if x.key != "" {
				keep[x.key] = x
			}
		}
		m.byKey = keep
	}
}

func (m *monitor) addPacket(p *nflogPacket) {
	s := p.summary()
	m.mu.Lock()
	m.addLocked(&monItem{time: p.Time, summary: s, search: strings.ToLower(s), pkt: p})
	m.mu.Unlock()
	m.ping()
}

// traceItemFor returns the item collecting steps for key, starting a new one
// for unknown or stale keys.
func (m *monitor) traceItemFor(key, id string, fam Family) *monItem {
	if it := m.byKey[key]; it != nil && time.Since(it.time) < traceTimeout {
		return it
	}
	it := &monItem{time: time.Now(), key: key, trace: &traceItem{ID: id, Family: fam}}
	m.byKey[key] = it
	m.addLocked(it)
	return it
}

func (it *monItem) refreshTrace() {
	it.summary, it.st = it.trace.summary()
	it.search = strings.ToLower(it.summary + " " + it.trace.Packet)
	for _, s := range it.trace.Steps {
		it.search += strings.ToLower(" " + s.Table + ":" + s.Chain + " " + s.Verdict + " " + s.Rule)
	}
}

// xtmLine handles a line of xtables-monitor --trace.
func (m *monitor) xtmLine(line string) {
	kind, fam, id, rest, ok := parseXtmLine(line)
	if !ok {
		return
	}
	m.mu.Lock()
	it := m.traceItemFor(fam.String()+"/"+id, id, fam)
	t := it.trace
	if kind == "PACKET" {
		switch {
		case t.Packet == "":
			t.Packet = rest
		case rest != t.lastPacket:
			t.Steps = append(t.Steps, traceStep{Type: "packet", Rule: rest})
		}
		t.lastPacket = rest
	} else {
		t.Steps = append(t.Steps, parseXtmStep(rest))
	}
	it.refreshTrace()
	m.mu.Unlock()
	m.ping()
}

// kmsgLine handles a legacy TRACE line from the kernel log.
func (m *monitor) kmsgLine(msg string) {
	step, pkt, ok := parseKmsgTrace(msg)
	if !ok {
		return
	}
	fam := V4
	if kv, _ := packetFields(pkt); strings.Contains(kv["SRC"], ":") {
		fam = V6
	}
	m.mu.Lock()
	it := m.traceItemFor("k/"+packetKey(pkt), "", fam)
	if it.trace.Packet == "" {
		it.trace.Packet = pkt
	}
	it.trace.Steps = append(it.trace.Steps, step)
	it.refreshTrace()
	m.mu.Unlock()
	m.ping()
}

func (m *monitor) finished(err error) {
	m.mu.Lock()
	m.running = false
	if err != nil {
		m.err = err.Error()
	}
	m.mu.Unlock()
	m.ping()
}

func (m *monitor) stop() {
	m.mu.Lock()
	stop := m.stopFn
	m.stopFn = nil
	m.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// ---- App side ----

const (
	viewRules = iota
	viewMonitor
)

func (a *App) monitorFor(k monKind) *monitor {
	if k == monTRACE {
		return a.trace
	}
	return a.nflog
}

func (a *App) showMonitor(m *monitor) {
	if a.view != viewMonitor || a.mon != m {
		a.monSel, a.monTop, a.monFollow, a.monFrozen, a.monFilter = 0, 0, true, nil, ""
	}
	a.view, a.mon = viewMonitor, m
}

// openNFLOG shows the NFLOG monitor, asking for a group to listen on if it is
// not running yet.
func (a *App) openNFLOG() {
	m := a.nflog
	m.mu.Lock()
	running, group := m.running, m.group
	m.mu.Unlock()
	if running {
		a.showMonitor(m)
		return
	}
	if group == 0 {
		group = uint16(defaultNFLOGGroup)
	}
	a.startPrompt("listen on NFLOG group (0-65535): ", strconv.Itoa(int(group)), nil, func(s string) {
		g, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
		if err != nil {
			a.setMsg(msgErr, "invalid group")
			return
		}
		a.showMonitor(m)
		a.startNFLOG(uint16(g))
	})
}

func (a *App) startNFLOG(group uint16) {
	m := a.nflog
	conn, err := openNFLOG(group)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.group = group
	if err != nil {
		m.err = err.Error()
		a.setMsg(msgErr, m.err)
		return
	}
	m.running, m.err, m.stopFn = true, "", conn.stop
	m.source = fmt.Sprintf("group %d", group)
	go func() {
		m.finished(conn.run(m.addPacket, func() {
			m.mu.Lock()
			m.overrun++
			m.mu.Unlock()
			m.ping()
		}))
	}()
	a.setMsg(msgOK, fmt.Sprintf("listening on NFLOG group %d", group))
}

func (a *App) openTrace() {
	m := a.trace
	a.showMonitor(m)
	m.mu.Lock()
	running := m.running
	m.mu.Unlock()
	if !running {
		a.startTrace()
	}
}

func (a *App) startTrace() {
	m := a.trace
	be := a.be()
	var stop func()
	var err error
	source := ""
	if strings.Contains(be.Version, "nf_tables") {
		var bin string
		if bin, err = findXtablesMonitor(be.Bin); err == nil {
			source = filepath.Base(bin) + " --trace"
			stop, err = startXtablesMonitor(bin, m.xtmLine, m.finished)
		}
	} else {
		source = "kernel log (/dev/kmsg)"
		stop, err = startKmsgTrace(m.kmsgLine, m.finished)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.source = source
	if err != nil {
		m.err = err.Error()
		a.setMsg(msgErr, "TRACE: "+m.err)
		return
	}
	m.running, m.err, m.stopFn = true, "", stop
	a.setMsg(msgOK, "tracing via "+source)
}

func (a *App) stopMonitors() {
	a.nflog.stop()
	a.trace.stop()
}

// monItems returns the items shown: the frozen copy while paused, filtered.
// The caller must hold a.mon.mu.
func (a *App) monItemsLocked() []*monItem {
	items := a.mon.items
	if a.monFrozen != nil {
		items = a.monFrozen
	}
	if a.monFilter == "" {
		return items
	}
	terms := strings.Fields(strings.ToLower(a.monFilter))
	var out []*monItem
	for _, it := range items {
		if matchTerms(it.search, terms) {
			out = append(out, it)
		}
	}
	return out
}

func (a *App) handleMonitorKey(k Key) {
	m := a.mon
	m.mu.Lock()
	n := len(a.monItemsLocked())
	m.mu.Unlock()
	move := func(i int) {
		a.monSel = clamp(i, 0, n-1)
		a.monFollow = a.monSel >= n-1 && a.monFrozen == nil
	}
	switch {
	case k.is('q'), k.ctrl('c'):
		a.quit = true
	case k.is('?'), k.Code == KeyF1:
		a.showHelp()
	case k.is('M'):
		a.setMouse(!a.mouse)
	case k.Code == KeyEsc, k.Code == KeyBackspace:
		if a.monFilter != "" && k.Code == KeyEsc {
			a.monFilter = ""
			return
		}
		a.view = viewRules
	case k.is('n'):
		a.openNFLOG()
	case k.is('T'):
		a.openTrace()
	case k.Code == KeyTab, k.Code == KeyBacktab:
		if m.kind == monNFLOG {
			a.showMonitor(a.trace)
		} else {
			a.showMonitor(a.nflog)
		}
	case k.plain(KeyUp), k.is('k'):
		move(a.monSel - 1)
	case k.plain(KeyDown), k.is('j'):
		move(a.monSel + 1)
	case k.Code == KeyPgUp, k.ctrl('b'):
		move(a.monSel - max(1, a.monRows))
	case k.Code == KeyPgDn, k.ctrl('f'):
		move(a.monSel + max(1, a.monRows))
	case k.Code == KeyHome, k.is('g'):
		move(0)
	case k.Code == KeyEnd, k.is('G'):
		a.monSel, a.monFollow = max(0, n-1), a.monFrozen == nil
	case k.is(' '):
		a.toggleFreeze()
	case k.is('f'):
		a.monFollow = !a.monFollow
		if a.monFollow {
			a.monSel = max(0, n-1)
		}
	case k.Code == KeyEnter:
		a.showMonDetail()
	case k.is('/'):
		old := a.monFilter
		a.startPrompt("filter "+m.kind.String()+": ", old, nil, func(s string) { a.monFilter = strings.TrimSpace(s) })
		a.promptChange = func(s string) { a.monFilter = strings.TrimSpace(s) }
		a.promptCancel = func() { a.monFilter = old }
	case k.is('c'):
		m.mu.Lock()
		m.items, m.byKey = nil, map[string]*monItem{}
		m.mu.Unlock()
		a.monFrozen, a.monSel, a.monTop = nil, 0, 0
	case k.is('x'):
		m.stop()
		a.setMsg(msgInfo, m.kind.String()+" stopped")
	case k.is('W') && m.kind == monNFLOG:
		a.actWritePcap()
	}
}

func (a *App) toggleFreeze() {
	m := a.mon
	if a.monFrozen != nil {
		a.monFrozen, a.monFollow = nil, true
		return
	}
	m.mu.Lock()
	a.monFrozen = append(make([]*monItem, 0, len(m.items)), m.items...)
	m.mu.Unlock()
	if len(a.monFrozen) == 0 {
		a.monFrozen = []*monItem{}
	}
	a.monFollow = false
}

func (a *App) selectedMonItem() *monItem {
	m := a.mon
	m.mu.Lock()
	defer m.mu.Unlock()
	items := a.monItemsLocked()
	if a.monSel < 0 || a.monSel >= len(items) {
		return nil
	}
	return items[a.monSel]
}

func (a *App) showMonDetail() {
	it := a.selectedMonItem()
	if it == nil {
		return
	}
	a.mon.mu.Lock()
	lines := a.monDetailLocked(it, true)
	a.mon.mu.Unlock()
	a.showText(a.mon.kind.String()+" details", lines)
}

// monDetailLocked describes an item; full adds everything (overlay), otherwise
// a short form for the detail area. The caller holds a.mon.mu.
func (a *App) monDetailLocked(it *monItem, full bool) []textLine {
	bold := stDefault.with(AttrBold)
	var lines []textLine
	if p := it.pkt; p != nil {
		pi := p.Info
		hook := "?"
		if p.Hook >= 0 && p.Hook < len(hookNames) {
			hook = hookNames[p.Hook]
		}
		meta := fmt.Sprintf("group %d · hook %s · in %q out %q · mark 0x%x", p.Group, hook, p.InDev, p.OutDev, p.Mark)
		if p.UID >= 0 {
			meta += fmt.Sprintf(" · uid %d gid %d", p.UID, p.GID)
		}
		l3 := fmt.Sprintf("IPv%d %s -> %s · %s · ttl/hlim %d · length %d · captured %d bytes",
			pi.Version, pi.Src, pi.Dst, pi.protoName(), pi.TTL, pi.TotalLen, len(p.Payload))
		if pi.Version == 0 {
			l3 = fmt.Sprintf("not an IP packet · captured %d bytes", len(p.Payload))
		}
		if pi.ID >= 0 {
			l3 += fmt.Sprintf(" · id %d", pi.ID)
		}
		if pi.Frag {
			l3 += " · fragment"
		}
		var l4 string
		switch {
		case pi.SPort >= 0:
			l4 = fmt.Sprintf("%s port %d -> %d", pi.protoName(), pi.SPort, pi.DPort)
			if pi.TCPFlags != "" {
				l4 += " · flags " + pi.TCPFlags
			}
		case pi.ICMPType >= 0:
			l4 = fmt.Sprintf("%s type %d code %d", pi.protoName(), pi.ICMPType, pi.ICMPCode)
		}
		if !full {
			return []textLine{plain(meta + " · prefix " + quoteArg(p.Prefix)), plain(l3 + "  " + l4)}
		}
		lines = append(lines,
			textLine{p.Time.Format("2006-01-02 15:04:05.000000"), bold},
			plain("prefix:   "+quoteArg(p.Prefix)),
			plain(meta), plain(""), plain(l3))
		if l4 != "" {
			lines = append(lines, plain(l4))
		}
		lines = append(lines, plain(""), textLine{"payload (from the network header):", bold})
		for _, h := range hexDump(p.Payload, 512) {
			lines = append(lines, textLine{"  " + h, stDim})
		}
		return lines
	}
	t := it.trace
	if !full {
		var parts []string
		for _, s := range t.Steps {
			if s.Type == "packet" {
				parts = append(parts, "[packet changed]")
				continue
			}
			parts = append(parts, strings.TrimSpace(s.Table+":"+s.Chain+" "+stepVerdict(s)))
		}
		return []textLine{plain(strings.Join(parts, " -> "))}
	}
	lines = append(lines,
		textLine{fmt.Sprintf("%s · %s · trace %s", it.time.Format("15:04:05.000"), t.Family, t.ID), bold},
		plain("packet: "+t.Packet), plain(""), textLine{"path through the ruleset:", bold})
	for _, s := range t.Steps {
		if s.Type == "packet" {
			lines = append(lines, textLine{"  packet changed: " + s.Rule, fg(cYellow)})
			continue
		}
		v, st := stepVerdict(s), stDefault
		switch {
		case s.Verdict == "ACCEPT":
			st = fg(cGreen)
		case s.Verdict == "DROP":
			st = fg(cRed).with(AttrBold)
		}
		lines = append(lines, textLine{fmt.Sprintf("  %-22s %-7s %s", s.Table+":"+s.Chain, s.Type, v), st})
		if r := a.stepRule(t, s); r != "" {
			lines = append(lines, textLine{"      " + r, stDim})
		}
	}
	return lines
}

func stepVerdict(s traceStep) string {
	if s.Verdict != "" {
		return s.Verdict
	}
	if s.RuleNum > 0 {
		return "#" + strconv.Itoa(s.RuleNum)
	}
	return s.Type
}

// stepRule returns the rule text of a step: printed by xtables-monitor, or
// for legacy traces looked up by position in the current ruleset.
func (a *App) stepRule(t *traceItem, s traceStep) string {
	if s.Rule != "" || s.RuleNum <= 0 {
		return s.Rule
	}
	snap := a.snaps[t.Family]
	if snap == nil {
		return ""
	}
	c := snap.Tables[s.Table].Chain(s.Chain)
	if c == nil || s.RuleNum > len(c.Rules) {
		return ""
	}
	return "(now) -A " + s.Chain + " " + joinArgs(c.Rules[s.RuleNum-1].Spec)
}

// nflogRules lists rules sending packets to the given NFLOG group.
func (a *App) nflogRules(group uint16) []string {
	var out []string
	for _, fam := range []Family{V4, V6} {
		snap := a.snaps[fam]
		if snap == nil {
			continue
		}
		for _, tn := range tableNames {
			for _, c := range snap.Tables[tn].Chains {
				for _, r := range c.Rules {
					if r.Target == "NFLOG" && !r.Disabled && nflogGroup(r.Spec) == int(group) {
						out = append(out, fmt.Sprintf("%s %s/%s #%d", fam, tn, c.Name, r.Num))
					}
				}
			}
		}
	}
	return out
}

func (a *App) traceRules() []string {
	var out []string
	for _, fam := range []Family{V4, V6} {
		if snap := a.snaps[fam]; snap != nil {
			for _, c := range snap.Tables["raw"].Chains {
				for _, r := range c.Rules {
					if r.Target == "TRACE" && !r.Disabled {
						out = append(out, fmt.Sprintf("%s raw/%s #%d", fam, c.Name, r.Num))
					}
				}
			}
		}
	}
	return out
}

// nflogGroup returns the --nflog-group of an NFLOG rule (0 by default).
func nflogGroup(spec []string) int {
	for i := 0; i+1 < len(spec); i++ {
		if spec[i] == "--nflog-group" {
			g, _ := strconv.Atoi(spec[i+1])
			return g
		}
	}
	return 0
}

func (a *App) actWritePcap() {
	m := a.mon
	m.mu.Lock()
	var pkts []*nflogPacket
	for _, it := range a.monItemsLocked() {
		if it.pkt != nil {
			pkts = append(pkts, it.pkt)
		}
	}
	m.mu.Unlock()
	if len(pkts) == 0 {
		a.setMsg(msgWarn, "no packets to write")
		return
	}
	name := "nflog-" + time.Now().Format("20060102-150405") + ".pcap"
	a.promptPath(fmt.Sprintf("write %d packet(s) as pcap to: ", len(pkts)), name, "the captured packets (pcap)", func(path string) {
		n, err := writePcap(path, pkts)
		if err != nil {
			a.setMsg(msgErr, err.Error())
			return
		}
		a.setMsg(msgOK, fmt.Sprintf("wrote %d packet(s) to %s", n, path))
	})
}

// ---- drawing ----

func (a *App) drawMonitor() {
	s, W, H := a.scr, a.scr.w, a.scr.h
	m := a.mon
	m.mu.Lock()
	defer m.mu.Unlock()

	// row 1: monitor tabs and state
	x := 0
	for _, mm := range []*monitor{a.nflog, a.trace} {
		st := stDim
		if mm == m {
			st = stTabActive
		}
		state := "off"
		if mm == m {
			if m.running {
				state = "on"
			}
		} else {
			mm.mu.Lock()
			if mm.running {
				state = "on"
			}
			mm.mu.Unlock()
		}
		tx, target := x, mm
		x = s.Text(x, 1, W, fmt.Sprintf(" %s %s ", mm.kind, state), st)
		a.hit(tx, 1, x, 2, func(int, bool) { a.showMonitor(target) }, nil)
		x++
	}
	items := a.monItemsLocked()
	var info []string
	if m.source != "" {
		info = append(info, m.source)
	}
	unit := "packets"
	if m.kind == monTRACE {
		unit = "traces"
	}
	info = append(info, fmt.Sprintf("%d %s", m.total, unit))
	if m.overrun > 0 {
		info = append(info, fmt.Sprintf("%d overrun(s): packets lost", m.overrun))
	}
	if a.monFilter != "" {
		info = append(info, "filter~"+quoteArg(a.monFilter)+fmt.Sprintf(" (%d)", len(items)))
	}
	switch {
	case a.monFrozen != nil:
		info = append(info, "PAUSED")
	case a.monFollow:
		info = append(info, "following")
	}
	text := strings.Join(info, " · ")
	ist := fg(cCyan)
	if m.overrun > 0 || a.monFrozen != nil {
		ist = fg(cYellow).with(AttrBold)
	}
	s.Text(max(x+1, W-strWidth(text)-1), 1, W, fit(text, W-x-2), ist)

	// list
	const detailH = 3
	top, bot := 3, H-2-detailH-1
	hdr := " time         iface        proto  packet"
	if m.kind == monTRACE {
		hdr = " time         iface        proto  packet  => final verdict  (steps)"
	}
	s.Fill(0, 2, W, 1, ' ', stColHdr)
	s.Text(0, 2, W, hdr, stColHdr)
	rows := bot - top
	a.monRows = rows
	if a.monFollow {
		a.monSel = len(items) - 1
	}
	a.monSel = clamp(a.monSel, 0, len(items)-1)
	a.monTop = scrollTo(a.monSel, a.monTop, rows, len(items))
	a.hit(0, top, W, bot, nil, func(d int) {
		a.monSel = clamp(a.monSel+3*d, 0, len(items)-1)
		a.monFollow = d > 0 && a.monSel >= len(items)-1 && a.monFrozen == nil
	})
	if len(items) == 0 {
		for i, l := range a.monEmptyHint(m) {
			s.Text(1, top+i, W, l.text, l.st)
		}
	}
	for i := 0; i < rows && a.monTop+i < len(items); i++ {
		idx := a.monTop + i
		it, y := items[idx], top+i
		st := it.st
		if idx == a.monSel {
			st = stSel
			s.Fill(0, y, W, 1, ' ', st)
		}
		x := s.Text(1, y, W, it.time.Format("15:04:05.000")+" ", map[bool]Style{true: stSel, false: stDim}[idx == a.monSel])
		s.Text(x, y, W, it.summary, st)
		a.hit(0, y, W, y+1, func(_ int, dbl bool) {
			a.monSel, a.monFollow = idx, false
			if dbl {
				a.showMonDetail()
			}
		}, nil)
	}

	// detail area
	s.Fill(0, bot, W, 1, '─', stBorder)
	if a.monSel >= 0 && a.monSel < len(items) {
		it := items[a.monSel]
		s.Text(2, bot, W, " "+m.kind.String()+" #"+strconv.Itoa(a.monSel+1)+" ", stTitle)
		var lines []string
		for _, l := range a.monDetailLocked(it, false) {
			lines = append(lines, wrapText(l.text, W-2)...)
		}
		for i := 0; i < detailH && i < len(lines); i++ {
			s.Text(1, bot+1+i, W, lines[i], stDefault)
		}
	}
}

func (a *App) monEmptyHint(m *monitor) []textLine {
	dim, warn := stDim, fg(cYellow)
	var lines []textLine
	if m.err != "" {
		lines = append(lines, textLine{"error: " + m.err, fg(cRed).with(AttrBold)}, plain(""))
	}
	if m.kind == monNFLOG {
		if !m.running {
			return append(lines, textLine{"NFLOG capture is not running. Press n to listen on a group.", dim})
		}
		lines = append(lines, textLine{fmt.Sprintf("Waiting for packets on NFLOG group %d…", m.group), dim})
		if rs := a.nflogRules(m.group); len(rs) > 0 {
			return append(lines, textLine{"rules sending to this group: " + strings.Join(rs, ", "), dim})
		}
		return append(lines, textLine{fmt.Sprintf("No rule sends packets to group %d yet. Add one with the \"Log via NFLOG\" template", m.group), warn},
			textLine{fmt.Sprintf("(-j NFLOG --nflog-group %d), e.g. in filter/INPUT.", m.group), warn})
	}
	if !m.running {
		return append(lines, textLine{"Tracing is not running. Press T to start.", dim})
	}
	lines = append(lines, textLine{"Waiting for traced packets…", dim})
	if rs := a.traceRules(); len(rs) > 0 {
		return append(lines, textLine{"TRACE rules: " + strings.Join(rs, ", "), dim})
	}
	return append(lines, textLine{"No TRACE rule exists. Add one in raw PREROUTING or OUTPUT with the \"Trace packets\" template", warn},
		textLine{"and keep its match narrow: every traced packet is reported at every step. Remove it when done.", warn})
}

// promptPath asks for a file path (default name in the current directory)
// and confirms before overwriting an existing file.
func (a *App) promptPath(label, defName, what string, write func(path string)) {
	def := defName
	if wd, err := os.Getwd(); err == nil {
		def = filepath.Join(wd, defName)
	}
	a.startPrompt(label, def, nil, func(s string) {
		path := strings.TrimSpace(s)
		if path == "" {
			a.setMsg(msgInfo, "cancelled")
			return
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		st, err := os.Stat(path)
		switch {
		case os.IsNotExist(err):
			write(path)
			return
		case err != nil:
			a.setMsg(msgErr, err.Error())
			return
		case st.IsDir():
			a.setMsg(msgErr, path+" is a directory")
			return
		}
		lines := []textLine{
			{"WARNING: " + path + " already exists and will be OVERWRITTEN!", stConfWarn},
			plain(""),
			plain(fmt.Sprintf("existing file: %d bytes, modified %s", st.Size(), st.ModTime().Format("2006-01-02 15:04:05"))),
		}
		if lst, err := os.Lstat(path); err == nil && lst.Mode()&os.ModeSymlink != 0 {
			if target, err := filepath.EvalSymlinks(path); err == nil {
				lines = append(lines, textLine{"it is a symlink; the file written is " + target, fg(cYellow)})
			}
		}
		lines = append(lines, plain("its contents are replaced with "+what))
		a.confirm("Confirm: overwrite file", lines, func() { write(path) })
	})
}
