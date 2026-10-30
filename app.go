package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type pane int

const (
	paneChains pane = iota
	paneRules
)

type uiMode int

const (
	modeNormal uiMode = iota
	modePrompt
	modeConfirm
	modeText
	modeList
	modeForm
)

type msgKind int

const (
	msgInfo msgKind = iota
	msgOK
	msgWarn
	msgErr
)

// job runs on the worker goroutine: an optional mutation followed by a
// fresh snapshot.
type job struct {
	be    *Backend
	fn    func(*Backend) (string, error)
	sel   *selTarget
	onErr func(error)
}

type result struct {
	fam      Family
	snap     *Snapshot
	fetchErr error
	mutation bool
	msg      string
	err      error
	sel      *selTarget
	onErr    func(error)
}

// selTarget moves the cursor once a job's snapshot arrives.
type selTarget struct {
	table, chain string
	num          int // rule number; -1 = last rule; 0 = keep the rule cursor
}

type tableView struct {
	chain   string
	ruleSel int
	focus   pane
}

type navEntry struct {
	chain   string
	ruleSel int
}

type textLine struct {
	text string
	st   Style
}

type options struct {
	fam      Family
	table    string
	watch    bool
	interval time.Duration
	bins     map[Family]string
	mouse    bool
}

// hitRegion is a clickable screen area registered while drawing. Later
// regions are on top; a modal region swallows events that no region above it
// handled.
type hitRegion struct {
	x0, y0, x1, y1 int
	click          func(x int, dbl bool)
	wheel          func(d int)
	modal          bool
}

type App struct {
	scr      *Screen
	opts     options
	store    *Store
	backends map[Family]*Backend
	snaps    map[Family]*Snapshot
	prevCtr  map[Family]map[string]uint64
	fam      Family
	tIdx     int

	focus               pane
	chainSel, chainTop  int
	ruleSel, ruleTop    int
	curChain            string
	chainFilter         string
	ruleFilter          string
	views               map[string]tableView
	back                []navEntry
	chainRows, ruleRows int

	watch    bool
	interval time.Duration
	ticker   *time.Ticker
	exact    bool

	busy    int
	mutBusy int
	msg     string
	msgKind msgKind

	mode uiMode

	edit         LineEdit
	promptLabel  string
	promptSubmit func(string)
	promptChange func(string)
	promptCancel func()

	confirmTitle string
	confirmLines []textLine
	confirmYes   func()
	confirmNo    func()

	txtTitle string
	txtLines []textLine
	txtTop   int
	txtRows  int

	lstTitle   string
	lstHint    string
	lstItems   []textLine
	lstSel     int
	lstTop     int
	lstRows    int
	lstEnter   func(i int)
	lstKey     func(k Key, i int) bool
	lstRebuild func()

	form       *ruleForm
	preferAdv  bool
	ruleHist   []string
	lastSearch string

	mouse      bool
	hits       []hitRegion
	lastClick  time.Time
	lastClickX int
	lastClickY int

	jobs    chan job
	results chan result
	quit    bool
}

func newApp(opts options, be *Backend, store *Store) *App {
	a := &App{
		scr:      newScreen(os.Stdout),
		opts:     opts,
		store:    store,
		backends: map[Family]*Backend{opts.fam: be},
		snaps:    map[Family]*Snapshot{},
		prevCtr:  map[Family]map[string]uint64{},
		fam:      opts.fam,
		views:    map[string]tableView{},
		watch:    opts.watch,
		interval: opts.interval,
		mouse:    opts.mouse,
		jobs:     make(chan job, 32),
		results:  make(chan result, 32),
	}
	for i, t := range tableNames {
		if t == opts.table {
			a.tIdx = i
		}
	}
	return a
}

func (a *App) Run() error {
	st, err := makeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("stdin is not a terminal: %w", err)
	}
	os.Stdout.WriteString("\x1b[?1049h\x1b[?25l\x1b[?7l")
	a.setMouse(a.mouse)
	defer func() {
		os.Stdout.WriteString("\x1b[?1006l\x1b[?1000l\x1b[0m\x1b[?7h\x1b[?25h\x1b[?1049l")
		st.restore()
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "panic: %v\n%s", r, debug.Stack())
			os.Exit(2)
		}
	}()
	a.resize()

	inCh := make(chan []byte, 16)
	go readInput(os.Stdin, inCh)
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT)
	go a.worker()
	a.refresh()
	a.setWatch(a.watch)

	var pending []byte
	escTimer := time.NewTimer(time.Hour)
	escTimer.Stop()
	for !a.quit {
		a.draw()
		var tick <-chan time.Time
		if a.ticker != nil {
			tick = a.ticker.C
		}
		select {
		case b, ok := <-inCh:
			if !ok {
				return nil
			}
			var keys []Key
			keys, pending = parseKeys(append(pending, b...), false)
			if len(pending) > 0 {
				escTimer.Reset(30 * time.Millisecond)
			}
			for _, k := range keys {
				if a.handleKey(k); a.quit {
					break
				}
			}
		case <-escTimer.C:
			keys, _ := parseKeys(pending, true)
			pending = nil
			for _, k := range keys {
				a.handleKey(k)
			}
		case <-winch:
			a.resize()
		case r := <-a.results:
			a.applyResult(r)
		case <-tick:
			if a.busy == 0 {
				a.refresh()
			}
		case <-term:
			return nil
		}
	}
	return nil
}

func (a *App) resize() {
	w, h, err := termSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		w, h = 80, 24
	}
	a.scr.Resize(w, h)
}

// ---- jobs ----

func (a *App) worker() {
	for j := range a.jobs {
		a.results <- runJob(j)
	}
}

func runJob(j job) (res result) {
	res = result{fam: j.be.Family, sel: j.sel, onErr: j.onErr, mutation: j.fn != nil}
	defer func() {
		if r := recover(); r != nil {
			res.err = fmt.Errorf("internal error: %v", r)
		}
	}()
	if j.fn != nil {
		res.msg, res.err = j.fn(j.be)
	}
	res.snap, res.fetchErr = j.be.Snapshot()
	return res
}

func (a *App) be() *Backend { return a.backends[a.fam] }

func (a *App) enqueue(fn func(*Backend) (string, error), sel *selTarget, onErr func(error)) {
	if fn != nil && a.mutBusy > 0 {
		a.setMsg(msgWarn, "previous operation still running")
		return
	}
	select {
	case a.jobs <- job{be: a.be(), fn: fn, sel: sel, onErr: onErr}:
		a.busy++
		if fn != nil {
			a.mutBusy++
		}
	default:
		a.setMsg(msgWarn, "busy, try again")
	}
}

func (a *App) mutate(fn func(*Backend) (string, error), sel *selTarget) { a.enqueue(fn, sel, nil) }

func (a *App) refresh() { a.enqueue(nil, nil, nil) }

func (a *App) applyResult(r result) {
	a.busy--
	if r.mutation {
		a.mutBusy--
	}
	if r.snap != nil {
		a.computeDeltas(r.fam, r.snap)
		a.snaps[r.fam] = r.snap
	}
	if r.mutation {
		if r.err != nil {
			a.setMsg(msgErr, r.err.Error())
		} else if r.msg != "" {
			a.setMsg(msgOK, r.msg)
		}
	}
	if r.fetchErr != nil {
		text := "refresh failed: " + r.fetchErr.Error()
		if r.mutation && r.err != nil {
			text = r.err.Error() + "; " + text
		}
		a.setMsg(msgErr, text)
	}
	if r.fam != a.fam {
		return
	}
	a.syncSelection()
	if r.sel != nil && r.err == nil {
		a.applySel(r.sel)
	}
	if r.err != nil && r.onErr != nil && a.mode == modeNormal {
		r.onErr(r.err)
	}
	if a.mode == modeList && a.lstRebuild != nil {
		a.lstRebuild()
	}
}

// computeDeltas sets per-rule packet deltas against the previous snapshot.
// Rules are keyed by chain, text and occurrence so that shifted positions
// still line up.
func (a *App) computeDeltas(fam Family, s *Snapshot) {
	prev := a.prevCtr[fam]
	next := make(map[string]uint64, len(prev))
	for tn, t := range s.Tables {
		for _, c := range t.Chains {
			ck := tn + "\x00" + c.Name
			if p, ok := prev[ck]; ok && c.Pkts >= p {
				c.DPkts, c.HasDelta = c.Pkts-p, true
			}
			next[ck] = c.Pkts
			seen := map[string]int{}
			for _, r := range c.Rules {
				n := seen[r.Raw]
				seen[r.Raw] = n + 1
				k := ck + "\x00" + r.Raw + "\x00" + strconv.Itoa(n)
				if p, ok := prev[k]; ok && r.Pkts >= p {
					r.DPkts, r.HasDelta = r.Pkts-p, true
				}
				next[k] = r.Pkts
			}
		}
	}
	a.prevCtr[fam] = next
}

func (a *App) setMsg(k msgKind, text string) { a.msg, a.msgKind = text, k }

func (a *App) setWatch(on bool) {
	a.watch = on
	if a.ticker != nil {
		a.ticker.Stop()
		a.ticker = nil
	}
	if on {
		a.ticker = time.NewTicker(a.interval)
	}
}

var intervals = []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 3 * time.Second,
	5 * time.Second, 10 * time.Second, 30 * time.Second, time.Minute}

func (a *App) changeInterval(d int) {
	i := sort.Search(len(intervals), func(i int) bool { return intervals[i] >= a.interval })
	if i < len(intervals) && intervals[i] != a.interval && d < 0 {
		i-- // between two steps: "down" goes to the lower one
	}
	i = clamp(i+d, 0, len(intervals)-1)
	a.interval = intervals[i]
	a.setWatch(a.watch)
	a.setMsg(msgInfo, "refresh interval "+fmtDur(a.interval))
}

// ---- selection ----

func clamp(v, lo, hi int) int {
	if v > hi {
		v = hi
	}
	if v < lo {
		v = lo
	}
	return v
}

func (a *App) tableName() string { return tableNames[a.tIdx] }

func (a *App) table() *Table {
	s := a.snaps[a.fam]
	if s == nil {
		return nil
	}
	return s.Tables[a.tableName()]
}

func (a *App) chains() []*Chain {
	t := a.table()
	if t == nil {
		return nil
	}
	if a.chainFilter == "" {
		return t.Chains
	}
	f := strings.ToLower(a.chainFilter)
	var out []*Chain
	for _, c := range t.Chains {
		if strings.Contains(strings.ToLower(c.Name), f) {
			out = append(out, c)
		}
	}
	return out
}

func (a *App) chain() *Chain {
	cs := a.chains()
	if a.chainSel >= 0 && a.chainSel < len(cs) {
		return cs[a.chainSel]
	}
	return nil
}

func matchTerms(text string, terms []string) bool {
	for _, t := range terms {
		if !strings.Contains(text, t) {
			return false
		}
	}
	return true
}

func (a *App) rules() []*Rule {
	c := a.chain()
	if c == nil {
		return nil
	}
	if a.ruleFilter == "" {
		return c.Rules
	}
	terms := strings.Fields(strings.ToLower(a.ruleFilter))
	var out []*Rule
	for _, r := range c.Rules {
		if matchTerms(r.search, terms) {
			out = append(out, r)
		}
	}
	return out
}

func (a *App) rule() *Rule {
	rs := a.rules()
	if a.ruleSel >= 0 && a.ruleSel < len(rs) {
		return rs[a.ruleSel]
	}
	return nil
}

func (a *App) userChains() []string {
	var out []string
	if t := a.table(); t != nil {
		for _, c := range t.Chains {
			if !c.Builtin {
				out = append(out, c.Name)
			}
		}
	}
	return out
}

// syncSelection re-finds the selected chain by name after the data changed
// and clamps both cursors.
func (a *App) syncSelection() {
	cs := a.chains()
	for i, c := range cs {
		if c.Name == a.curChain {
			a.chainSel = i
			break
		}
	}
	a.chainSel = clamp(a.chainSel, 0, len(cs)-1)
	if c := a.chain(); c == nil {
		a.curChain = ""
	} else if c.Name != a.curChain {
		a.curChain = c.Name
		a.ruleSel = 0
	}
	a.ruleSel = clamp(a.ruleSel, 0, len(a.rules())-1)
}

func (a *App) setChainSel(i int) {
	a.chainSel = clamp(i, 0, len(a.chains())-1)
	if c := a.chain(); c != nil && c.Name != a.curChain {
		a.curChain = c.Name
		a.ruleSel, a.ruleTop = 0, 0
	}
}

func (a *App) selectChain(name string) bool {
	for _, pass := range []int{0, 1} {
		for i, c := range a.chains() {
			if c.Name == name {
				a.setChainSel(i)
				return true
			}
		}
		if pass == 0 && a.chainFilter != "" {
			a.chainFilter = ""
			continue
		}
	}
	return false
}

func (a *App) selectRuleNum(num int) {
	rs := a.rules()
	if num < 0 {
		a.ruleSel = len(rs) - 1
	}
	for i, r := range rs {
		if r.Num == num {
			a.ruleSel = i
		}
	}
	a.ruleSel = clamp(a.ruleSel, 0, len(rs)-1)
}

func (a *App) applySel(s *selTarget) {
	if s.table != a.tableName() {
		return
	}
	if s.chain != "" {
		a.selectChain(s.chain)
	}
	if s.num != 0 {
		a.selectRuleNum(s.num)
	}
}

func (a *App) viewKey() string { return a.fam.String() + "/" + a.tableName() }

func (a *App) saveView() {
	a.views[a.viewKey()] = tableView{chain: a.curChain, ruleSel: a.ruleSel, focus: a.focus}
}

func (a *App) restoreView() {
	v := a.views[a.viewKey()]
	a.chainFilter, a.ruleFilter = "", ""
	a.curChain, a.chainSel, a.ruleSel, a.focus = v.chain, 0, v.ruleSel, v.focus
	a.chainTop, a.ruleTop = 0, 0
	a.back = nil
	a.syncSelection()
}

func (a *App) switchTable(i int) {
	if i == a.tIdx {
		return
	}
	a.saveView()
	a.tIdx = i
	a.restoreView()
}

func (a *App) toggleFamily() {
	nf := V6
	if a.fam == V6 {
		nf = V4
	}
	if a.backends[nf] == nil {
		b, err := newBackend(nf, a.opts.bins[nf], a.store)
		if err != nil {
			a.setMsg(msgErr, nf.String()+": "+err.Error())
			return
		}
		a.backends[nf] = b
	}
	a.saveView()
	a.fam = nf
	a.restoreView()
	a.refresh()
	a.setMsg(msgInfo, "switched to "+nf.String())
}

func (a *App) jumpTo(table, chain string, num int) {
	for i, t := range tableNames {
		if t == table {
			a.switchTable(i)
		}
	}
	a.selectChain(chain)
	if num > 0 {
		a.ruleFilter = ""
		a.focus = paneRules
		a.selectRuleNum(num)
	} else {
		a.focus = paneChains
	}
}

// ---- modes ----

func (a *App) startPrompt(label, initial string, hist *[]string, submit func(string)) {
	a.mode = modePrompt
	a.promptLabel = label
	a.edit.Reset(initial, hist)
	a.promptSubmit, a.promptChange, a.promptCancel = submit, nil, nil
}

// confirm shows a dialog describing a change; only y/Y runs yes, any other
// key cancels (and runs confirmNo, if the caller sets one afterwards).
func (a *App) confirm(title string, lines []textLine, yes func()) {
	a.mode = modeConfirm
	a.confirmTitle, a.confirmLines = title, lines
	a.confirmYes, a.confirmNo = yes, nil
}

var (
	stConfHead = stDefault.with(AttrBold)
	stConfCmd  = fg(cGreen)
	stConfWarn = fg(cRed).with(AttrBold)
)

func plain(s string) textLine { return textLine{s, stDefault} }

// cmdLines renders commands that a change will run, for confirmation dialogs.
func (a *App) cmdLines(cmds ...[]string) []textLine {
	lines := []textLine{plain(""), {"will run:", stConfHead}}
	for _, c := range cmds {
		lines = append(lines, textLine{"  " + joinArgs(append([]string{a.be().Name()}, c...)), stConfCmd})
	}
	return lines
}

func (a *App) showText(title string, lines []textLine) {
	a.mode = modeText
	a.txtTitle, a.txtLines, a.txtTop = title, lines, 0
}

func (a *App) showList(title, hint string, items []textLine, enter func(int), key func(Key, int) bool) {
	a.mode = modeList
	a.lstTitle, a.lstHint, a.lstItems = title, hint, items
	a.lstSel, a.lstTop = 0, 0
	a.lstEnter, a.lstKey, a.lstRebuild = enter, key, nil
}

// setMouse turns terminal mouse reporting (button presses, SGR encoding) on or off.
func (a *App) setMouse(on bool) {
	a.mouse = on
	if on {
		a.scr.out.WriteString("\x1b[?1000h\x1b[?1006h")
	} else {
		a.scr.out.WriteString("\x1b[?1006l\x1b[?1000l")
	}
	a.scr.out.Flush()
}

func (a *App) hit(x0, y0, x1, y1 int, click func(x int, dbl bool), wheel func(int)) {
	a.hits = append(a.hits, hitRegion{x0: x0, y0: y0, x1: x1, y1: y1, click: click, wheel: wheel})
}

// modal blocks events below it in the given area (the whole screen if w == 0).
func (a *App) modal(x0, y0, w, h int, click func(x int, dbl bool), wheel func(int)) {
	if w == 0 {
		x0, y0, w, h = 0, 0, a.scr.w, a.scr.h
	}
	a.hits = append(a.hits, hitRegion{x0: x0, y0: y0, x1: x0 + w, y1: y0 + h, click: click, wheel: wheel, modal: true})
}

func (a *App) handleMouse(m Mouse) {
	wheel := m.Btn == 64 || m.Btn == 65
	if !m.Press || m.Motion || (!wheel && m.Btn != 0) {
		return
	}
	if a.mode == modeNormal {
		a.msg = ""
	}
	for i := len(a.hits) - 1; i >= 0; i-- {
		h := a.hits[i]
		if m.X < h.x0 || m.X >= h.x1 || m.Y < h.y0 || m.Y >= h.y1 {
			continue
		}
		switch {
		case wheel && h.wheel != nil:
			d := 1
			if m.Btn == 64 {
				d = -1
			}
			h.wheel(d)
			return
		case !wheel && h.click != nil:
			now := time.Now()
			dbl := now.Sub(a.lastClick) < 400*time.Millisecond && m.X == a.lastClickX && m.Y == a.lastClickY
			a.lastClick, a.lastClickX, a.lastClickY = now, m.X, m.Y
			if dbl {
				a.lastClick = time.Time{}
			}
			h.click(m.X, dbl)
			return
		}
		if h.modal {
			return
		}
	}
}

func (a *App) handleKey(k Key) {
	if k.Code == KeyMouse {
		a.handleMouse(k.Mouse)
		return
	}
	switch a.mode {
	case modePrompt:
		a.handlePromptKey(k)
		return
	case modeConfirm:
		a.mode = modeNormal
		if k.is('y') || k.is('Y') {
			a.confirmYes()
		} else if a.confirmNo != nil {
			a.confirmNo()
		} else {
			a.setMsg(msgInfo, "cancelled")
		}
		return
	case modeText:
		a.handleTextKey(k)
		return
	case modeList:
		a.handleListKey(k)
		return
	case modeForm:
		a.handleFormKey(k)
		return
	}
	if k.Alt {
		return
	}
	a.msg = ""
	if a.handleGlobalKey(k) {
		return
	}
	if a.focus == paneChains {
		a.handleChainKey(k)
	} else {
		a.handleRuleKey(k)
	}
}

func (a *App) handlePromptKey(k Key) {
	act, changed := a.edit.Handle(k)
	switch act {
	case editSubmit:
		a.mode = modeNormal
		v := a.edit.Value()
		if a.edit.hist != nil {
			addHist(a.edit.hist, v)
		}
		if a.promptSubmit != nil {
			a.promptSubmit(v)
		}
	case editCancel:
		a.mode = modeNormal
		if a.promptCancel != nil {
			a.promptCancel()
		}
	default:
		if changed && a.promptChange != nil {
			a.promptChange(a.edit.Value())
		}
	}
}

func addHist(h *[]string, v string) {
	v = strings.TrimSpace(v)
	if v == "" || (len(*h) > 0 && (*h)[len(*h)-1] == v) {
		return
	}
	*h = append(*h, v)
	if len(*h) > 200 {
		*h = (*h)[1:]
	}
}

func (a *App) handleTextKey(k Key) {
	switch {
	case k.Code == KeyEsc, k.Code == KeyEnter, k.is('q'), k.is('?'), k.ctrl('c'):
		a.mode = modeNormal
	case k.Code == KeyUp, k.is('k'):
		a.txtTop--
	case k.Code == KeyDown, k.is('j'):
		a.txtTop++
	case k.Code == KeyPgUp, k.ctrl('b'):
		a.txtTop -= a.txtRows
	case k.Code == KeyPgDn, k.ctrl('f'), k.is(' '):
		a.txtTop += a.txtRows
	case k.Code == KeyHome, k.is('g'):
		a.txtTop = 0
	case k.Code == KeyEnd, k.is('G'):
		a.txtTop = 1 << 30
	}
}

func (a *App) handleListKey(k Key) {
	n := len(a.lstItems)
	switch {
	case k.Code == KeyEsc, k.is('q'), k.ctrl('c'):
		a.mode = modeNormal
		return
	case k.Code == KeyUp, k.is('k'):
		a.lstSel--
	case k.Code == KeyDown, k.is('j'):
		a.lstSel++
	case k.Code == KeyPgUp, k.ctrl('b'):
		a.lstSel -= a.lstRows
	case k.Code == KeyPgDn, k.ctrl('f'):
		a.lstSel += a.lstRows
	case k.Code == KeyHome, k.is('g'):
		a.lstSel = 0
	case k.Code == KeyEnd, k.is('G'):
		a.lstSel = n - 1
	case k.Code == KeyEnter:
		if n > 0 && a.lstEnter != nil {
			a.lstEnter(a.lstSel)
		}
	default:
		if n > 0 && a.lstKey != nil {
			a.lstKey(k, a.lstSel)
		}
	}
	a.lstSel = clamp(a.lstSel, 0, len(a.lstItems)-1)
}

func (a *App) handleFormKey(k Key) {
	f := a.form
	submit, cancel := f.handleKey(k)
	if !f.editing {
		a.preferAdv = f.advanced
	}
	switch {
	case cancel:
		a.mode = modeNormal
		a.setMsg(msgInfo, "cancelled")
	case submit:
		args, err := f.build()
		if err != nil {
			f.err = err.Error()
			return
		}
		if f.advanced {
			addHist(&a.ruleHist, f.get("rule"))
		}
		a.mode = modeNormal
		disabled := f.disabled()
		title, lines := f.describe(args, disabled)
		if lines == nil {
			return
		}
		if findTarget(args) == 0 && !disabled && contains([]string{"ACCEPT", "DROP", "REJECT"}, args[1]) {
			// a rule without conditions affects every packet: easy to lock yourself out
			warn := textLine{fmt.Sprintf("WARNING: this rule has no conditions and will %s EVERY packet in %s/%s!",
				args[1], f.table, f.chain), stConfWarn}
			lines = append([]textLine{lines[0], warn}, lines[1:]...)
		}
		a.confirm(title, lines, func() { f.submit(args, disabled) })
		a.confirmNo = func() { a.form, a.mode = f, modeForm }
	}
}

// reopenForm shows a form again with the error of its failed submission.
func (a *App) reopenForm(f *ruleForm) func(error) {
	return func(err error) {
		a.form = f
		f.err = err.Error()
		a.mode = modeForm
	}
}

// ---- key handling ----

func (a *App) handleGlobalKey(k Key) bool {
	switch {
	case k.is('q'), k.ctrl('c'):
		a.quit = true
	case k.is('?'), k.Code == KeyF1:
		a.showHelp()
	case k.is('w'):
		a.setWatch(!a.watch)
		if a.watch {
			a.refresh()
			a.setMsg(msgInfo, "watch on, refreshing every "+fmtDur(a.interval))
		} else {
			a.setMsg(msgInfo, "watch off")
		}
	case k.is('+'), k.is('='):
		a.changeInterval(1)
	case k.is('-'), k.is('_'):
		a.changeInterval(-1)
	case k.is('r'), k.Code == KeyF5, k.ctrl('l'):
		a.scr.Invalidate()
		a.refresh()
	case k.is('x'):
		a.exact = !a.exact
	case k.is('M'):
		a.setMouse(!a.mouse)
		if a.mouse {
			a.setMsg(msgInfo, "mouse on (hold Shift to select text in the terminal)")
		} else {
			a.setMsg(msgInfo, "mouse off")
		}
	case k.is('6'):
		a.toggleFamily()
	case k.is('['):
		a.switchTable((a.tIdx + len(tableNames) - 1) % len(tableNames))
	case k.is(']'):
		a.switchTable((a.tIdx + 1) % len(tableNames))
	case k.Code == KeyRune && k.Rune >= '1' && k.Rune <= '5' && !k.Alt:
		a.switchTable(int(k.Rune - '1'))
	case k.Code == KeyTab, k.Code == KeyBacktab:
		if a.focus == paneChains {
			a.focus = paneRules
		} else {
			a.focus = paneChains
		}
	case k.is('/'):
		a.startFilter()
	case k.is('s'):
		a.actSearch()
	case k.is('D'):
		a.showDisabled()
	case k.is('L'):
		a.showLog()
	case k.is('a'):
		a.actAdd(0)
	case k.is('N'):
		a.actNewChain()
	case k.is('X'):
		a.actDeleteChain()
	case k.is('F'):
		a.actFlushChain()
	case k.is('P'):
		a.actPolicy()
	case k.is('R'):
		a.actRenameChain()
	case k.is('Z'):
		a.actZero()
	case k.is('W'):
		a.actSave()
	default:
		return false
	}
	return true
}

func (a *App) handleChainKey(k Key) {
	switch {
	case k.plain(KeyUp), k.is('k'):
		a.setChainSel(a.chainSel - 1)
	case k.plain(KeyDown), k.is('j'):
		a.setChainSel(a.chainSel + 1)
	case k.Code == KeyPgUp, k.ctrl('b'):
		a.setChainSel(a.chainSel - max(1, a.chainRows))
	case k.Code == KeyPgDn, k.ctrl('f'):
		a.setChainSel(a.chainSel + max(1, a.chainRows))
	case k.Code == KeyHome, k.is('g'):
		a.setChainSel(0)
	case k.Code == KeyEnd, k.is('G'):
		a.setChainSel(len(a.chains()) - 1)
	case k.Code == KeyEnter, k.Code == KeyRight, k.is('l'):
		if a.chain() != nil {
			a.focus = paneRules
		}
	case k.is('d'), k.Code == KeyDelete:
		a.actDeleteChain()
	case k.Code == KeyEsc:
		if a.chainFilter != "" {
			a.chainFilter = ""
			a.syncSelection()
		}
	}
}

func (a *App) handleRuleKey(k Key) {
	n := len(a.rules())
	switch {
	case (k.Code == KeyUp && k.Shift) || k.is('K'):
		a.actMove(-1)
	case (k.Code == KeyDown && k.Shift) || k.is('J'):
		a.actMove(1)
	case k.plain(KeyUp), k.is('k'):
		a.ruleSel = clamp(a.ruleSel-1, 0, n-1)
	case k.plain(KeyDown), k.is('j'):
		a.ruleSel = clamp(a.ruleSel+1, 0, n-1)
	case k.Code == KeyPgUp, k.ctrl('b'):
		a.ruleSel = clamp(a.ruleSel-max(1, a.ruleRows), 0, n-1)
	case k.Code == KeyPgDn, k.ctrl('f'):
		a.ruleSel = clamp(a.ruleSel+max(1, a.ruleRows), 0, n-1)
	case k.Code == KeyHome, k.is('g'):
		a.ruleSel = 0
	case k.Code == KeyEnd, k.is('G'):
		a.ruleSel = clamp(n-1, 0, n-1)
	case k.Code == KeyLeft, k.is('h'):
		a.focus = paneChains
	case k.Code == KeyEsc:
		if a.ruleFilter != "" {
			a.ruleFilter = ""
			a.syncSelection()
		} else {
			a.focus = paneChains
		}
	case k.Code == KeyEnter:
		a.actEnter()
	case k.Code == KeyBackspace, k.is('b'):
		a.goBack()
	case k.is('i'):
		a.actAdd(-1)
	case k.is('o'):
		a.actAdd(1)
	case k.is('e'):
		a.actEdit()
	case k.is('d'), k.Code == KeyDelete:
		a.actDelete()
	case k.is(' '):
		a.actToggle()
	case k.is('m'):
		a.actMoveTo()
	}
}

// ---- actions ----

func (a *App) curRef() (ruleRef, *Rule, bool) {
	r, c := a.rule(), a.chain()
	if r == nil || c == nil {
		return ruleRef{}, nil, false
	}
	return ruleRef{table: a.tableName(), chain: c.Name, num: r.Num, raw: r.Raw}, r, true
}

func (a *App) startFilter() {
	if a.focus == paneChains {
		old := a.chainFilter
		a.startPrompt("filter chains: ", old, nil, func(s string) { a.chainFilter = strings.TrimSpace(s) })
		a.promptChange = func(s string) {
			a.chainFilter = strings.TrimSpace(s)
			a.chainSel = 0
			a.syncSelection()
		}
		a.promptCancel = func() { a.chainFilter = old; a.syncSelection() }
		return
	}
	old := a.ruleFilter
	a.startPrompt("filter rules: ", old, nil, func(s string) { a.ruleFilter = strings.TrimSpace(s) })
	a.promptChange = func(s string) {
		a.ruleFilter = strings.TrimSpace(s)
		a.ruleSel, a.ruleTop = 0, 0
	}
	a.promptCancel = func() { a.ruleFilter = old; a.syncSelection() }
}

// actAdd opens the add-rule form: where < 0 inserts above the cursor,
// where > 0 below it, 0 appends.
func (a *App) actAdd(where int) {
	c := a.chain()
	if c == nil {
		a.setMsg(msgErr, "no chain selected")
		return
	}
	table, chain := a.tableName(), c.Name
	pos := 0
	var anchor *ruleRef
	if where != 0 {
		pos = 1
		if ref, r, ok := a.curRef(); ok {
			anchor = &ref
			pos = r.Num
			if where > 0 {
				pos++
			}
		}
	}
	f := newRuleForm(a.fam, table, chain, a.userChains(), &a.ruleHist)
	f.advanced = a.preferAdv
	if pos > 0 {
		f.title = fmt.Sprintf("Insert rule at #%d in %s/%s", pos, table, chain)
		f.cmdPrefix = []string{"-I", chain, strconv.Itoa(pos)}
	} else {
		f.title = fmt.Sprintf("Append rule to %s/%s", table, chain)
		f.cmdPrefix = []string{"-A", chain}
	}
	f.describe = func(args []string, disabled bool) (string, []textLine) {
		head := fmt.Sprintf("Append this rule to %s/%s?", table, chain)
		if pos > 0 {
			head = fmt.Sprintf("Insert this rule at #%d in %s/%s?", pos, table, chain)
		}
		lines := []textLine{{head, stConfHead}, plain(""), plain("  " + joinArgs(args))}
		cmd := append([]string{"-t", table}, f.cmdPrefix...)
		if disabled {
			lines = append(lines, plain(""), textLine{"added DISABLED: the rule is kept in " + a.store.Path +
				", only a placeholder goes into the chain", fg(cYellow)})
			return "Confirm: add rule", append(lines, a.cmdLines(append(cmd, placeholderArgs("<new id>")...))...)
		}
		return "Confirm: add rule", append(lines, a.cmdLines(append(cmd, args...))...)
	}
	f.submit = func(args []string, disabled bool) {
		state := ""
		if disabled {
			state = " (disabled)"
		}
		sel := &selTarget{table: table, chain: chain, num: pos}
		if pos == 0 {
			sel.num = -1
		}
		a.focus = paneRules
		a.enqueue(func(b *Backend) (string, error) {
			return fmt.Sprintf("added rule to %s/%s%s", table, chain, state),
				b.AddRule(table, chain, pos, anchor, args, disabled)
		}, sel, a.reopenForm(f))
	}
	a.form = f
	a.mode = modeForm
}

func (a *App) actEdit() {
	ref, r, ok := a.curRef()
	if !ok {
		return
	}
	if r.Disabled && r.Entry == nil {
		a.setMsg(msgErr, "the original of this disabled rule is missing from the state file")
		return
	}
	f := newRuleForm(a.fam, ref.table, ref.chain, a.userChains(), &a.ruleHist)
	f.editing, f.advanced = true, true
	f.title = fmt.Sprintf("Edit rule #%d in %s/%s", ref.num, ref.table, ref.chain)
	f.cmdPrefix = []string{"-R", ref.chain, strconv.Itoa(ref.num)}
	f.field("rule").set(joinArgs(r.Spec))
	if r.Disabled {
		f.field("as").set("disabled")
	}
	f.describe = func(args []string, disabled bool) (string, []textLine) {
		if equalArgs(args, r.Spec) && disabled == r.Disabled {
			a.setMsg(msgInfo, "no changes")
			return "", nil
		}
		state := map[bool]string{false: "enabled", true: "disabled"}
		lines := []textLine{
			{fmt.Sprintf("Replace rule #%d in %s/%s?", ref.num, ref.table, ref.chain), stConfHead},
			plain(""),
			{"  old: " + joinArgs(r.Spec), fg(cRed)},
			{"  new: " + joinArgs(args), fg(cGreen)},
		}
		if disabled != r.Disabled {
			lines = append(lines, textLine{"  state: " + state[r.Disabled] + " -> " + state[disabled], fg(cYellow)})
		}
		replace := []string{"-t", ref.table, "-R", ref.chain, strconv.Itoa(ref.num)}
		switch {
		case !r.Disabled && !disabled:
			lines = append(lines, plain(""), plain("the packet counters of this rule will be reset"))
			lines = append(lines, a.cmdLines(append(replace, args...))...)
		case !r.Disabled:
			lines = append(lines, plain(""), plain("the new rule is stored in "+a.store.Path))
			lines = append(lines, a.cmdLines(append(replace, placeholderArgs("<new id>")...))...)
		case disabled:
			lines = append(lines, plain(""), plain("only the stored copy in "+a.store.Path+" changes;"),
				plain("nothing changes in the kernel"))
		default:
			lines = append(lines, plain(""), plain("the stored copy is removed from "+a.store.Path))
			lines = append(lines, a.cmdLines(append(replace, args...))...)
		}
		return "Confirm: edit rule", lines
	}
	f.submit = func(args []string, disabled bool) {
		a.enqueue(func(b *Backend) (string, error) {
			return fmt.Sprintf("replaced rule #%d", ref.num), b.ReplaceRule(ref, args, disabled)
		}, &selTarget{table: ref.table, chain: ref.chain, num: ref.num}, a.reopenForm(f))
	}
	a.form = f
	a.mode = modeForm
}

func (a *App) actDelete() {
	ref, r, ok := a.curRef()
	if !ok {
		return
	}
	pk, by := r.Counters()
	lines := []textLine{
		{fmt.Sprintf("Delete rule #%d from %s/%s?", ref.num, ref.table, ref.chain), stConfHead},
		plain(""),
		plain("  " + strings.TrimPrefix(ruleSummary(r), "[off] ")),
		plain(""),
		plain(fmt.Sprintf("counters: %d packets, %d bytes", pk, by)),
	}
	if r.Disabled {
		lines = append(lines, textLine{"this rule is DISABLED; its stored copy in " + a.store.Path +
			" is removed too", fg(cYellow)})
	}
	lines = append(lines, textLine{"this cannot be undone", stConfWarn})
	lines = append(lines, a.cmdLines([]string{"-t", ref.table, "-D", ref.chain, strconv.Itoa(ref.num)})...)
	a.confirm("Confirm: delete rule", lines, func() {
		a.mutate(func(b *Backend) (string, error) {
			return fmt.Sprintf("deleted rule #%d from %s/%s", ref.num, ref.table, ref.chain), b.DeleteRule(ref)
		}, nil)
	})
}

func (a *App) actToggle() {
	ref, _, ok := a.curRef()
	if !ok {
		return
	}
	a.mutate(func(b *Backend) (string, error) {
		on, err := b.ToggleRule(ref)
		if on {
			return fmt.Sprintf("enabled rule #%d", ref.num), err
		}
		return fmt.Sprintf("disabled rule #%d", ref.num), err
	}, &selTarget{table: ref.table, chain: ref.chain, num: ref.num})
}

func (a *App) actMove(d int) {
	ref, _, ok := a.curRef()
	if !ok {
		return
	}
	to := ref.num + d
	if to < 1 || to > len(a.chain().Rules) {
		return
	}
	a.moveRule(ref, to)
}

func (a *App) moveRule(ref ruleRef, to int) {
	a.mutate(func(b *Backend) (string, error) {
		got, err := b.MoveRule(ref, to)
		return fmt.Sprintf("moved rule #%d to #%d", ref.num, got), err
	}, &selTarget{table: ref.table, chain: ref.chain, num: to})
}

func (a *App) actMoveTo() {
	ref, _, ok := a.curRef()
	if !ok {
		return
	}
	n := len(a.chain().Rules)
	a.startPrompt(fmt.Sprintf("move rule #%d to position (1-%d): ", ref.num, n), "", nil, func(s string) {
		to, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || to < 1 || to > n {
			a.setMsg(msgErr, "invalid position")
			return
		}
		a.moveRule(ref, to)
	})
}

func (a *App) actEnter() {
	r := a.rule()
	if r == nil {
		return
	}
	if tc := a.table().Chain(r.Target); tc != nil && !tc.Builtin {
		a.back = append(a.back, navEntry{chain: a.curChain, ruleSel: a.ruleSel})
		a.ruleFilter = ""
		a.selectChain(r.Target)
		a.ruleSel = 0
		return
	}
	a.showRuleDetail(r)
}

func (a *App) goBack() {
	if len(a.back) == 0 {
		return
	}
	e := a.back[len(a.back)-1]
	a.back = a.back[:len(a.back)-1]
	a.ruleFilter = ""
	if a.selectChain(e.chain) {
		a.ruleSel = clamp(e.ruleSel, 0, len(a.rules())-1)
	}
}

func (a *App) actNewChain() {
	table := a.tableName()
	a.startPrompt("new chain in "+table+": ", "", nil, func(s string) {
		name := strings.TrimSpace(s)
		if name == "" {
			return
		}
		a.focus = paneChains
		a.mutate(func(b *Backend) (string, error) {
			return "created chain " + name, b.NewChain(table, name)
		}, &selTarget{table: table, chain: name})
	})
}

func (a *App) actDeleteChain() {
	c := a.chain()
	if c == nil {
		return
	}
	table, name, n := a.tableName(), c.Name, len(c.Rules)
	switch {
	case c.Builtin:
		a.setMsg(msgErr, "built-in chains cannot be deleted")
		return
	case c.Refs > 0:
		a.setMsg(msgErr, fmt.Sprintf("%s is referenced by %d rule(s) in %s; remove them first",
			name, c.Refs, strings.Join(c.RefBy, ", ")))
		return
	}
	lines := []textLine{{fmt.Sprintf("Delete chain %s/%s?", table, name), stConfHead}}
	cmds := [][]string{{"-t", table, "-X", name}}
	if n > 0 {
		lines = append(lines, textLine{fmt.Sprintf("it still has %d rule(s), which are flushed first (atomically)", n), stConfWarn})
		cmds = [][]string{{"-t", table, "-F", name}, {"-t", table, "-X", name}}
	}
	if d := len(disabledIDs(c)); d > 0 {
		lines = append(lines, textLine{fmt.Sprintf("%d disabled rule(s) are dropped from the state file", d), fg(cYellow)})
	}
	a.confirm("Confirm: delete chain", append(lines, a.cmdLines(cmds...)...), func() {
		a.mutate(func(b *Backend) (string, error) {
			return "deleted chain " + name, b.DeleteChain(table, name, n > 0)
		}, nil)
	})
}

func (a *App) actFlushChain() {
	c := a.chain()
	if c == nil {
		return
	}
	table, name, n := a.tableName(), c.Name, len(c.Rules)
	if n == 0 {
		a.setMsg(msgInfo, name+" is already empty")
		return
	}
	lines := []textLine{{fmt.Sprintf("Remove all %d rule(s) from %s/%s?", n, table, name), stConfHead},
		textLine{"this cannot be undone", stConfWarn}}
	if d := len(disabledIDs(c)); d > 0 {
		lines = append(lines, textLine{fmt.Sprintf("%d disabled rule(s) are dropped from the state file", d), fg(cYellow)})
	}
	lines = append(lines, a.cmdLines([]string{"-t", table, "-F", name})...)
	a.confirm("Confirm: flush chain", lines, func() {
		a.mutate(func(b *Backend) (string, error) {
			return "flushed " + name, b.FlushChain(table, name)
		}, nil)
	})
}

func (a *App) actPolicy() {
	c := a.chain()
	if c == nil {
		return
	}
	if !c.Builtin {
		a.setMsg(msgErr, "only built-in chains have a policy")
		return
	}
	table, name, cur := a.tableName(), c.Name, c.Policy
	suggest := "DROP"
	if cur == "DROP" {
		suggest = "ACCEPT"
	}
	a.startPrompt(fmt.Sprintf("policy for %s/%s (ACCEPT/DROP): ", table, name), suggest, nil, func(s string) {
		p := strings.ToUpper(strings.TrimSpace(s))
		if p != "ACCEPT" && p != "DROP" {
			a.setMsg(msgErr, "policy must be ACCEPT or DROP")
			return
		}
		if p == cur {
			a.setMsg(msgInfo, "policy unchanged")
			return
		}
		lines := []textLine{{fmt.Sprintf("Change the policy of %s/%s from %s to %s?", table, name, cur, p), stConfHead}}
		if p == "DROP" {
			lines = append(lines, textLine{"packets not accepted by a rule will be dropped; make sure your own", stConfWarn},
				textLine{"access (e.g. ssh) is accepted by a rule first", stConfWarn})
		}
		lines = append(lines, a.cmdLines([]string{"-t", table, "-P", name, p})...)
		a.confirm("Confirm: set policy", lines, func() {
			a.mutate(func(b *Backend) (string, error) {
				return fmt.Sprintf("policy of %s set to %s", name, p), b.SetPolicy(table, name, p)
			}, nil)
		})
	})
}

func (a *App) actRenameChain() {
	c := a.chain()
	if c == nil {
		return
	}
	if c.Builtin {
		a.setMsg(msgErr, "built-in chains cannot be renamed")
		return
	}
	table, old := a.tableName(), c.Name
	a.startPrompt("rename chain "+old+" to: ", old, nil, func(s string) {
		name := strings.TrimSpace(s)
		if name == "" || name == old {
			return
		}
		a.curChain = name
		a.mutate(func(b *Backend) (string, error) {
			return fmt.Sprintf("renamed %s to %s", old, name), b.RenameChain(table, old, name)
		}, &selTarget{table: table, chain: name})
	})
}

func (a *App) actZero() {
	c := a.chain()
	if c == nil {
		return
	}
	table, name := a.tableName(), c.Name
	a.mutate(func(b *Backend) (string, error) {
		return "zeroed counters of " + name, b.ZeroCounters(table, name)
	}, nil)
}

func (a *App) actSave() {
	def := "/etc/iptables/rules.v4"
	if a.fam == V6 {
		def = "/etc/iptables/rules.v6"
	}
	a.startPrompt("write "+a.fam.String()+" ruleset (iptables-save) to: ", def, nil, func(s string) {
		path := strings.TrimSpace(s)
		if path == "" {
			return
		}
		save := func() {
			a.mutate(func(b *Backend) (string, error) {
				n, err := b.SaveTo(path)
				return fmt.Sprintf("wrote %d bytes to %s", n, path), err
			}, nil)
		}
		st, err := os.Stat(path)
		if err != nil {
			save()
			return
		}
		a.confirm("Confirm: overwrite file", []textLine{
			{"Overwrite " + path + "?", stConfHead},
			plain(fmt.Sprintf("existing file: %d bytes, modified %s", st.Size(), st.ModTime().Format("2006-01-02 15:04:05"))),
			plain("it is replaced with the current " + a.fam.String() + " ruleset (iptables-save)"),
		}, save)
	})
}

// ---- search & lists ----

type searchHit struct {
	table, chain string
	num          int
}

func ruleSummary(r *Rule) string {
	if r.Disabled && r.Entry == nil {
		return "(disabled, original missing: " + r.DisabledID + ")"
	}
	s := r.MatchText
	if r.Target != "" {
		s = strings.TrimSpace(s + " -j " + r.Target + " " + r.TargetOpts)
	}
	if s == "" {
		s = "(matches everything, no target)"
	}
	if r.Disabled {
		s = "[off] " + s
	}
	return s
}

func (a *App) actSearch() {
	a.startPrompt("search all "+a.fam.String()+" tables: ", a.lastSearch, nil, func(q string) {
		if q = strings.TrimSpace(q); q != "" {
			a.lastSearch = q
			a.showSearch(q)
		}
	})
}

func (a *App) showSearch(q string) {
	snap := a.snaps[a.fam]
	if snap == nil {
		return
	}
	terms := strings.Fields(strings.ToLower(q))
	var hits []searchHit
	var items []textLine
	for _, tn := range tableNames {
		for _, c := range snap.Tables[tn].Chains {
			if matchTerms(strings.ToLower(c.Name), terms) {
				hits = append(hits, searchHit{tn, c.Name, 0})
				items = append(items, textLine{fmt.Sprintf("%-8s %s  (chain, %d rules)", tn, c.Name, len(c.Rules)),
					fg(cBlue).with(AttrBold)})
			}
			for _, r := range c.Rules {
				if matchTerms(r.search, terms) {
					st := stDefault
					if r.Disabled {
						st = stDim
					}
					hits = append(hits, searchHit{tn, c.Name, r.Num})
					items = append(items, textLine{fmt.Sprintf("%-8s %s #%d  %s", tn, c.Name, r.Num, ruleSummary(r)), st})
				}
			}
		}
	}
	title := fmt.Sprintf("search %q: %d result(s)", q, len(hits))
	a.showList(title, "Enter jump · Esc close", items, func(i int) {
		a.mode = modeNormal
		h := hits[i]
		a.jumpTo(h.table, h.chain, h.num)
	}, nil)
}

// showDisabled lists all disabled rules of the current family: placeholders
// found in the kernel and state file entries whose placeholder is gone.
func (a *App) showDisabled() {
	type item struct {
		hit   searchHit
		entry *DisabledEntry
	}
	var list []item
	build := func() {
		snap := a.snaps[a.fam]
		if snap == nil {
			return
		}
		list = list[:0]
		var items []textLine
		placed := map[string]bool{}
		for _, tn := range tableNames {
			for _, c := range snap.Tables[tn].Chains {
				for _, r := range c.Rules {
					if !r.Disabled {
						continue
					}
					placed[r.DisabledID] = true
					list = append(list, item{searchHit{tn, c.Name, r.Num}, r.Entry})
					st := stDefault
					if r.Entry == nil {
						st = fg(cRed)
					}
					items = append(items, textLine{fmt.Sprintf("%-8s %s #%d  %s", tn, c.Name, r.Num,
						strings.TrimPrefix(ruleSummary(r), "[off] ")), st})
				}
			}
		}
		var orphans []*DisabledEntry
		for _, e := range snap.Entries {
			if !placed[e.ID] {
				orphans = append(orphans, e)
			}
		}
		sort.Slice(orphans, func(i, j int) bool { return orphans[i].DisabledAt.Before(orphans[j].DisabledAt) })
		for _, e := range orphans {
			list = append(list, item{searchHit{e.Table, e.Chain, 0}, e})
			items = append(items, textLine{fmt.Sprintf("%-8s %s  ORPHANED  %s  (disabled %s)", e.Table, e.Chain,
				joinArgs(e.Args), e.DisabledAt.Format("2006-01-02 15:04")), fg(cYellow)})
		}
		a.lstItems = items
		a.lstTitle = fmt.Sprintf("disabled %s rules (%d) · state file %s", a.fam, len(items), a.store.Path)
		a.lstSel = clamp(a.lstSel, 0, len(items)-1)
	}
	a.showList("", "Enter jump · a re-add orphan · x forget orphan · Esc close", nil, func(i int) {
		if it := list[i]; it.hit.num > 0 {
			a.mode = modeNormal
			a.jumpTo(it.hit.table, it.hit.chain, it.hit.num)
		} else {
			a.setMsg(msgWarn, "orphaned entry: its placeholder is no longer in the chain")
		}
	}, func(k Key, i int) bool {
		it := list[i]
		orphan := it.hit.num == 0 && it.entry != nil
		switch {
		case (k.is('a') || k.is('x')) && !orphan:
			a.setMsg(msgWarn, "only orphaned entries can be re-added or forgotten here")
		case k.is('a'):
			e := it.entry
			lines := []textLine{{fmt.Sprintf("Append this orphaned rule to %s/%s as an ENABLED rule?", e.Table, e.Chain), stConfHead},
				plain(""), plain("  " + joinArgs(e.Args))}
			lines = append(lines, a.cmdLines(append([]string{"-t", e.Table, "-A", e.Chain}, e.Args...))...)
			a.confirm("Confirm: re-add rule", lines, func() {
				a.mode = modeList
				a.mutate(func(b *Backend) (string, error) {
					return "re-added rule to " + e.Chain, b.RestoreEntry(e)
				}, nil)
			})
			a.confirmNo = func() { a.mode = modeList }
		case k.is('x'):
			e := it.entry
			lines := []textLine{{"Forget this orphaned entry? The rule will be lost.", stConfHead},
				plain(""), plain("  " + joinArgs(e.Args)), plain(""),
				plain("it is removed from " + a.store.Path + "; nothing changes in the kernel")}
			a.confirm("Confirm: forget entry", lines, func() {
				a.mode = modeList
				a.mutate(func(b *Backend) (string, error) {
					return "forgot entry " + e.ID, b.ForgetEntry(e.ID)
				}, nil)
			})
			a.confirmNo = func() { a.mode = modeList }
		default:
			return false
		}
		return true
	})
	a.lstRebuild = build
	build()
}

func (a *App) showLog() {
	entries := a.be().Log()
	var lines []textLine
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		status, st := "ok ", fg(cGreen)
		if e.Err != nil {
			status, st = "ERR", fg(cRed)
		}
		lines = append(lines, textLine{e.Time.Format("15:04:05") + " " + status + " " + e.Cmd, st})
		for _, l := range strings.Split(strings.TrimRight(e.Input, "\n"), "\n") {
			if l != "" {
				lines = append(lines, textLine{"           | " + l, stDim})
			}
		}
		if e.Err != nil {
			lines = append(lines, textLine{"           " + e.Err.Error(), fg(cRed)})
		}
	}
	if len(lines) == 0 {
		lines = append(lines, textLine{"(no commands executed yet)", stDim})
	}
	a.showText("command log ("+a.fam.String()+", newest first)", lines)
}

func groupArgs(spec []string) []string {
	var groups []string
	var cur []string
	ti := findTarget(spec)
	for i, s := range spec {
		if (s == "-m" || s == "--match" || i == ti) && len(cur) > 0 {
			groups = append(groups, joinArgs(cur))
			cur = nil
		}
		cur = append(cur, s)
	}
	if len(cur) > 0 {
		groups = append(groups, joinArgs(cur))
	}
	return groups
}

func (a *App) showRuleDetail(r *Rule) {
	b, table, chain := a.be(), a.tableName(), a.curChain
	bold := stDefault.with(AttrBold)
	lines := []textLine{
		{fmt.Sprintf("table %s · chain %s · rule #%d", table, chain, r.Num), bold},
		{"", stDefault},
	}
	if r.Disabled {
		lines = append(lines, textLine{"state:    DISABLED (id " + r.DisabledID + ")", fg(cRed).with(AttrBold)})
		if r.Entry != nil {
			lines = append(lines,
				textLine{"disabled: " + r.Entry.DisabledAt.Format("2006-01-02 15:04:05"), stDefault},
				textLine{fmt.Sprintf("counters: %d packets, %d bytes when disabled", r.Entry.Pkts, r.Entry.Bytes), stDefault})
		} else {
			lines = append(lines, textLine{"original rule not found in " + a.store.Path, fg(cRed)})
		}
	} else {
		lines = append(lines,
			textLine{"state:    enabled", fg(cGreen)},
			textLine{fmt.Sprintf("counters: %d packets, %d bytes", r.Pkts, r.Bytes), stDefault})
	}
	if r.Spec != nil {
		target := r.Target
		if target == "" {
			target = "(none: counts packets only)"
		} else if r.Goto {
			target += " (goto)"
		}
		lines = append(lines, textLine{"target:   " + target, stDefault}, textLine{"", stDefault},
			textLine{"command:", bold},
			textLine{"  " + joinArgs(append([]string{b.Name(), "-t", table, "-A", chain}, r.Spec...)), fg(cGreen)},
			textLine{"", stDefault}, textLine{"parts:", bold})
		for _, g := range groupArgs(r.Spec) {
			lines = append(lines, textLine{"  " + g, stDefault})
		}
	}
	if r.Disabled {
		lines = append(lines, textLine{"", stDefault}, textLine{"in the kernel:", bold},
			textLine{"  -A " + chain + " " + r.Raw, stDim})
	}
	a.showText("rule details", lines)
}
