package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Family int

const (
	V4 Family = 4
	V6 Family = 6
)

func (f Family) String() string {
	if f == V6 {
		return "IPv6"
	}
	return "IPv4"
}

var tableNames = []string{"filter", "nat", "mangle", "raw", "security"}

var builtinChains = map[string][]string{
	"filter":   {"INPUT", "FORWARD", "OUTPUT"},
	"nat":      {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"},
	"mangle":   {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"},
	"raw":      {"PREROUTING", "OUTPUT"},
	"security": {"INPUT", "FORWARD", "OUTPUT"},
}

// disabledPrefix marks the placeholder rule that keeps the position of a
// disabled rule; the comment is followed by the ID of its state file entry.
const disabledPrefix = "iptui-disabled-"

const (
	cmdTimeout = 30 * time.Second
	lockWait   = "5"
)

type Rule struct {
	Num   int
	Pkts  uint64
	Bytes uint64
	Raw   string   // text after "-A CHAIN" exactly as printed by iptables-save
	Args  []string // Raw, tokenized
	// Spec is the effective rule: Args for an enabled rule, the stored
	// original for a disabled one (nil if its state entry is missing).
	Spec       []string
	Disabled   bool
	DisabledID string
	Entry      *DisabledEntry
	Target     string
	Goto       bool
	MatchText  string
	TargetOpts string
	search     string

	// filled in by the UI from consecutive snapshots
	DPkts    uint64
	HasDelta bool
}

type Chain struct {
	Name    string
	Policy  string // empty for user-defined chains
	Builtin bool
	Virtual bool // built-in chain that does not exist in the kernel yet
	Pkts    uint64
	Bytes   uint64
	Rules   []*Rule
	RefBy   []string // chains with rules jumping here
	Refs    int      // number of rules jumping here

	DPkts    uint64
	HasDelta bool
}

type Table struct {
	Name   string
	Loaded bool
	Chains []*Chain
	byName map[string]*Chain
}

func (t *Table) Chain(name string) *Chain {
	if t == nil {
		return nil
	}
	return t.byName[name]
}

func (t *Table) addChain(c *Chain) {
	t.Chains = append(t.Chains, c)
	t.byName[c.Name] = c
}

type Snapshot struct {
	Tables   map[string]*Table
	Entries  map[string]*DisabledEntry // state file entries of this family
	Warnings []string
	Time     time.Time
}

// ---- argument helpers ----

// splitArgs tokenizes a rule the way iptables-restore and a POSIX shell would:
// whitespace separates words, double quotes allow backslash escapes, single
// quotes are literal.
func splitArgs(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inTok := false
	var quote rune
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch quote {
		case '"':
			switch {
			case c == '\\' && i+1 < len(rs):
				i++
				cur.WriteRune(rs[i])
			case c == '"':
				quote = 0
			default:
				cur.WriteRune(c)
			}
			continue
		case '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteRune(c)
			}
			continue
		}
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inTok {
				out = append(out, cur.String())
				cur.Reset()
				inTok = false
			}
		case c == '"' || c == '\'':
			inTok = true
			quote = c
		case c == '\\' && i+1 < len(rs):
			inTok = true
			i++
			cur.WriteRune(rs[i])
		default:
			inTok = true
			cur.WriteRune(c)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote", quote)
	}
	if inTok {
		out = append(out, cur.String())
	}
	return out, nil
}

// quoteArg quotes s so that both splitArgs and iptables-restore read it back verbatim.
func quoteArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\n\r\"'\\") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		if r == '"' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

func joinArgs(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = quoteArg(a)
	}
	return strings.Join(q, " ")
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// findTarget returns the index of the -j/-g option in spec, or -1.
func findTarget(spec []string) int {
	for i := 0; i < len(spec)-1; i++ {
		switch spec[i] {
		case "--comment", "--string", "--hex-string", "--log-prefix", "--nflog-prefix", "--name":
			i++ // skip free-form values
		case "-j", "--jump", "-g", "--goto":
			return i
		}
	}
	return -1
}

// Counters returns the rule's counters; for a disabled rule those saved when
// it was disabled (the placeholder's own counters mean nothing).
func (r *Rule) Counters() (uint64, uint64) {
	if r.Disabled {
		if r.Entry != nil {
			return r.Entry.Pkts, r.Entry.Bytes
		}
		return 0, 0
	}
	return r.Pkts, r.Bytes
}

func placeholderID(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--comment" && strings.HasPrefix(args[i+1], disabledPrefix) {
			return strings.TrimPrefix(args[i+1], disabledPrefix)
		}
	}
	return ""
}

func placeholderArgs(id string) []string {
	return []string{"-m", "comment", "--comment", disabledPrefix + id}
}

// finalize derives the display fields from Spec.
func (r *Rule) finalize() {
	r.Target, r.Goto, r.MatchText, r.TargetOpts = "", false, "", ""
	match := r.Spec
	if ti := findTarget(r.Spec); ti >= 0 {
		r.Target = r.Spec[ti+1]
		r.Goto = r.Spec[ti] == "-g" || r.Spec[ti] == "--goto"
		match = r.Spec[:ti]
		r.TargetOpts = joinArgs(r.Spec[ti+2:])
	}
	r.MatchText = joinArgs(match)
	r.search = strings.ToLower(r.Target + " " + joinArgs(r.Spec))
	if r.Disabled {
		r.search += " disabled " + r.DisabledID
	}
}

// ---- iptables-save parsing ----

func parseCounters(s string) (uint64, uint64, error) {
	if len(s) < 5 || s[0] != '[' || s[len(s)-1] != ']' {
		return 0, 0, fmt.Errorf("bad counters %q", s)
	}
	p, b, ok := strings.Cut(s[1:len(s)-1], ":")
	if !ok {
		return 0, 0, fmt.Errorf("bad counters %q", s)
	}
	pk, err1 := strconv.ParseUint(p, 10, 64)
	by, err2 := strconv.ParseUint(b, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("bad counters %q", s)
	}
	return pk, by, nil
}

func parseRuleLine(line string) (chain string, r *Rule, err error) {
	r = &Rule{}
	if strings.HasPrefix(line, "[") {
		end := strings.IndexByte(line, ']')
		if end < 0 {
			return "", nil, fmt.Errorf("bad counters in %q", line)
		}
		if r.Pkts, r.Bytes, err = parseCounters(line[:end+1]); err != nil {
			return "", nil, err
		}
		line = strings.TrimLeft(line[end+1:], " ")
	}
	if !strings.HasPrefix(line, "-A ") {
		return "", nil, fmt.Errorf("unexpected line %q", line)
	}
	rest := line[3:]
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		chain, r.Raw = rest[:sp], rest[sp+1:]
	} else {
		chain = rest
	}
	if r.Args, err = splitArgs(r.Raw); err != nil {
		return "", nil, fmt.Errorf("%v in %q", err, line)
	}
	r.Spec = r.Args
	if id := placeholderID(r.Args); id != "" {
		r.Disabled, r.DisabledID, r.Spec = true, id, nil
	}
	r.finalize()
	return chain, r, nil
}

// parseSave parses `iptables-save -c` output. Warnings printed as comments
// (e.g. about iptables-legacy tables) are returned separately.
func parseSave(out string) (map[string]*Table, []string, error) {
	tables := map[string]*Table{}
	var warnings []string
	var cur *Table
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "":
		case line[0] == '#':
			if w := strings.TrimSpace(strings.TrimPrefix(line, "#")); strings.HasPrefix(w, "Warning:") {
				warnings = append(warnings, w)
			}
		case line[0] == '*':
			cur = &Table{Name: line[1:], Loaded: true, byName: map[string]*Chain{}}
			tables[cur.Name] = cur
		case line == "COMMIT":
			cur = nil
		case cur == nil:
			return nil, nil, fmt.Errorf("line outside of a table: %q", line)
		case line[0] == ':':
			f := strings.Fields(line[1:])
			if len(f) < 2 {
				return nil, nil, fmt.Errorf("bad chain line %q", line)
			}
			c := &Chain{Name: f[0]}
			if f[1] != "-" {
				c.Policy, c.Builtin = f[1], true
			}
			if len(f) >= 3 {
				c.Pkts, c.Bytes, _ = parseCounters(f[2])
			}
			cur.addChain(c)
		default:
			name, r, err := parseRuleLine(line)
			if err != nil {
				return nil, nil, err
			}
			c := cur.byName[name]
			if c == nil {
				c = &Chain{Name: name}
				cur.addChain(c)
			}
			r.Num = len(c.Rules) + 1
			c.Rules = append(c.Rules, r)
		}
	}
	return tables, warnings, nil
}

// attachStore resolves disabled placeholders to their stored original rules.
func attachStore(tables map[string]*Table, entries map[string]*DisabledEntry) {
	for _, t := range tables {
		for _, c := range t.Chains {
			for _, r := range c.Rules {
				if !r.Disabled {
					continue
				}
				if e := entries[r.DisabledID]; e != nil {
					r.Entry, r.Spec = e, e.Args
				}
				r.finalize()
			}
		}
	}
}

// normalize makes sure every standard table exists and lists its built-in
// chains first, and computes chain references.
func normalize(tables map[string]*Table) {
	for _, name := range tableNames {
		t := tables[name]
		if t == nil {
			t = &Table{Name: name, byName: map[string]*Chain{}}
			tables[name] = t
		}
		builtin := builtinChains[name]
		chains := make([]*Chain, 0, len(t.Chains)+len(builtin))
		isBuiltin := map[string]bool{}
		for _, bn := range builtin {
			isBuiltin[bn] = true
			c := t.byName[bn]
			if c == nil {
				c = &Chain{Name: bn, Policy: "ACCEPT", Builtin: true, Virtual: true}
			}
			chains = append(chains, c)
		}
		for _, c := range t.Chains {
			if !isBuiltin[c.Name] {
				chains = append(chains, c)
			}
		}
		t.Chains = chains
		t.byName = make(map[string]*Chain, len(chains))
		for _, c := range chains {
			t.byName[c.Name] = c
		}
	}
	for _, t := range tables {
		for _, c := range t.Chains {
			for _, r := range c.Rules {
				target := r.Target
				if r.Disabled {
					// the placeholder still holds no reference in the kernel
					continue
				}
				if tc := t.byName[target]; tc != nil && !tc.Builtin {
					tc.Refs++
					if n := len(tc.RefBy); n == 0 || tc.RefBy[n-1] != c.Name {
						tc.RefBy = append(tc.RefBy, c.Name)
					}
				}
			}
		}
	}
}

// ---- backend ----

type LogEntry struct {
	Time  time.Time
	Cmd   string
	Input string
	Err   error
}

type cmdError struct {
	code int
	msg  string
}

func (e *cmdError) Error() string { return e.msg }

// Backend runs one family's iptables binaries.
type Backend struct {
	Family     Family
	Bin        string
	SaveBin    string
	RestoreBin string
	Version    string
	store      *Store

	mu  sync.Mutex
	log []LogEntry
}

func findBinary(name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		if _, err := os.Stat(name); err != nil {
			return "", err
		}
		return name, nil
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: command not found", name)
}

// newBackend locates name, name-save and name-restore (e.g. iptables-legacy,
// iptables-legacy-save, iptables-legacy-restore).
func newBackend(fam Family, name string, store *Store) (*Backend, error) {
	b := &Backend{Family: fam, store: store}
	var err error
	if b.Bin, err = findBinary(name); err != nil {
		return nil, err
	}
	if b.SaveBin, err = findBinary(name + "-save"); err != nil {
		return nil, err
	}
	if b.RestoreBin, err = findBinary(name + "-restore"); err != nil {
		return nil, err
	}
	out, err := b.run("", b.Bin, "--version")
	if err != nil {
		return nil, err
	}
	b.Version = strings.TrimSpace(out)
	return b, nil
}

func (b *Backend) Name() string { return filepath.Base(b.Bin) }

func (b *Backend) run(stdin, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := cleanErr(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		code := -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		return stdout.String(), &cmdError{code: code, msg: msg}
	}
	return stdout.String(), nil
}

func cleanErr(s string) string {
	var parts []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "Try `") {
			continue
		}
		parts = append(parts, l)
	}
	return strings.Join(parts, "; ")
}

func (b *Backend) record(cmd, input string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.log = append(b.log, LogEntry{Time: time.Now(), Cmd: cmd, Input: input, Err: err})
	if len(b.log) > 500 {
		b.log = b.log[len(b.log)-500:]
	}
}

func (b *Backend) Log() []LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]LogEntry(nil), b.log...)
}

// ipt runs a modifying iptables command against table and logs it.
func (b *Backend) ipt(table string, args ...string) error {
	full := append([]string{"-w", lockWait, "-t", table}, args...)
	_, err := b.run("", b.Bin, full...)
	b.record(b.Name()+" "+joinArgs(full[2:]), "", err)
	return err
}

func (b *Backend) restore(input string) error {
	_, err := b.run(input, b.RestoreBin, "-w", lockWait, "--noflush")
	b.record(filepath.Base(b.RestoreBin)+" --noflush", input, err)
	return err
}

// Snapshot reads all tables currently present in the kernel. Tables that are
// not loaded are not touched (and thus not auto-created).
func (b *Backend) Snapshot() (*Snapshot, error) {
	out, err := b.run("", b.SaveBin, "-c")
	if err != nil {
		return nil, err
	}
	tables, warnings, err := parseSave(out)
	if err != nil {
		return nil, err
	}
	entries, serr := b.store.Entries(b.Family)
	if serr != nil {
		warnings = append(warnings, "state file: "+serr.Error())
	}
	attachStore(tables, entries)
	normalize(tables)
	return &Snapshot{Tables: tables, Entries: entries, Warnings: warnings, Time: time.Now()}, nil
}

func (b *Backend) fetchTable(name string) (*Table, error) {
	out, err := b.run("", b.SaveBin, "-c", "-t", name)
	if err != nil {
		return nil, err
	}
	tables, _, err := parseSave(out)
	if err != nil {
		return nil, err
	}
	entries, err := b.store.Entries(b.Family)
	if err != nil {
		return nil, err
	}
	attachStore(tables, entries)
	t := tables[name]
	if t == nil {
		return nil, fmt.Errorf("table %s not found", name)
	}
	return t, nil
}
