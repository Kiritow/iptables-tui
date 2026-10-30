package main

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// clipRule is one copied rule. The clipboard lives in memory only.
type clipRule struct {
	args     []string
	disabled bool
	jump     string // user-defined chain the rule jumps to in its source table
}

type clipboard struct {
	fam          Family
	table, chain string
	rules        []clipRule
}

func (c *clipboard) source() string { return fmt.Sprintf("%s %s/%s", c.fam, c.table, c.chain) }

// Translations between iptables and ip6tables for things that differ only in
// spelling. Everything else (addresses in particular) is reported, not guessed.
var (
	protoV4toV6  = map[string]string{"icmp": "ipv6-icmp", "1": "ipv6-icmp"}
	protoV6toV4  = map[string]string{"ipv6-icmp": "icmp", "icmpv6": "icmp", "icmp6": "icmp", "58": "icmp"}
	matchV4toV6  = map[string]string{"icmp": "icmp6", "ttl": "hl"}
	matchV6toV4  = map[string]string{"icmp6": "icmp", "hl": "ttl"}
	targetV4toV6 = map[string]string{"TTL": "HL"}
	targetV6toV4 = map[string]string{"HL": "TTL"}
	optV4toV6    = map[string]string{"--icmp-type": "--icmpv6-type", "--ttl-eq": "--hl-eq", "--ttl-lt": "--hl-lt",
		"--ttl-gt": "--hl-gt", "--ttl-set": "--hl-set", "--ttl-dec": "--hl-dec", "--ttl-inc": "--hl-inc"}
	optV6toV4 = invert(optV4toV6)
	// ICMP types with the same meaning in both protocols
	icmpV4toV6 = map[string]string{"any": "any", "0": "129", "echo-reply": "echo-reply",
		"3": "1", "destination-unreachable": "destination-unreachable", "8": "128", "echo-request": "echo-request",
		"11": "3", "time-exceeded": "time-exceeded", "12": "4", "parameter-problem": "parameter-problem"}
	icmpV6toV4   = invert(icmpV4toV6)
	rejectV4toV6 = map[string]string{"icmp-net-unreachable": "icmp6-no-route", "icmp-host-unreachable": "icmp6-addr-unreachable",
		"icmp-port-unreachable": "icmp6-port-unreachable", "icmp-net-prohibited": "icmp6-adm-prohibited",
		"icmp-host-prohibited": "icmp6-adm-prohibited", "icmp-admin-prohibited": "icmp6-adm-prohibited", "tcp-reset": "tcp-reset"}
	rejectV6toV4 = map[string]string{"icmp6-no-route": "icmp-net-unreachable", "no-route": "icmp-net-unreachable",
		"icmp6-addr-unreachable": "icmp-host-unreachable", "addr-unreach": "icmp-host-unreachable",
		"icmp6-port-unreachable": "icmp-port-unreachable", "port-unreach": "icmp-port-unreachable",
		"icmp6-adm-prohibited": "icmp-admin-prohibited", "adm-prohibited": "icmp-admin-prohibited", "tcp-reset": "tcp-reset"}
	v6OnlyMatches = []string{"frag", "rt", "hbh", "dst", "ipv6header", "mh", "eui64"}
	freeText      = []string{"--comment", "--log-prefix", "--nflog-prefix", "--string"}
)

func invert(m map[string]string) map[string]string {
	r := make(map[string]string, len(m))
	for k, v := range m {
		if _, dup := r[v]; !dup || k == v {
			r[v] = k
		}
	}
	return r
}

// natAddrFamily guesses the family of a NAT target address such as
// 1.2.3.4:80, 1.2.3.4-1.2.3.9, [fd00::1]:80 or fd00::1.
func natAddrFamily(v string) (Family, bool) {
	if strings.HasPrefix(v, "[") || strings.Count(v, ":") > 1 {
		return V6, true
	}
	host := v
	if i := strings.IndexAny(host, ":-/"); i >= 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return V4, true
	}
	return 0, false
}

// adaptRule rewrites a rule copied from family `from` for family `to`. It
// returns the new arguments, notes describing each change, and problems that
// have to be fixed by hand.
func adaptRule(args []string, from, to Family) (out, notes, problems []string) {
	out = append([]string(nil), args...)
	if from == to {
		return out, nil, nil
	}
	toV6 := to == V6
	pick := func(m4, m6 map[string]string) map[string]string {
		if toV6 {
			return m4
		}
		return m6
	}
	protoMap, matchMap := pick(protoV4toV6, protoV6toV4), pick(matchV4toV6, matchV6toV4)
	targetMap, optMap := pick(targetV4toV6, targetV6toV4), pick(optV4toV6, optV6toV4)
	icmpMap, rejectMap := pick(icmpV4toV6, icmpV6toV4), pick(rejectV4toV6, rejectV6toV4)
	note := func(old, new string) {
		if n := old + " -> " + new; !contains(notes, n) {
			notes = append(notes, n)
		}
	}
	rename := func(i int, m map[string]string) {
		if v, ok := m[out[i+1]]; ok {
			note(out[i]+" "+out[i+1], out[i]+" "+v)
			out[i+1] = v
		}
	}
	for i := 0; i < len(out); i++ {
		tok, hasNext := out[i], i+1 < len(out)
		switch {
		case !hasNext:
			if !toV6 || (tok != "-f" && tok != "--fragment") {
				continue
			}
			problems = append(problems, "-f (fragments) exists only in iptables; ip6tables uses -m frag")
		case contains(freeText, tok):
			i++
		case tok == "-p" || tok == "--protocol":
			rename(i, protoMap)
			i++
		case tok == "-m" || tok == "--match":
			if !toV6 && contains(v6OnlyMatches, out[i+1]) {
				problems = append(problems, "-m "+out[i+1]+" exists only in ip6tables")
			}
			rename(i, matchMap)
			i++
		case tok == "-j" || tok == "--jump":
			rename(i, targetMap)
			i++
		case tok == "--icmp-type" || tok == "--icmpv6-type":
			opt := optMap[tok]
			if opt == "" {
				opt = tok
			}
			if v, ok := icmpMap[out[i+1]]; ok {
				note(tok+" "+out[i+1], opt+" "+v)
				out[i], out[i+1] = opt, v
			} else {
				problems = append(problems, fmt.Sprintf("ICMP type %s has no automatic %s equivalent", out[i+1], to))
				out[i] = opt
			}
			i++
		case tok == "--reject-with":
			if v, ok := rejectMap[out[i+1]]; ok {
				if v != out[i+1] {
					note(tok+" "+out[i+1], tok+" "+v)
				}
				out[i+1] = v
			} else {
				problems = append(problems, fmt.Sprintf("--reject-with %s has no %s equivalent", out[i+1], to))
			}
			i++
		case tok == "--to-destination" || tok == "--to-source" || tok == "--to":
			if fam, ok := natAddrFamily(out[i+1]); ok && fam != to {
				problems = append(problems, fmt.Sprintf("%s %s is not an %s address; replace it", tok, out[i+1], to))
			}
			i++
		case toV6 && (tok == "-f" || tok == "--fragment"):
			problems = append(problems, "-f (fragments) exists only in iptables; ip6tables uses -m frag")
		default:
			if v, ok := optMap[tok]; ok {
				note(tok, v)
				out[i] = v
			}
		}
	}
	for _, h := range wrongFamilyAddrs(out, to) {
		problems = append(problems, fmt.Sprintf("%s is not an %s address; replace it", h, to))
	}
	return out, notes, problems
}

// actCopy copies the rule under the cursor, or with all set every rule shown
// in the current chain (so a filter selects what is copied).
func (a *App) actCopy(all bool) {
	c := a.chain()
	if c == nil {
		return
	}
	rs := a.rules()
	if !all {
		r := a.rule()
		if r == nil {
			a.setMsg(msgWarn, "no rule to copy")
			return
		}
		rs = []*Rule{r}
	}
	t := a.table()
	clip := &clipboard{fam: a.fam, table: a.tableName(), chain: c.Name}
	skipped := 0
	for _, r := range rs {
		if r.Spec == nil {
			skipped++
			continue
		}
		cr := clipRule{args: append([]string(nil), r.Spec...), disabled: r.Disabled}
		if tc := t.Chain(r.Target); tc != nil && !tc.Builtin {
			cr.jump = r.Target
		}
		clip.rules = append(clip.rules, cr)
	}
	if len(clip.rules) == 0 {
		a.setMsg(msgWarn, "nothing to copy")
		return
	}
	a.clip = clip
	msg := fmt.Sprintf("copied %d rule(s) from %s", len(clip.rules), clip.source())
	if all && a.ruleFilter != "" {
		msg += " (only those matching the filter)"
	}
	if skipped > 0 {
		msg += fmt.Sprintf("; skipped %d disabled rule(s) whose original is missing", skipped)
	}
	a.setMsg(msgOK, msg)
}

// actPaste inserts the clipboard below the cursor (at the end of the chain
// when the chains pane has focus), adapting rules copied from the other
// family. One rule opens the add dialog prefilled; several are confirmed and
// inserted in one iptables-restore transaction.
func (a *App) actPaste() {
	clip := a.clip
	if clip == nil {
		a.setMsg(msgWarn, "clipboard is empty: y copies a rule, Y every rule shown in the chain")
		return
	}
	c := a.chain()
	if c == nil {
		a.setMsg(msgErr, "no chain selected")
		return
	}
	table, chain, t := a.tableName(), c.Name, a.table()
	pos := 0
	var anchor *ruleRef
	if a.focus == paneRules {
		if ref, r, ok := a.curRef(); ok {
			anchor, pos = &ref, r.Num+1
		}
	}
	type item struct {
		args     []string
		disabled bool
		problems []string
	}
	var items []item
	var notes []string
	bad := 0
	for _, cr := range clip.rules {
		args, n, probs := adaptRule(cr.args, clip.fam, a.fam)
		for _, x := range n {
			if !contains(notes, x) {
				notes = append(notes, x)
			}
		}
		switch tc := t.Chain(cr.jump); {
		case cr.jump == "":
		case cr.jump == chain:
			probs = append(probs, "it jumps to "+chain+" itself")
		case tc == nil || tc.Builtin:
			probs = append(probs, fmt.Sprintf("it jumps to chain %s, which does not exist in %s %s", cr.jump, a.fam, table))
		}
		if len(probs) > 0 {
			bad++
		}
		items = append(items, item{args, cr.disabled, probs})
	}
	adapted := ""
	if len(notes) > 0 {
		adapted = "adapted for " + a.fam.String() + ": " + strings.Join(notes, ", ")
	}

	if len(items) == 1 {
		it := items[0]
		f := a.addForm(table, chain, pos, anchor)
		f.lockMode, f.advanced = true, true
		f.title = strings.Replace(f.title, " rule", " copied rule", 1)
		f.field("rule").set(joinArgs(it.args))
		if it.disabled {
			f.field("as").set("disabled")
		}
		f.info = []string{"copied from " + clip.source()}
		if adapted != "" {
			f.info = append(f.info, adapted)
		}
		if len(it.problems) > 0 {
			f.err = "fix before adding: " + strings.Join(it.problems, "; ")
		}
		a.form, a.mode = f, modeForm
		return
	}

	if bad > 0 {
		lines := []textLine{{fmt.Sprintf("%d of the %d copied rules cannot go into %s %s/%s as they are:",
			bad, len(items), a.fam, table, chain), stConfHead}, plain("")}
		for i, it := range items {
			if len(it.problems) == 0 {
				continue
			}
			lines = append(lines, plain(fmt.Sprintf("%d. %s", i+1, joinArgs(it.args))))
			for _, p := range it.problems {
				lines = append(lines, textLine{"   - " + p, fg(cRed)})
			}
		}
		lines = append(lines, plain(""), plain("Nothing was pasted. Copy only the rules that fit (filter with / and copy with Y),"),
			plain("or paste the others one at a time with y / p and fix them in the dialog."))
		a.showText("cannot paste", lines)
		return
	}

	where := fmt.Sprintf("at the end of %s/%s", table, chain)
	if pos > 0 {
		where = fmt.Sprintf("into %s/%s below #%d", table, chain, pos-1)
	}
	lines := []textLine{{fmt.Sprintf("Paste %d rules %s (%s)?", len(items), where, a.fam), stConfHead},
		plain("copied from " + clip.source())}
	if adapted != "" {
		lines = append(lines, textLine{adapted, fg(cCyan)})
	}
	lines = append(lines, plain(""))
	rules := make([]pasteRule, len(items))
	disabled := 0
	for i, it := range items {
		rules[i] = pasteRule{args: it.args, disabled: it.disabled}
		prefix := fmt.Sprintf("%2d. ", i+1)
		if it.disabled {
			prefix += "[disabled] "
			disabled++
		}
		lines = append(lines, plain(prefix+joinArgs(it.args)))
	}
	if disabled > 0 {
		lines = append(lines, textLine{fmt.Sprintf("%d rule(s) are added DISABLED (kept in %s, placeholder in the chain)",
			disabled, a.store.Path), fg(cYellow)})
	}
	lines = append(lines, plain(""),
		textLine{"will run, as one atomic " + filepath.Base(a.be().RestoreBin) + " --noflush transaction:", stConfHead},
		textLine{"  *" + table, stConfCmd})
	for i, it := range items {
		args := it.args
		if it.disabled {
			args = placeholderArgs("<new id>")
		}
		cmd := fmt.Sprintf("-A %s %s", quoteArg(chain), joinArgs(args))
		if pos > 0 {
			cmd = fmt.Sprintf("-I %s %d %s", quoteArg(chain), pos+i, joinArgs(args))
		}
		lines = append(lines, textLine{"  " + cmd, stConfCmd})
	}
	lines = append(lines, textLine{"  COMMIT", stConfCmd})
	a.confirm("Confirm: paste rules", lines, func() {
		sel := &selTarget{table: table, chain: chain, num: pos}
		if pos == 0 {
			sel.num = -1
		}
		a.focus = paneRules
		a.mutate(func(b *Backend) (string, error) {
			return fmt.Sprintf("pasted %d rules into %s/%s", len(rules), table, chain),
				b.PasteRules(table, chain, pos, anchor, rules)
		}, sel)
	})
}
