package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ruleRef identifies a rule as the UI saw it. Operations re-read the table
// and refuse to act if the rule at that position is no longer the same.
type ruleRef struct {
	table, chain string
	num          int
	raw          string
}

var errStale = errors.New("rules changed since the last refresh (view refreshed), please retry")

func (b *Backend) verify(ref ruleRef) (*Chain, *Rule, error) {
	t, err := b.fetchTable(ref.table)
	if err != nil {
		return nil, nil, err
	}
	c := t.Chain(ref.chain)
	if c == nil || ref.num < 1 || ref.num > len(c.Rules) || c.Rules[ref.num-1].Raw != ref.raw {
		return nil, nil, errStale
	}
	return c, c.Rules[ref.num-1], nil
}

// checkSyntax validates a rule without changing anything: `iptables -C` exits
// with 1 when the rule merely does not exist and with 2 on a parameter problem.
func (b *Backend) checkSyntax(table, chain string, args []string) error {
	full := append([]string{"-w", lockWait, "-t", table, "-C", chain}, args...)
	_, err := b.run("", b.Bin, full...)
	var ce *cmdError
	if err == nil || (errors.As(err, &ce) && ce.code == 1) {
		return nil
	}
	return err
}

func (b *Backend) forget(ids ...string) error {
	if err := b.store.Remove(ids...); err != nil {
		return fmt.Errorf("iptables updated, but state file %s was not: %w", b.store.Path, err)
	}
	return nil
}

// AddRule inserts args at position pos (0 appends). anchor, if set, is the
// rule the position was chosen relative to. A disabled rule is validated,
// stored in the state file, and only its placeholder goes into the chain.
func (b *Backend) AddRule(table, chain string, pos int, anchor *ruleRef, args []string, disabled bool) error {
	if anchor != nil {
		c, _, err := b.verify(*anchor)
		if err != nil {
			return err
		}
		if pos > len(c.Rules) {
			pos = 0
		}
	}
	kernelArgs := args
	id := ""
	if disabled {
		if err := b.checkSyntax(table, chain, args); err != nil {
			return err
		}
		id = newID()
		e := &DisabledEntry{ID: id, Family: b.Family, Table: table, Chain: chain, Args: args, DisabledAt: time.Now()}
		if err := b.store.Add(e); err != nil {
			return fmt.Errorf("state file: %w", err)
		}
		kernelArgs = placeholderArgs(id)
	}
	cmd := []string{"-A", chain}
	if pos > 0 {
		cmd = []string{"-I", chain, strconv.Itoa(pos)}
	}
	err := b.ipt(table, append(cmd, kernelArgs...)...)
	if err != nil && id != "" {
		_ = b.store.Remove(id)
	}
	return err
}

// disable swaps the rule at ref for a placeholder after storing args.
func (b *Backend) disable(ref ruleRef, args []string, pkts, bytes uint64) error {
	if err := b.checkSyntax(ref.table, ref.chain, args); err != nil {
		return err
	}
	id := newID()
	e := &DisabledEntry{ID: id, Family: b.Family, Table: ref.table, Chain: ref.chain, Args: args,
		Pkts: pkts, Bytes: bytes, DisabledAt: time.Now()}
	if err := b.store.Add(e); err != nil {
		return fmt.Errorf("state file: %w", err)
	}
	cmd := append([]string{"-R", ref.chain, strconv.Itoa(ref.num)}, placeholderArgs(id)...)
	if err := b.ipt(ref.table, cmd...); err != nil {
		_ = b.store.Remove(id)
		return err
	}
	return nil
}

func missingEntryErr(r *Rule, path string) error {
	return fmt.Errorf("original rule %s is not in %s; it cannot be restored (delete the placeholder instead)", r.DisabledID, path)
}

// ToggleRule disables an enabled rule or restores a disabled one, keeping its
// position and counters. It reports whether the rule is now enabled.
func (b *Backend) ToggleRule(ref ruleRef) (bool, error) {
	_, r, err := b.verify(ref)
	if err != nil {
		return false, err
	}
	if !r.Disabled {
		return false, b.disable(ref, r.Args, r.Pkts, r.Bytes)
	}
	if r.Entry == nil {
		return false, missingEntryErr(r, b.store.Path)
	}
	e := r.Entry
	cmd := []string{"-R", ref.chain, strconv.Itoa(ref.num),
		"-c", strconv.FormatUint(e.Pkts, 10), strconv.FormatUint(e.Bytes, 10)}
	if err := b.ipt(ref.table, append(cmd, e.Args...)...); err != nil {
		return false, err
	}
	return true, b.forget(r.DisabledID)
}

// ReplaceRule replaces the rule at ref with args in the requested state.
func (b *Backend) ReplaceRule(ref ruleRef, args []string, disabled bool) error {
	_, r, err := b.verify(ref)
	if err != nil {
		return err
	}
	replace := append([]string{"-R", ref.chain, strconv.Itoa(ref.num)}, args...)
	switch {
	case !r.Disabled && !disabled:
		return b.ipt(ref.table, replace...)
	case !r.Disabled && disabled:
		return b.disable(ref, args, 0, 0)
	case r.Entry == nil:
		return missingEntryErr(r, b.store.Path)
	case disabled:
		if err := b.checkSyntax(ref.table, ref.chain, args); err != nil {
			return err
		}
		e := *r.Entry
		e.Args = args
		e.Pkts, e.Bytes = 0, 0
		return b.store.Put(&e)
	default:
		if err := b.ipt(ref.table, replace...); err != nil {
			return err
		}
		return b.forget(r.DisabledID)
	}
}

func (b *Backend) DeleteRule(ref ruleRef) error {
	_, r, err := b.verify(ref)
	if err != nil {
		return err
	}
	if err := b.ipt(ref.table, "-D", ref.chain, strconv.Itoa(ref.num)); err != nil {
		return err
	}
	if r.Disabled && r.Entry != nil {
		return b.forget(r.DisabledID)
	}
	return nil
}

// MoveRule moves the rule at ref to position to (1-based, in the final
// chain), atomically and keeping its counters.
func (b *Backend) MoveRule(ref ruleRef, to int) (int, error) {
	c, r, err := b.verify(ref)
	if err != nil {
		return 0, err
	}
	n := len(c.Rules)
	if to < 1 {
		to = 1
	}
	if to > n {
		to = n
	}
	if to == ref.num {
		return to, nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "*%s\n", ref.table)
	fmt.Fprintf(&sb, "-D %s %d\n", quoteArg(ref.chain), ref.num)
	if to == n {
		fmt.Fprintf(&sb, "-A %s", quoteArg(ref.chain))
	} else {
		fmt.Fprintf(&sb, "-I %s %d", quoteArg(ref.chain), to)
	}
	fmt.Fprintf(&sb, " -c %d %d", r.Pkts, r.Bytes)
	if len(r.Args) > 0 {
		sb.WriteString(" " + joinArgs(r.Args))
	}
	sb.WriteString("\nCOMMIT\n")
	return to, b.restore(sb.String())
}

func disabledIDs(c *Chain) []string {
	var ids []string
	if c == nil {
		return nil
	}
	for _, r := range c.Rules {
		if r.Disabled && r.Entry != nil {
			ids = append(ids, r.DisabledID)
		}
	}
	return ids
}

func (b *Backend) chainDisabledIDs(table, chain string) []string {
	t, err := b.fetchTable(table)
	if err != nil {
		return nil
	}
	return disabledIDs(t.Chain(chain))
}

func (b *Backend) FlushChain(table, chain string) error {
	ids := b.chainDisabledIDs(table, chain)
	if err := b.ipt(table, "-F", chain); err != nil {
		return err
	}
	return b.forget(ids...)
}

func (b *Backend) DeleteChain(table, chain string, flush bool) error {
	if !flush {
		return b.ipt(table, "-X", chain)
	}
	ids := b.chainDisabledIDs(table, chain)
	q := quoteArg(chain)
	if err := b.restore(fmt.Sprintf("*%s\n-F %s\n-X %s\nCOMMIT\n", table, q, q)); err != nil {
		return err
	}
	return b.forget(ids...)
}

func (b *Backend) NewChain(table, chain string) error { return b.ipt(table, "-N", chain) }

func (b *Backend) RenameChain(table, from, to string) error {
	if err := b.ipt(table, "-E", from, to); err != nil {
		return err
	}
	if err := b.store.RenameChain(b.Family, table, from, to); err != nil {
		return fmt.Errorf("chain renamed, but state file was not updated: %w", err)
	}
	return nil
}

func (b *Backend) SetPolicy(table, chain, policy string) error {
	return b.ipt(table, "-P", chain, policy)
}

func (b *Backend) ZeroCounters(table, chain string) error { return b.ipt(table, "-Z", chain) }

// RestoreEntry appends an orphaned state entry (its placeholder is gone) to
// its chain as an enabled rule and forgets it.
func (b *Backend) RestoreEntry(e *DisabledEntry) error {
	if err := b.ipt(e.Table, append([]string{"-A", e.Chain}, e.Args...)...); err != nil {
		return err
	}
	return b.forget(e.ID)
}

func (b *Backend) ForgetEntry(id string) error { return b.store.Remove(id) }

// SaveTo writes the full ruleset (iptables-save format, no counters) to path.
func (b *Backend) SaveTo(path string) (int, error) {
	out, err := b.run("", b.SaveBin)
	if err != nil {
		return 0, err
	}
	if err := writeFileAtomic(path, []byte(out), 0o640); err != nil {
		return 0, err
	}
	b.record(fmt.Sprintf("%s > %s", b.SaveBin, path), "", nil)
	return len(out), nil
}
