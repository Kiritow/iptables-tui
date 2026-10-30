// iptables-tui is a terminal UI for viewing and editing iptables rules.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

const version = "0.1.0"

func main() {
	var (
		v6       = flag.Bool("6", false, "start in IPv6 mode (ip6tables)")
		table    = flag.String("t", "filter", "initial table: filter, nat, mangle, raw or security")
		watch    = flag.Bool("w", false, "start in watch (auto refresh) mode")
		interval = flag.Duration("i", time.Second, "watch refresh interval")
		bin4     = flag.String("iptables", "iptables", "iptables command; -save/-restore are derived from it (e.g. iptables-legacy)")
		bin6     = flag.String("ip6tables", "ip6tables", "ip6tables command")
		noMouse  = flag.Bool("no-mouse", false, "disable mouse support (M toggles it at runtime)")
		state    = flag.String("state", "/var/lib/iptables-tui/disabled.json", "state file holding disabled rules")
		showVer  = flag.Bool("version", false, "print the version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags]\n\nA terminal UI for iptables. Press ? inside for help.\n\nflags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVer {
		fmt.Println("iptables-tui", version)
		return
	}
	if !contains(tableNames, *table) {
		fatalf("unknown table %q", *table)
	}
	if *interval < 200*time.Millisecond {
		*interval = 200 * time.Millisecond
	}
	if os.Geteuid() != 0 {
		fatalf("must be run as root (iptables needs CAP_NET_ADMIN)")
	}
	opts := options{
		fam:      V4,
		table:    *table,
		watch:    *watch,
		interval: *interval,
		bins:     map[Family]string{V4: *bin4, V6: *bin6},
		mouse:    !*noMouse,
	}
	if *v6 {
		opts.fam = V6
	}
	store := &Store{Path: *state}
	be, err := newBackend(opts.fam, opts.bins[opts.fam], store)
	if err != nil {
		fatalf("%v", err)
	}
	if _, err := be.Snapshot(); err != nil {
		fatalf("reading rules: %v", err)
	}
	if err := newApp(opts, be, store).Run(); err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "iptables-tui: "+format+"\n", args...)
	os.Exit(1)
}
