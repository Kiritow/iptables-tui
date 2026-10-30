// iptables-tui is a terminal UI for viewing and editing iptables rules.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// version is set at build time (see Makefile):
//
//	go build -ldflags "-X main.version=$(git describe --tags --always --dirty)"
var version string

// buildVersion returns the version set at build time, or else what the Go
// toolchain recorded from git: a release tag, or the commit for other builds.
func buildVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	// Go 1.24+ stamps the tag (v0.0.1) or a pseudo-version (v0.0.0-2026...-abcdef123456)
	if v := info.Main.Version; v != "" && v != "(devel)" && !isPseudoVersion(v) {
		return v
	}
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}

func isPseudoVersion(v string) bool {
	v, _, _ = strings.Cut(v, "+")
	i := strings.LastIndexByte(v, '-')
	if i < 0 || len(v)-i-1 != 12 {
		return false
	}
	for _, c := range v[i+1:] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func main() {
	var (
		v6       = flag.Bool("6", false, "start in IPv6 mode (ip6tables)")
		table    = flag.String("t", "filter", "initial table: filter, nat, mangle, raw or security")
		watch    = flag.Bool("w", false, "start in watch (auto refresh) mode")
		interval = flag.Duration("i", time.Second, "watch refresh interval")
		bin4     = flag.String("iptables", "iptables", "iptables command; -save/-restore are derived from it (e.g. iptables-legacy)")
		bin6     = flag.String("ip6tables", "", "ip6tables command (default: derived from -iptables, e.g. ip6tables-legacy)")
		nflogGrp = flag.Int("nflog-group", defaultNFLOGGroup, "NFLOG group used by the NFLOG template and packet monitor")
		noMouse  = flag.Bool("no-mouse", false, "disable mouse support (M toggles it at runtime)")
		state    = flag.String("state", "/var/lib/iptables-tui/disabled.json", "state file holding disabled rules")
		showVer  = flag.Bool("version", false, "print the version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "iptables-tui %s\n\nusage: %s [flags]\n\nA terminal UI for iptables. Press ? inside for help.\n\nflags:\n",
			buildVersion(), os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *nflogGrp < 0 || *nflogGrp > 65535 {
		fatalf("-nflog-group must be 0-65535")
	}
	defaultNFLOGGroup = *nflogGrp
	if *bin6 == "" {
		*bin6 = derive6(*bin4)
	}
	if *showVer {
		fmt.Printf("iptables-tui %s (%s)\n", buildVersion(), runtime.Version())
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

// derive6 maps an iptables command to its IPv6 sibling so both families use
// the same backend: iptables-legacy -> ip6tables-legacy,
// /usr/sbin/iptables-nft -> /usr/sbin/ip6tables-nft.
func derive6(bin4 string) string {
	dir, base := filepath.Split(bin4)
	if strings.HasPrefix(base, "iptables") {
		return dir + "ip6tables" + strings.TrimPrefix(base, "iptables")
	}
	return "ip6tables"
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "iptables-tui: "+format+"\n", args...)
	os.Exit(1)
}
