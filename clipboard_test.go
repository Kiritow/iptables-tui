package main

import (
	"strings"
	"testing"
)

func TestAdaptRule(t *testing.T) {
	cases := []struct {
		from, to Family
		in, want string
		notes    int
		problems []string // substrings, in order
	}{
		{V4, V6, "-p icmp -m icmp --icmp-type 8 -j ACCEPT", "-p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT", 3, nil},
		{V6, V4, "-p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT", "-p icmp -m icmp --icmp-type 8 -j ACCEPT", 3, nil},
		{V4, V6, "-p tcp -m tcp --dport 23 -j REJECT --reject-with icmp-port-unreachable",
			"-p tcp -m tcp --dport 23 -j REJECT --reject-with icmp6-port-unreachable", 1, nil},
		{V6, V4, "-j REJECT --reject-with icmp6-adm-prohibited", "-j REJECT --reject-with icmp-admin-prohibited", 1, nil},
		{V4, V6, "-p tcp -j REJECT --reject-with tcp-reset", "-p tcp -j REJECT --reject-with tcp-reset", 0, nil},
		{V4, V6, "-m ttl --ttl-lt 5 -j TTL --ttl-set 64", "-m hl --hl-lt 5 -j HL --hl-set 64", 4, nil},
		{V4, V6, `-m comment --comment -p -j ACCEPT`, `-m comment --comment -p -j ACCEPT`, 0, nil},
		{V4, V6, "-s 10.0.0.0/8 -p tcp -j ACCEPT", "-s 10.0.0.0/8 -p tcp -j ACCEPT", 0, []string{"10.0.0.0 is not an IPv6"}},
		{V4, V6, "-p tcp -j DNAT --to-destination 192.168.1.10:80", "-p tcp -j DNAT --to-destination 192.168.1.10:80", 0,
			[]string{"--to-destination 192.168.1.10:80"}},
		{V6, V4, "-j DNAT --to-destination [fd00::1]:80", "-j DNAT --to-destination [fd00::1]:80", 0, []string{"not an IPv4"}},
		{V4, V6, "-f -j DROP", "-f -j DROP", 0, []string{"-f (fragments)"}},
		{V6, V4, "-m frag --fragmore -j DROP", "-m frag --fragmore -j DROP", 0, []string{"-m frag exists only in ip6tables"}},
		{V4, V6, "-p icmp -m icmp --icmp-type 3/3 -j ACCEPT", "-p ipv6-icmp -m icmp6 --icmpv6-type 3/3 -j ACCEPT", 2,
			[]string{"ICMP type 3/3"}},
		{V4, V4, "-s 10.0.0.1 -p icmp -j ACCEPT", "-s 10.0.0.1 -p icmp -j ACCEPT", 0, nil},
	}
	for _, c := range cases {
		in, _ := splitArgs(c.in)
		out, notes, problems := adaptRule(in, c.from, c.to)
		if got := joinArgs(out); got != c.want {
			t.Errorf("%v->%v %q:\n got  %q\n want %q", c.from, c.to, c.in, got, c.want)
		}
		if len(notes) != c.notes {
			t.Errorf("%v->%v %q: notes=%q, want %d", c.from, c.to, c.in, notes, c.notes)
		}
		if len(problems) != len(c.problems) {
			t.Errorf("%v->%v %q: problems=%q, want %q", c.from, c.to, c.in, problems, c.problems)
			continue
		}
		for i, p := range c.problems {
			if !strings.Contains(problems[i], p) {
				t.Errorf("%v->%v %q: problem %q does not mention %q", c.from, c.to, c.in, problems[i], p)
			}
		}
		if joinArgs(in) != strings.Join(strings.Fields(c.in), " ") && !strings.Contains(c.in, `"`) {
			t.Errorf("input modified: %q", in)
		}
	}
}
