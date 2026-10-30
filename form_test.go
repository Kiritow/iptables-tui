package main

import (
	"reflect"
	"testing"
)

// Every template must produce a valid argument list in every table and family it is offered for.
func TestTemplatesBuild(t *testing.T) {
	for _, fam := range []Family{V4, V6} {
		for _, table := range tableNames {
			f := newRuleForm(fam, table, "FORWARD", nil, nil)
			for i, tpl := range f.templates {
				f.field("template").sel = i
				f.applyTemplate(tpl)
				if _, err := f.build(); err != nil {
					t.Errorf("%v %s %q: %v", fam, table, tpl.name, err)
				}
			}
		}
	}
}

func TestClampTemplate(t *testing.T) {
	for _, table := range []string{"filter", "mangle"} {
		f := newRuleForm(V4, table, "FORWARD", nil, nil)
		found := false
		for i, tpl := range f.templates {
			if tpl.name != "Clamp TCP MSS to PMTU" {
				continue
			}
			found = true
			f.field("template").sel = i
			f.applyTemplate(tpl)
			args, err := f.build()
			want := []string{"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"}
			if err != nil || !reflect.DeepEqual(args, want) {
				t.Errorf("%s: args=%q err=%v", table, args, err)
			}
		}
		if !found {
			t.Errorf("clamp template not offered in %s", table)
		}
	}
}

func TestTemplateFamilies(t *testing.T) {
	has := func(fam Family, name string) bool {
		for _, tpl := range newRuleForm(fam, "filter", "INPUT", nil, nil).templates {
			if tpl.name == name {
				return true
			}
		}
		return false
	}
	if has(V4, "Allow ICMPv6") || !has(V6, "Allow ICMPv6") || !has(V6, "Allow DHCPv6 client") {
		t.Error("IPv6-only templates offered in the wrong family")
	}
}

func TestCheckFamily(t *testing.T) {
	cases := []struct {
		fam  Family
		args string
		ok   bool
	}{
		{V4, "-s 10.0.0.0/8 -d 1.2.3.4,5.6.7.8 -j ACCEPT", true},
		{V4, "-s fd00::/8 -j ACCEPT", false},
		{V6, "-s fd00::/8 -d ::ffff:1.2.3.4 -j ACCEPT", true},
		{V6, "-s 10.0.0.1 -j DROP", false},
		{V6, "! -d 192.168.1.0/24 -j DROP", false},
		{V6, "-s example.com -m comment --comment 1.2.3.4 -j ACCEPT", true},
	}
	for _, c := range cases {
		args, _ := splitArgs(c.args)
		if err := checkFamily(args, c.fam); (err == nil) != c.ok {
			t.Errorf("%v %q: err=%v", c.fam, c.args, err)
		}
	}
}

func TestDerive6(t *testing.T) {
	for in, want := range map[string]string{
		"iptables": "ip6tables", "iptables-legacy": "ip6tables-legacy",
		"/usr/sbin/iptables-nft": "/usr/sbin/ip6tables-nft", "/opt/xt": "ip6tables",
	} {
		if got := derive6(in); got != want {
			t.Errorf("derive6(%q) = %q, want %q", in, got, want)
		}
	}
}
