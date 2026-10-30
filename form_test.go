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
