// SPDX-License-Identifier: Apache-2.0

package deep

import (
	"strings"
	"testing"
)

func TestParseURI(t *testing.T) {
	tests := []struct {
		raw  string
		want URI
	}{
		{"deep://node.alpha", URI{"node.alpha", "node", "alpha", "/", "", ""}},
		{"DEEP://MiXeD.BeTa/A%2fb?q=UP%20Down#Local?Only", URI{"mixed.beta", "mixed", "beta", "/A%2fb", "q=UP%20Down", "Local?Only"}},
		{"deep://n-1.net-2/?a=b&c=d/?#f%20g", URI{"n-1.net-2", "n-1", "net-2", "/", "a=b&c=d/?", "f%20g"}},
		{"deep://0.9?x=1", URI{"0.9", "0", "9", "/", "x=1", ""}},
		{"deep://node.alpha/a;b:@!$&'()*+,=~_-./%00", URI{"node.alpha", "node", "alpha", "/a;b:@!$&'()*+,=~_-./%00", "", ""}},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			got, err := ParseURI(test.raw)
			if err != nil || got != test.want {
				t.Fatalf("ParseURI(%q) = %#v, %v; want %#v", test.raw, got, err, test.want)
			}
		})
	}
}

func TestParseURIRejectsMalformed(t *testing.T) {
	invalid := []string{
		"", "http://node.alpha", "deep:node.alpha", "deep:///node.alpha", "deep://alpha",
		"deep://n.a.extra", "deep://node.alpha.", "deep://user@node.alpha/", "deep://node.alpha:1/",
		"deep://127.0.0.1/", "deep://[::1]/", "deep://-node.alpha", "deep://node-.alpha",
		"deep://node._alpha", "deep://node.%61lpha", "deep://nódé.alpha", "deep://node.alpha/a b",
		"deep://node.alpha/a\nb", "deep://node.alpha/a\x00b", "deep://node.alpha/\\evil",
		"deep://node.alpha/☃", "deep://node.alpha/%", "deep://node.alpha/%0", "deep://node.alpha/%gg",
		"deep://node.alpha/?x=%Q0", "deep://node.alpha/#bad%2", "deep://node.alpha/#one#two",
		"deep://node.alpha/a[0]", "deep://node.alpha/<a>", "deep://node.alpha/\"a\"",
		"deep://" + strings.Repeat("a", 64) + ".alpha/",
		"deep://node.alpha/" + strings.Repeat("a", MaxURILength),
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseURI(raw); err == nil {
				t.Fatalf("ParseURI(%q) unexpectedly succeeded", raw)
			}
		})
	}
}

func TestAuthorityCanonicalForm(t *testing.T) {
	for _, authority := range []string{"node.alpha", "a.b", strings.Repeat("n", 63) + "." + strings.Repeat("a", 63)} {
		if err := ValidateAuthority(authority); err != nil {
			t.Errorf("valid authority %q: %v", authority, err)
		}
	}
	for _, authority := range []string{"NODE.alpha", "node.Alpha", "node.alpha/", "node..alpha", "node.alpha?x", ".alpha", "node.", "-a.b", "a.b-"} {
		if err := ValidateAuthority(authority); err == nil {
			t.Errorf("noncanonical authority %q accepted", authority)
		}
	}
}

func TestValidateResource(t *testing.T) {
	for _, value := range [][2]string{{"/", ""}, {"/%FF/%20", "x=?yes/a"}, {"/UPPER", "q=%2f"}} {
		if err := ValidateResource(value[0], value[1]); err != nil {
			t.Errorf("valid resource %q: %v", value, err)
		}
	}
	for _, value := range [][2]string{{"", ""}, {"relative", ""}, {"/path?query", ""}, {"/path#fragment", ""}, {"/", "x=#fragment"}, {"/", "x=white space"}, {"/", "x=\\"}, {"/%GG", ""}, {"/", strings.Repeat("x", MaxURILength)}} {
		if err := ValidateResource(value[0], value[1]); err == nil {
			t.Errorf("invalid resource %q accepted", value)
		}
	}
}

func FuzzParseURI(f *testing.F) {
	for _, seed := range []string{"deep://node.alpha/path?query#fragment", "DEEP://N.B/%20", "", "deep://[::1]"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		uri, err := ParseURI(raw)
		if err != nil {
			return
		}
		if err := ValidateAuthority(uri.Authority); err != nil {
			t.Fatalf("accepted invalid authority: %v", err)
		}
		if err := ValidateResource(uri.Path, uri.Query); err != nil {
			t.Fatalf("accepted invalid resource: %v", err)
		}
		if uri.Authority != uri.Node+"."+uri.Network {
			t.Fatal("authority decomposition changed its meaning")
		}
	})
}
