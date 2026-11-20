package app

import "testing"

func TestExtractTargetsFromChineseProse(t *testing.T) {
	cases := []struct {
		field string
		want  []string
	}{
		{"对http://127.0.0.1:18000进行渗透测试", []string{"http://127.0.0.1:18000"}},
		{"http://192.168.5.2:3000", []string{"http://192.168.5.2:3000"}},
		{"http://x.test/a?b=c，然后", []string{"http://x.test/a?b=c"}},
		{"192.168.5.2:3000", []string{"192.168.5.2:3000"}},
		{"帮我看看这个站点", nil},
	}
	for _, c := range cases {
		got := extractTargets(c.field)
		if len(got) != len(c.want) {
			t.Fatalf("%q -> %v, want %v", c.field, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%q -> %v, want %v", c.field, got, c.want)
			}
		}
	}
}
