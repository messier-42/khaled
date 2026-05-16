package health_test

import (
	"testing"

	"github.com/messier-42/khaled/pkg/health"
)

func TestAllOK(t *testing.T) {
	cases := []struct {
		name    string
		results []health.CheckResult
		want    bool
	}{
		{"empty is vacuously ok", nil, true},
		{"all passing", []health.CheckResult{{Name: "a", OK: true}, {Name: "b", OK: true}}, true},
		{"one failing", []health.CheckResult{{Name: "a", OK: true}, {Name: "b", OK: false}}, false},
		{"all failing", []health.CheckResult{{Name: "a", OK: false}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := health.AllOK(tc.results); got != tc.want {
				t.Errorf("AllOK = %v, want %v", got, tc.want)
			}
		})
	}
}
