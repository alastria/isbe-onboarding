package tsaservice

import (
	"testing"
	"time"
)

func TestParseGeneralizedTime(t *testing.T) {
	ok := map[string]time.Time{
		"20261008095659Z":       time.Date(2026, 10, 8, 9, 56, 59, 0, time.UTC),
		"20261008095659.5Z":     time.Date(2026, 10, 8, 9, 56, 59, 500_000_000, time.UTC),
		"20261008095659.123Z":   time.Date(2026, 10, 8, 9, 56, 59, 123_000_000, time.UTC),
		"20261008095659.00001Z": time.Date(2026, 10, 8, 9, 56, 59, 10_000, time.UTC),
	}
	for in, want := range ok {
		got, err := parseGeneralizedTime(in)
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: got %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "20261008095659", "20261008095659+0100", "20261008095659.Z", "20261008095659.50Z", "20261008095659,5Z", "2026100809565aZ", "20261308095659Z"} {
		if _, err := parseGeneralizedTime(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestParseOID(t *testing.T) {
	if oid, err := parseOID("0.4.0.2023.1.1"); err != nil || oid.String() != "0.4.0.2023.1.1" {
		t.Fatal(oid, err)
	}
	for _, bad := range []string{"", "1", "1..2", "3.1", "1.40", "-1.2", "a.b"} {
		if _, err := parseOID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
