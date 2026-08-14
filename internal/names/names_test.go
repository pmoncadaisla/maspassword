package names

import "testing"

func TestDeriveFromEmail(t *testing.T) {
	cases := []struct {
		email string
		want  string
	}{
		{"pablo.moncada@x.com", "Pablo Moncada"},
		{"john_doe-smith@example.org", "John Doe Smith"},
		{"ALICE@example.com", "Alice"},
		{"bob@example.com", "Bob"},
		{"bob", "Bob"},                              // no @: treat whole string as local part
		{"a.b.c@example.com", "A B C"},              // single-letter parts
		{"maría.lópez@example.es", "María López"},   // unicode local part
		{"double..dots@example.com", "Double Dots"}, // empty segments dropped
		{"", ""},
		{"@example.com", ""},
		{"._-@example.com", ""}, // only separators
	}

	for _, tc := range cases {
		if got := DeriveFromEmail(tc.email); got != tc.want {
			t.Errorf("DeriveFromEmail(%q) = %q, want %q", tc.email, got, tc.want)
		}
	}
}
