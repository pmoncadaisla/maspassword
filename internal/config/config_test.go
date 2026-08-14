package config

import "testing"

func TestParseAdminEmails(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string // emails that must be admins
		not   []string // emails that must NOT be admins
	}{
		{
			name:  "empty input means no admins",
			input: "",
			not:   []string{"", "anyone@example.com"},
		},
		{
			name:  "single email",
			input: "admin@example.com",
			want:  []string{"admin@example.com"},
			not:   []string{"other@example.com"},
		},
		{
			name:  "comma separated with spaces are trimmed",
			input: " admin@example.com ,  ops@example.com ",
			want:  []string{"admin@example.com", "ops@example.com", "admin@example.com "},
			not:   []string{"nope@example.com"},
		},
		{
			name:  "matching is case-insensitive both ways",
			input: "Admin@Example.COM",
			want:  []string{"admin@example.com", "ADMIN@EXAMPLE.COM", "Admin@example.com"},
			not:   []string{"admin@example.org"},
		},
		{
			name:  "empty entries and stray commas are ignored",
			input: ",, a@b.com, ,",
			want:  []string{"a@b.com"},
			not:   []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := ParseAdminEmails(tt.input)
			for _, e := range tt.want {
				if !set.Contains(e) {
					t.Errorf("ParseAdminEmails(%q).Contains(%q) = false, want true", tt.input, e)
				}
			}
			for _, e := range tt.not {
				if set.Contains(e) {
					t.Errorf("ParseAdminEmails(%q).Contains(%q) = true, want false", tt.input, e)
				}
			}
		})
	}
}

func TestAdminEmailsZeroValue(t *testing.T) {
	var set AdminEmails // nil map: no admins, must not panic
	if set.Contains("admin@example.com") {
		t.Error("nil AdminEmails must contain nobody")
	}
}
