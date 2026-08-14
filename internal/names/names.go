// Package names derives human-readable display names from email addresses.
package names

import (
	"strings"
	"unicode"
)

// DeriveFromEmail builds a display name from the local part of an email
// address: "pablo.moncada@x.com" becomes "Pablo Moncada". The local part is
// split on '.', '_' and '-', each part is title-cased and the parts are
// joined with single spaces. Returns "" when nothing can be derived.
func DeriveFromEmail(email string) string {
	local := email
	if at := strings.IndexByte(email, '@'); at >= 0 {
		local = email[:at]
	}

	parts := strings.FieldsFunc(local, func(r rune) bool {
		return r == '.' || r == '_' || r == '-'
	})

	titled := make([]string, 0, len(parts))
	for _, p := range parts {
		titled = append(titled, titleCase(p))
	}
	return strings.Join(titled, " ")
}

// titleCase upper-cases the first rune and lower-cases the rest.
func titleCase(s string) string {
	runes := []rune(strings.ToLower(s))
	if len(runes) == 0 {
		return ""
	}
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
