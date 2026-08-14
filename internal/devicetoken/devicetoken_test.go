package devicetoken

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestGenerateRoundtrip(t *testing.T) {
	id, token, hash, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if !strings.HasPrefix(token, Prefix) {
		t.Errorf("token %q does not start with %q", token, Prefix)
	}
	// "mpd_" + 36-char uuid + "_" + 43-char base64url(32 bytes)
	if got, want := len(token), len(Prefix)+36+1+43; got != want {
		t.Errorf("token length = %d, want %d", got, want)
	}

	// The embedded id parses back to the generated one.
	parsed, ok := ParseID(token)
	if !ok {
		t.Fatalf("ParseID(%q) not ok", token)
	}
	if parsed != id {
		t.Errorf("ParseID = %s, want %s", parsed, id)
	}

	// The stored hash matches a recomputation from the plaintext token.
	if !HashEqual(hash, Hash(token)) {
		t.Error("stored hash does not match recomputed hash")
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64 hex chars", len(hash))
	}

	// A different token does NOT match.
	_, other, _, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if HashEqual(hash, Hash(other)) {
		t.Error("hash of a different token must not match")
	}
}

func TestGenerateUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		_, token, _, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[token] {
			t.Fatalf("duplicate token generated: %q", token)
		}
		seen[token] = true
	}
}

func TestParseIDRejectsGarbage(t *testing.T) {
	valid := uuid.New().String()
	cases := []string{
		"",
		"mpd_",
		"mpd_" + valid,          // no secret part
		"mpd_" + valid + "_",    // empty secret
		"mpd_not-a-uuid_secret", // bad uuid
		"jwt-looking-token",
		"mpx_" + valid + "_secret", // wrong prefix
		"Bearer mpd_" + valid + "_secret",
	}
	for _, c := range cases {
		if id, ok := ParseID(c); ok {
			t.Errorf("ParseID(%q) = %s, ok — want rejection", c, id)
		}
	}
}

func TestParseIDAcceptsUnderscoreInSecret(t *testing.T) {
	// base64url alphabet has '-' and '_'; LastIndex must still find the
	// separator correctly when the secret itself contains underscores.
	id := uuid.New()
	raw := Prefix + id.String() + "_ab_cd_ef"
	parsed, ok := ParseID(raw)
	if !ok || parsed != id {
		t.Fatalf("ParseID(%q) = %v, %v; want %s, true", raw, parsed, ok, id)
	}
}

func TestHashDeterministic(t *testing.T) {
	if Hash("mpd_x") != Hash("mpd_x") {
		t.Error("Hash must be deterministic")
	}
	if Hash("a") == Hash("b") {
		t.Error("different inputs must not collide trivially")
	}
	if !HashEqual(Hash("same"), Hash("same")) {
		t.Error("HashEqual must accept equal hashes")
	}
	if HashEqual(Hash("same"), Hash("diff")) {
		t.Error("HashEqual must reject different hashes")
	}
}
