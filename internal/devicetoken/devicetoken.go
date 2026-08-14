// Package devicetoken generates and verifies long-lived API tokens for
// linked mobile devices.
//
// Token format: "mpd_" + <uuid> + "_" + base64url(32 random bytes).
// The server stores ONLY hex(SHA-256(full token)); the plaintext token is
// shown exactly once at creation. The embedded uuid lets the auth middleware
// look up the row directly and compare hashes in constant time.
//
// Zero-knowledge note: a device token authenticates the device against the
// API. It carries no key material — the phone derives all encryption keys
// locally from the master password, which the server never sees.
package devicetoken

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Prefix distinguishes device tokens from JWTs in the Authorization header.
const Prefix = "mpd_"

// secretBytes is the entropy of the random part of the token.
const secretBytes = 32

// Generate returns a fresh device token: the id embedded in it (also the
// database primary key), the plaintext token, and the hex SHA-256 hash to
// store server-side.
func Generate() (id uuid.UUID, token, hash string, err error) {
	id = uuid.New()
	secret := make([]byte, secretBytes)
	if _, err = rand.Read(secret); err != nil {
		return uuid.Nil, "", "", fmt.Errorf("generating device token secret: %w", err)
	}
	token = Prefix + id.String() + "_" + base64.RawURLEncoding.EncodeToString(secret)
	return id, token, Hash(token), nil
}

// Hash returns hex(SHA-256(token)) — the only representation ever persisted.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ParseID extracts the token id from a raw bearer value. ok is false when
// the value is not shaped like a device token. The uuid is fixed-width
// (36 chars) followed by "_" and the secret; the secret is base64url and may
// itself contain underscores, so the split is positional.
func ParseID(raw string) (uuid.UUID, bool) {
	if !strings.HasPrefix(raw, Prefix) {
		return uuid.Nil, false
	}
	rest := raw[len(Prefix):]
	if len(rest) < 38 || rest[36] != '_' {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(rest[:36])
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// HashEqual compares two token hashes in constant time.
func HashEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
