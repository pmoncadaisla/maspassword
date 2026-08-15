package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"testing"
)

// buildAuthData assembles a minimal 37-byte authenticatorData header.
func buildAuthData(rpID string, flags byte, count uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := make([]byte, 37)
	copy(out[:32], h[:])
	out[32] = flags
	binary.BigEndian.PutUint32(out[33:37], count)
	return out
}

func genKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, spki
}

func sign(t *testing.T, priv *ecdsa.PrivateKey, authData, clientDataJSON []byte) []byte {
	t.Helper()
	cdh := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), cdh[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestVerifyAssertion_RoundTrip(t *testing.T) {
	priv, spki := genKey(t)
	authData := buildAuthData("vault.example", FlagUserPresent|FlagUserVerified, 7)
	clientData := []byte(`{"type":"webauthn.get","challenge":"abc","origin":"https://vault.example"}`)
	sig := sign(t, priv, authData, clientData)

	if err := VerifyAssertion(spki, authData, clientData, sig); err != nil {
		t.Fatalf("valid assertion rejected: %v", err)
	}
}

func TestVerifyAssertion_RejectsTampering(t *testing.T) {
	priv, spki := genKey(t)
	authData := buildAuthData("vault.example", FlagUserPresent|FlagUserVerified, 7)
	clientData := []byte(`{"type":"webauthn.get","challenge":"abc","origin":"https://vault.example"}`)
	sig := sign(t, priv, authData, clientData)

	// Tampered clientData (different challenge) must fail.
	tampered := []byte(`{"type":"webauthn.get","challenge":"xyz","origin":"https://vault.example"}`)
	if err := VerifyAssertion(spki, authData, tampered, sig); err == nil {
		t.Error("tampered clientData accepted")
	}
	// Tampered authData must fail.
	otherAuth := buildAuthData("evil.example", FlagUserPresent|FlagUserVerified, 7)
	if err := VerifyAssertion(spki, otherAuth, clientData, sig); err == nil {
		t.Error("tampered authData accepted")
	}
	// A different key must fail.
	_, otherSpki := genKey(t)
	if err := VerifyAssertion(otherSpki, authData, clientData, sig); err == nil {
		t.Error("wrong key accepted")
	}
}

func TestParseAuthData(t *testing.T) {
	raw := buildAuthData("vault.example", FlagUserPresent|FlagUserVerified, 42)
	ad, err := ParseAuthData(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("vault.example"))
	if ad.RPIDHash != want {
		t.Error("rpIdHash mismatch")
	}
	if ad.Flags&FlagUserPresent == 0 || ad.Flags&FlagUserVerified == 0 {
		t.Error("flags not parsed")
	}
	if ad.SignCount != 42 {
		t.Errorf("signCount = %d, want 42", ad.SignCount)
	}
	if _, err := ParseAuthData(raw[:36]); err == nil {
		t.Error("short authData accepted")
	}
}

func TestParsePublicKey_RejectsNonP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey(spki); err == nil {
		t.Error("P-384 key accepted, want P-256 only")
	}
	if _, err := ParsePublicKey([]byte("garbage")); err == nil {
		t.Error("garbage key accepted")
	}
}
