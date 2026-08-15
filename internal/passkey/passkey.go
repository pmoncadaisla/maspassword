// Package passkey verifies WebAuthn assertions for Sésamo's own login.
//
// It deliberately avoids attestation and CBOR: registration happens over an
// authenticated session and the client submits the credential public key in
// SPKI form (PublicKeyCredential.response.getPublicKey()), so verification
// only needs the standard library. The server's role is purely
// authentication — the PRF secret that decrypts the user's keys never
// reaches it.
package passkey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// FlagUserPresent and FlagUserVerified are authenticator data flag bits
	// (WebAuthn §6.1). UV is required here: this login replaces the master
	// password prompt, so the authenticator must have checked the user
	// (biometric / PIN), not just presence.
	FlagUserPresent  = 0x01
	FlagUserVerified = 0x04
)

// AuthData is the parsed fixed header of authenticatorData.
type AuthData struct {
	RPIDHash  [32]byte
	Flags     byte
	SignCount uint32
}

// ParseAuthData splits the 37-byte fixed header of authenticatorData.
func ParseAuthData(raw []byte) (*AuthData, error) {
	if len(raw) < 37 {
		return nil, errors.New("authenticator data too short")
	}
	var ad AuthData
	copy(ad.RPIDHash[:], raw[:32])
	ad.Flags = raw[32]
	ad.SignCount = binary.BigEndian.Uint32(raw[33:37])
	return &ad, nil
}

// ClientData is the subset of clientDataJSON we validate.
type ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"` // base64url, as the browser encodes it
	Origin    string `json:"origin"`
}

// ParseClientData decodes clientDataJSON.
func ParseClientData(raw []byte) (*ClientData, error) {
	var cd ClientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, fmt.Errorf("invalid clientDataJSON: %w", err)
	}
	return &cd, nil
}

// VerifyAssertion checks the WebAuthn assertion signature: ES256 over
// authenticatorData || SHA-256(clientDataJSON), against an SPKI-encoded
// P-256 public key. The signature is ASN.1/DER as produced by browsers.
func VerifyAssertion(publicKeySPKI, authData, clientDataJSON, signatureDER []byte) error {
	pub, err := ParsePublicKey(publicKeySPKI)
	if err != nil {
		return err
	}
	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, digest[:], signatureDER) {
		return errors.New("invalid assertion signature")
	}
	return nil
}

// ParsePublicKey parses and validates an SPKI blob as an ECDSA P-256 key.
// Used at registration too, so malformed keys are rejected before storage.
func ParsePublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	if pub.Curve.Params().Name != "P-256" {
		return nil, errors.New("public key is not P-256")
	}
	return pub, nil
}
