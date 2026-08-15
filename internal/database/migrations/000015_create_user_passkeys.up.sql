-- Passkeys that log into MasPassword itself (WebAuthn + PRF).
-- public_key is the credential's SPKI (base64); the server verifies
-- assertion signatures with it. prf_encrypted_enc_key is the user's
-- AES encryption key wrapped by a key derived from the credential's
-- PRF output — the server can store it but never unwrap it, so the
-- zero-knowledge model holds. Empty = auth-only passkey (the master
-- password is still asked after login).
CREATE TABLE user_passkeys (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL DEFAULT '',
    credential_id         TEXT NOT NULL UNIQUE,
    public_key            TEXT NOT NULL,
    sign_count            BIGINT NOT NULL DEFAULT 0,
    transports            TEXT NOT NULL DEFAULT '',
    prf_salt              TEXT NOT NULL DEFAULT '',
    prf_encrypted_enc_key TEXT NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at          TIMESTAMPTZ NULL
);

CREATE INDEX idx_user_passkeys_user_id ON user_passkeys(user_id);
