CREATE TABLE vaults (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_encrypted TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_vaults_owner_id ON vaults(owner_id);
