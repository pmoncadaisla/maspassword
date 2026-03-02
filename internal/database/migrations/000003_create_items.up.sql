CREATE TABLE items (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vault_id       UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    data_encrypted TEXT NOT NULL,
    version        INTEGER NOT NULL DEFAULT 1,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_items_vault_id ON items(vault_id);
