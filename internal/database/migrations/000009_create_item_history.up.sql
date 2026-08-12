CREATE TABLE item_history (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id        UUID NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    data_encrypted TEXT NOT NULL,
    version        INTEGER NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_item_history_item ON item_history(item_id, created_at DESC);
