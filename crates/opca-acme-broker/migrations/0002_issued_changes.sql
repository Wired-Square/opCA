ALTER TABLE certificates ADD COLUMN issuer_serial TEXT NOT NULL DEFAULT '';

-- Bumped on insert and on revoke: the sync cursor, so a revocation reaches a client already past the row's id.
ALTER TABLE certificates ADD COLUMN changed INTEGER NOT NULL DEFAULT 0;
UPDATE certificates SET changed = id;
CREATE UNIQUE INDEX certificates_by_change ON certificates (changed);
