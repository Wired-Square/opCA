CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    jwk TEXT NOT NULL,
    thumbprint TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('valid', 'deactivated', 'revoked')),
    contacts TEXT NOT NULL,
    created TEXT NOT NULL
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    account INTEGER NOT NULL REFERENCES accounts (id),
    status TEXT NOT NULL
        CHECK (status IN ('pending', 'ready', 'processing', 'valid', 'invalid')),
    identifiers TEXT NOT NULL,
    not_before TEXT,
    not_after TEXT,
    expires TEXT NOT NULL,
    error TEXT,
    certificate INTEGER REFERENCES certificates (id),
    created TEXT NOT NULL
);
CREATE INDEX orders_by_status ON orders (status, expires);

CREATE TABLE authorisations (
    id INTEGER PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES orders (id),
    identifier TEXT NOT NULL,
    wildcard INTEGER NOT NULL CHECK (wildcard IN (0, 1)),
    status TEXT NOT NULL
        CHECK (status IN ('pending', 'valid', 'invalid', 'deactivated', 'expired', 'revoked')),
    expires TEXT NOT NULL
);
CREATE INDEX authorisations_by_order ON authorisations (order_id);
CREATE INDEX authorisations_by_status ON authorisations (status, expires);

CREATE TABLE challenges (
    id INTEGER PRIMARY KEY,
    authorisation INTEGER NOT NULL REFERENCES authorisations (id),
    type TEXT NOT NULL CHECK (type IN ('http-01', 'dns-01', 'tls-alpn-01')),
    token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'valid', 'invalid')),
    validated TEXT,
    error TEXT
);
CREATE INDEX challenges_by_authorisation ON challenges (authorisation);

-- AUTOINCREMENT, so an id is never reused and serves as the sync cursor.
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial TEXT NOT NULL UNIQUE,
    account INTEGER NOT NULL REFERENCES accounts (id),
    order_id INTEGER NOT NULL UNIQUE REFERENCES orders (id),
    common_name TEXT,
    sans TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    chain_pem TEXT NOT NULL,
    revoked_at TEXT,
    revocation_reason INTEGER
        CHECK (revocation_reason BETWEEN 0 AND 10 AND revocation_reason <> 7),
    created TEXT NOT NULL
);

CREATE TABLE eab_keys (
    key_id TEXT PRIMARY KEY,
    hmac_key BLOB NOT NULL,
    account INTEGER REFERENCES accounts (id),
    created TEXT NOT NULL
);
