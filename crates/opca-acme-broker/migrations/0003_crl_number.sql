-- One row: the number of the last CRL signed, which only ever increases.
CREATE TABLE crl_number (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    number INTEGER NOT NULL
);
