CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE tokens (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL,
    token       TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE otp_2fa (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL,
    secret      TEXT NOT NULL,
    enabled     BOOL NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
