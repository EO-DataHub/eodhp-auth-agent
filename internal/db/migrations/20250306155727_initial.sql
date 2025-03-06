-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    user_id UUID NOT NULL,
    scope VARCHAR(255) NOT NULL,
    access TEXT NOT NULL,
    access_expiry INT NOT NULL,
    refresh TEXT NOT NULL,
    expires INT NOT NULL,
    created INT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_token ON tokens(token);
CREATE INDEX IF NOT EXISTS idx_user ON tokens(user_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
