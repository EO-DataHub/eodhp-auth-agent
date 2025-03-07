-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
ALTER TABLE tokens ADD COLUMN workspace VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_workspace ON tokens(workspace);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
DROP INDEX IF EXISTS idx_workspace;
ALTER TABLE tokens DROP COLUMN workspace;
-- +goose StatementEnd
