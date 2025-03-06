package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upAddWorkspace, downAddWorkspace)
}

func upAddWorkspace(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `
		ALTER TABLE tokens ADD COLUMN workspace VARCHAR(255);
	`); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_user ON tokens(workspace);
	`); err != nil {
		return err
	}

	return nil
}

func downAddWorkspace(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `
		DROP INDEX IF EXISTS idx_user;
	`); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		ALTER TABLE tokens DROP COLUMN workspace;
	`); err != nil {
		return err
	}

	return nil
}
