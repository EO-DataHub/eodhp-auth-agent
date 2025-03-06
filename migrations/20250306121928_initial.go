package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upInitial, downInitial)
}

func upInitial(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS tokens (
			id UUID PRIMARY KEY,
			name TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			user_id UUID NOT NULL,
			scope TEXT NOT NULL,
			access TEXT NOT NULL,
			access_expiry INT NOT NULL,
			refresh TEXT NOT NULL,
			expires INT NOT NULL,
			created INT NOT NULL
		)
	`); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_token ON tokens(token);
		CREATE INDEX IF NOT EXISTS idx_user ON tokens(user_id);
	`); err != nil {
		return err
	}

	return nil
}

func downInitial(ctx context.Context, tx *sql.Tx) error {
	// This code is executed when the migration is rolled back.
	return nil
}
