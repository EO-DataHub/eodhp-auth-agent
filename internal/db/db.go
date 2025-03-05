package db

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Token struct {
	ID           string
	Token        string
	Name         string
	Workspace    string
	UserID       string
	Scope        string
	Access       string
	AccessExpiry int64
	Refresh      string
	Expires      int64
	Created      int64
}

func (t Token) IsExpired() bool {
	return time.Now().Unix() > t.Expires
}

var ErrNotFound = errors.New("db: not found")
var ErrTokenExpired = errors.New("db: token expired")

type TokenDB struct {
	TokenDBInputs
	db          *sql.DB
	crypto      *crypto
	prefixBytes []byte
	log         *zerolog.Logger
}

type TokenDBInputs struct {
	Prefix                  string `yaml:"prefix"`
	Secret                  string `yaml:"secret"`
	AccessTokenExpiryMargin int16  `yaml:"access_token_expiry_margin"`
}

func NewTokenDB(inputs TokenDBInputs) *TokenDB {
	logger := log.With().Str("name", "token db").Logger()
	crypto, err := newCrypto(inputs.Secret)
	if err != nil {
		logger.Fatal().Err(err).Msg("db: failed to create crypto for database")
	}
	if len(inputs.Prefix) != 4 {
		logger.Fatal().Str("prefix", inputs.Prefix).
			Msg("db: token prefix must be 4 characters long")
	}
	return &TokenDB{
		TokenDBInputs: inputs,
		crypto:        crypto,
		prefixBytes:   []byte(inputs.Prefix),
		log:           &logger,
	}
}

func (t *TokenDB) OpenDB(driver, dataSourceName string) error {
	t.log.Info().Msg("opening database connection")

	var err error
	t.db, err = sql.Open(driver, dataSourceName)
	if err != nil {
		t.log.Error().Err(err).Msg("failed to open database connection")
		return err
	}

	return nil
}

func (t *TokenDB) CloseDB() error {
	if err := t.db.Close(); err != nil {
		return err
	}
	t.log.Info().Msg("database connection closed")
	t.db = nil
	t.log = nil
	return nil
}

func (t TokenDB) Ping() error {
	t.log.Trace().Msg("pinging database")
	return t.db.Ping()
}

func (t TokenDB) InitDB() error {
	t.log.Info().Msg("initialising database")
	var err error

	// Create the token table if it does not exist
	t.log.Debug().Msg("creating token table")
	_, err = t.db.Exec(
		`CREATE TABLE IF NOT EXISTS tokens (
			id UUID PRIMARY KEY,
			name TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			workspace TEXT NOT NULL,
			user_id UUID NOT NULL,
			access TEXT NOT NULL,
			access_expiry INT NOT NULL,
			refresh TEXT NOT NULL,
			expires INT NOT NULL,
			scope TEXT NOT NULL,
			created INT NOT NULL
		)`)
	if err != nil {
		t.log.Error().Err(err).Msg("failed to create token table")
		return err
	}

	// Create token database indices
	t.log.Trace().Msg("creating token database indices")
	_, err = t.db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_token ON tokens(token);
		CREATE INDEX IF NOT EXISTS idx_user ON tokens(workspace);
		CREATE INDEX IF NOT EXISTS idx_user ON tokens(user_id);
	`)
	if err != nil {
		t.log.Error().Err(err).Msg("failed to create token database indices")
		return err
	}

	t.log.Info().Msg("database initialised")
	return nil
}

func (t TokenDB) GetTokenByID(id string) (*Token, error) {
	t.log.Trace().Msg("getting token by id")

	token := &Token{}
	err := t.db.QueryRow(
		`SELECT id, name, workspace, user_id, scope, access, 
		access_expiry, refresh, expires, created
		FROM tokens 
		WHERE id = $1`, id).
		Scan(&token.ID, &token.Name, &token.Workspace, &token.UserID,
			&token.Scope, &token.Access, &token.AccessExpiry, &token.Refresh,
			&token.Expires, &token.Created)
	if err != nil {
		if err == sql.ErrNoRows {
			t.log.Warn().Err(ErrNotFound).Msg("token not found")
			return nil, ErrNotFound
		}
		t.log.Err(err).Msg("failed to get token by id")
		return nil, err
	}
	// token.Token is not returned because it has been hashed

	t.log.Debug().Msg("token found")
	return token, nil
}

func (t TokenDB) DeleteTokenByID(id string) error {
	t.log.Trace().Msg("deleting token by id")

	result, err := t.db.Exec(
		`DELETE FROM tokens WHERE id = $1`, id)
	if err != nil {
		t.log.Err(err).Msg("failed to delete token by id")
		return err
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		t.log.Warn().Err(ErrNotFound).Msg("token not found")
		return ErrNotFound
	} else if rows > 1 {
		t.log.Warn().Msg("more than one token deleted")
	}

	t.log.Debug().Msg("token deleted")
	return nil
}

func (t TokenDB) GetTokenByAPIToken(apiToken string) (*Token, error) {
	t.log.Trace().Msg("getting token by api token")

	// Calculate hash of API token
	hashToken := t.crypto.hash(apiToken)

	token := &Token{
		Token: apiToken,
	}
	var cypherAccess *string
	var cypherRefresh *string
	err := t.db.QueryRow(
		`SELECT id, name, workspace, user_id, scope, access, access_expiry, 
		refresh, expires, created 
		FROM tokens 
		WHERE token = $1`,
		hashToken).
		Scan(&token.ID, &token.Name, &token.Workspace, &token.UserID,
			&token.Scope, &cypherAccess, &token.AccessExpiry, &cypherRefresh,
			&token.Expires, &token.Created)
	if err != nil {
		if err == sql.ErrNoRows {
			t.log.Warn().Err(ErrNotFound).Msg("token not found")
			return nil, ErrNotFound
		}
		t.log.Err(err).Msg("failed to get token by api token")
		return nil, err
	}

	// Decrypt the sensitive values
	token.Token = apiToken
	token.Access, err = t.crypto.decrypt(*cypherAccess)
	if err != nil {
		t.log.Err(err).Msg("failed to decrypt access token")
		return nil, err
	}
	token.Refresh, err = t.crypto.decrypt(*cypherRefresh)
	if err != nil {
		t.log.Err(err).Msg("failed to decrypt refresh token")
		return nil, err
	}

	t.log.Debug().Msg("token found")
	return token, nil
}

func (t TokenDB) CreateToken(token Token) error {
	t.log.Trace().Msg("creating token")

	// Calculate hash of API token
	hashToken := t.crypto.hash(token.Token)

	// Encrypt the sensitive values
	cypherAccess, err := t.crypto.encrypt(token.Access)
	if err != nil {
		t.log.Err(err).Msg("failed to encrypt access token")
		return err
	}
	cypherRefresh, err := t.crypto.encrypt(token.Refresh)
	if err != nil {
		t.log.Err(err).Msg("failed to encrypt refresh token")
		return err
	}

	_, err = t.db.Exec(
		`INSERT INTO tokens (id, token, name, workspace, user_id, scope, 
		access, access_expiry, refresh, expires, created) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		token.ID, hashToken, token.Name, token.Workspace, token.UserID,
		token.Scope, cypherAccess, token.AccessExpiry, cypherRefresh,
		token.Expires, token.Created)
	if err != nil {
		t.log.Err(err).Msg("failed to create token")
		return err
	}

	t.log.Debug().Msg("token created")
	return nil
}

func (t TokenDB) UpdateToken(token Token) error {
	t.log.Trace().Msg("updating token")

	// Calculate hash of API token
	hashToken := t.crypto.hash(token.Token)

	// Encrypt the sensitive values
	cypherAccess, err := t.crypto.encrypt(token.Access)
	if err != nil {
		t.log.Err(err).Msg("failed to encrypt access token")
		return err
	}
	cypherRefresh, err := t.crypto.encrypt(token.Refresh)
	if err != nil {
		t.log.Err(err).Msg("failed to encrypt refresh token")
		return err
	}

	_, err = t.db.Exec(
		`UPDATE tokens SET access = $1, access_expiry = $2, refresh = $3
		WHERE token = $4`,
		cypherAccess, token.AccessExpiry, cypherRefresh, hashToken)
	if err != nil {
		if err == sql.ErrNoRows {
			t.log.Warn().Err(ErrNotFound).Msg("token not found")
			return ErrNotFound
		}
		t.log.Err(err).Msg("failed to update token")
		return err
	}

	t.log.Debug().Msg("token updated")
	return nil
}

func (t TokenDB) GetUserToken(id, workspace, userID string) (*Token, error) {
	t.log.Trace().Msg("getting user token")

	token := &Token{}
	err := t.db.QueryRow(
		`SELECT id, name, workspace, user_id, scope, access, 
		access_expiry, refresh, expires, created
		FROM tokens 
		WHERE id = $1 AND workspace = $2 AND user_id = $3`,
		id, workspace, userID).
		Scan(&token.ID, &token.Name, &token.Workspace, &token.UserID,
			&token.Scope, &token.Access, &token.AccessExpiry, &token.Refresh,
			&token.Expires, &token.Created)
	if err != nil {
		if err == sql.ErrNoRows {
			t.log.Warn().Err(ErrNotFound).Msg("token not found")
			return nil, ErrNotFound
		}
		t.log.Err(err).Msg("failed to get user token")
		return nil, err
	}
	// token.Token is not returned because it has been hashed

	t.log.Debug().Msg("token found")
	return token, nil
}

func (t TokenDB) ListUserTokens(workspace, userID string) ([]*Token, error) {
	t.log.Trace().Msg("listing user tokens")

	var tokens []*Token

	rows, err := t.db.Query(
		`SELECT id, access_expiry, name, workspace, scope, expires, created
		FROM tokens WHERE workspace = $1 AND user_id = $2`, workspace, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return tokens, nil
		}
		t.log.Err(err).Msg("failed to list user tokens")
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		token := &Token{
			UserID: userID,
		}
		err := rows.Scan(&token.ID, &token.AccessExpiry, &token.Name,
			&token.Workspace, &token.Scope, &token.Expires, &token.Created)
		if err != nil {
			t.log.Err(err).Msg("failed to scan token")
			return nil, err
		}

		tokens = append(tokens, token)
	}

	t.log.Debug().Msg("user tokens listed")
	return tokens, nil
}

func (t TokenDB) IsAPIToken(token string) bool {
	tokenBytes, err := hex.DecodeString(token)
	if err != nil {
		return false
	}
	return bytes.HasPrefix(tokenBytes, t.prefixBytes)
}

func (t TokenDB) GenerateAPIToken() (string, error) {
	tokenBytes := make([]byte, 16)
	copy(tokenBytes[0:4], t.prefixBytes)
	_, err := rand.Read(tokenBytes[4:])
	if err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)
	return token, nil
}

func (t TokenDB) AccessTokenRequiresRefresh(token Token) bool {
	return time.Now().Add(
		time.Duration(t.AccessTokenExpiryMargin)*time.Second).
		Unix() > token.AccessExpiry
}
