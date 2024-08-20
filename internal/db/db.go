package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type User struct {
	ID       string
	Username string
}

type Token struct {
	ID           string `json:"id"`
	Token        string `json:"token"`
	UserID       string `json:"user"`
	Access       string
	AccessExpiry int64
	Refresh      string
}

func (t Token) IsValid() bool {
	// Include a 5 second buffer to account for any latency
	return time.Now().Add(5*time.Second).Unix() >= t.AccessExpiry
}

var ErrInvalidToken = errors.New("db: invalid api token")
var ErrInvalidUser = errors.New("db: invalid user")
var ErrTokenExpired = errors.New("db: token expired")

type TokenDB struct {
	APITokenConfig
	db     *sql.DB
	crypto *crypto
	log    *zerolog.Logger
}

type APITokenConfig struct {
	Prefix string `yaml:"prefix"`
	Secret string `yaml:"secret"`
}

func NewTokenDB(config APITokenConfig) *TokenDB {
	logger := log.With().Str("name", "token db").Logger()
	crypto, err := newCrypto(config.Secret)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create crypto for database")
		panic(err)
	}
	return &TokenDB{
		APITokenConfig: config,
		crypto:         crypto,
		log:            &logger,
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

func (t TokenDB) InitDB() error {
	t.log.Info().Msg("initialising database")
	var err error

	// Create the user table if it does not exist
	t.log.Debug().Msg("creating user table")
	_, err = t.db.Exec(
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY,
			username TEXT NOT NULL
		)`)
	if err != nil {
		t.log.Error().Err(err).Msg("failed to create user table")
		return err
	}

	// Create the token table if it does not exist
	t.log.Debug().Msg("creating token table")
	_, err = t.db.Exec(
		`CREATE TABLE IF NOT EXISTS tokens (
			id UUID PRIMARY KEY,
			token TEXT NOT NULL UNIQUE,
			user UUID NOT NULL,
			access TEXT NOT NULL,
			access_expiry INT NOT NULL,
			refresh TEXT NOT NULL,
			FOREIGN KEY (user) REFERENCES users (id)
		)`)
	if err != nil {
		t.log.Error().Err(err).Msg("failed to create token table")
		return err
	}

	// Create an index on the tokens(token) column
	t.log.Debug().Msg("creating tokens(token) index")
	_, err = t.db.Exec(`CREATE INDEX idx_token ON tokens(token)`)
	if err != nil {
		t.log.Error().Err(err).Msg("failed to create tokens(token) index")
		return err
	}

	// Create an index on the tokens(user) column
	t.log.Debug().Msg("creating tokens(user) index")
	_, err = t.db.Exec(`CREATE INDEX idx_user ON tokens(user)`)
	if err != nil {
		t.log.Error().Err(err).Msg("failed to create tokens(user) index")
		return err
	}

	t.log.Info().Msg("database initialised")
	return nil
}

func (t TokenDB) GetUserByID(userID string) (*User, error) {
	t.log.Debug().Msg("getting user")

	user := &User{}
	err := t.db.QueryRow(
		`SELECT id, username FROM users WHERE id = $1`, userID).
		Scan(&user.ID, &user.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			t.log.Debug().Msg("user not found")
			return nil, ErrInvalidUser
		}
		t.log.Debug().Err(err).Msg("failed to get user by id")
		return nil, err
	}

	t.log.Debug().Msg("user found")
	return user, nil
}

func (t TokenDB) CreateUser(user User) error {
	logger := t.log.With().Str("username", user.Username).Logger()
	logger.Debug().Msg("creating user")

	_, err := t.db.Exec(
		`INSERT INTO users (id, username) 
		VALUES ($1, $2)`, user.ID, user.Username)
	if err != nil {
		logger.Debug().Err(err).Msg("failed to create user")
		return err
	}

	logger.Debug().Msg("user created")
	return nil
}

func (t TokenDB) GetTokenByID(id string) (*Token, error) {
	t.log.Debug().Msg("getting token by id")

	token := &Token{}
	err := t.db.QueryRow(
		`SELECT id, token, user, access, access_expiry, refresh
		FROM tokens WHERE id = $1`, id).
		Scan(&token.ID, &token.Token, &token.UserID, &token.Access,
			&token.AccessExpiry, &token.Refresh)
	if err != nil {
		if err == sql.ErrNoRows {
			t.log.Debug().Msg("token not found")
			return nil, ErrInvalidToken
		}
		t.log.Err(err).Msg("failed to get token by id")
		return nil, err
	}

	t.log.Debug().Msg("token found")
	return token, nil
}

func (t TokenDB) GetTokenByAPIToken(apiToken string) (*Token, error) {
	t.log.Debug().Msg("getting token by api token")

	cypherToken, err := t.crypto.encrypt(apiToken)
	if err != nil {
		t.log.Err(err).Msg("failed to encrypt api token")
		return nil, err
	}

	token := &Token{}
	var cypherAccess *string
	var cypherRefresh *string
	err = t.db.QueryRow(
		`SELECT id, user, access, access_expiry, refresh
		FROM tokens WHERE token = $1`, cypherToken).
		Scan(&token.ID, &token.UserID, &cypherAccess, &token.AccessExpiry,
			&cypherRefresh)
	if err != nil {
		if err == sql.ErrNoRows {
			t.log.Debug().Msg("token not found")
			return nil, ErrInvalidToken
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
	t.log.Debug().Msg("creating token")

	// Encrypt the sensitive values
	cypherToken, err := t.crypto.encrypt(token.Token)
	if err != nil {
		t.log.Err(err).Msg("failed to encrypt token")
		return err
	}
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
		`INSERT INTO tokens (id, token, user, access, access_expiry, refresh) 
		VALUES ($1, $2, $3, $4, $5, $6) 
		RETURNING id, token, user, access, access_expiry, refresh`,
		token.ID, cypherToken, token.UserID, cypherAccess, token.AccessExpiry,
		cypherRefresh)
	if err != nil {
		t.log.Err(err).Msg("failed to create token")
		return err
	}

	t.log.Debug().Msg("token created")
	return nil
}

func (t TokenDB) UpdateToken(token Token) error {
	t.log.Debug().Msg("updating token")

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
		cypherAccess, token.AccessExpiry, cypherRefresh, token.Token)
	if err != nil {
		t.log.Err(err).Msg("failed to update token")
		return err
	}

	t.log.Debug().Msg("token updated")
	return nil
}

func (t TokenDB) ListUserTokens(userID string) ([]*Token, error) {
	t.log.Debug().Msg("listing user tokens")

	rows, err := t.db.Query(
		`SELECT id, token, user, access, access_expiry, refresh
		FROM tokens WHERE user = $1`, userID)
	if err != nil {
		t.log.Err(err).Msg("failed to list user tokens")
		return nil, err
	}
	defer rows.Close()

	var tokens []*Token
	for rows.Next() {
		token := &Token{}
		var cypherToken *string
		var cypherAccess *string
		var cypherRefresh *string
		err := rows.Scan(&token.ID, &cypherToken, &token.UserID, &cypherAccess,
			&token.AccessExpiry, &cypherRefresh)
		if err != nil {
			t.log.Err(err).Msg("failed to scan token")
			return nil, err
		}

		// Decrypt the sensitive values
		token.Token, err = t.crypto.decrypt(*cypherToken)
		if err != nil {
			t.log.Err(err).Msg("failed to decrypt token")
			return nil, err
		}
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
		tokens = append(tokens, token)
	}

	t.log.Debug().Msg("user tokens listed")
	return tokens, nil
}

func (t TokenDB) DeleteTokenByID(id string) error {
	t.log.Debug().Msg("deleting token")

	_, err := t.db.Exec(
		`DELETE FROM tokens WHERE id = $1`, id)
	if err != nil {
		t.log.Err(err).Msg("failed to delete token")
		return err
	}

	t.log.Debug().Msg("token deleted")
	return nil
}

func (t TokenDB) GenerateAPIToken() (string, error) {
	tokenBytes := make([]byte, 16)
	prefixLen := len(t.APITokenConfig.Prefix)
	copy(tokenBytes[0:prefixLen], []byte(t.APITokenConfig.Prefix))
	_, err := rand.Read(tokenBytes[prefixLen:])
	if err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)
	return token, nil
}
