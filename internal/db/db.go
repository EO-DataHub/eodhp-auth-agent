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
	APITokenPrefix string
	db             *sql.DB
	log            *zerolog.Logger
}

func (t *TokenDB) OpenDB(driver, dataSourceName string) error {
	logger := log.With().Str("name", "token client").
		Str("driver", driver).Str("source", dataSourceName).Logger()

	logger.Info().Msg("opening database connection")

	var err error
	t.db, err = sql.Open(driver, dataSourceName)
	if err != nil {
		logger.Error().Err(err).Msg("failed to open database connection")
		return err
	}

	t.log = &logger
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

	token := &Token{}
	err := t.db.QueryRow(
		`SELECT id, token, user, access, access_expiry, refresh
		FROM tokens WHERE token = $1`, apiToken).
		Scan(&token.ID, &token.Token, &token.UserID, &token.Access,
			&token.AccessExpiry, &token.Refresh)
	if err != nil {
		if err == sql.ErrNoRows {
			t.log.Debug().Msg("token not found")
			return nil, ErrInvalidToken
		}
		t.log.Err(err).Msg("failed to get token by api token")
		return nil, err
	}

	t.log.Debug().Msg("token found")
	return token, nil
}

func (t TokenDB) CreateToken(token Token) error {
	t.log.Debug().Msg("creating token")

	_, err := t.db.Exec(
		`INSERT INTO tokens (id, token, user, access, access_expiry, refresh) 
		VALUES ($1, $2, $3, $4, $5, $6) 
		RETURNING id, token, user, access, access_expiry, refresh`,
		token.ID, token.Token, token.UserID, token.Access, token.AccessExpiry,
		token.Refresh)
	if err != nil {
		t.log.Err(err).Msg("failed to create token")
		return err
	}

	t.log.Debug().Msg("token created")
	return nil
}

func (t TokenDB) UpdateToken(token Token) error {
	t.log.Debug().Msg("updating token")

	_, err := t.db.Exec(
		`UPDATE tokens SET access = $1, access_expiry = $2, refresh = $3
		WHERE token = $4`,
		token.Access, token.AccessExpiry, token.Refresh, token.Token)
	if err != nil {
		t.log.Err(err).Msg("failed to update token")
		return err
	}

	t.log.Debug().Msg("token updated")
	return nil
}

func (t TokenDB) ListUserTokens(userID string) ([]Token, error) {
	t.log.Debug().Msg("listing user tokens")

	rows, err := t.db.Query(
		`SELECT id, token, user, access, access_expiry, refresh
		FROM tokens WHERE user = $1`, userID)
	if err != nil {
		t.log.Err(err).Msg("failed to list user tokens")
		return nil, err
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		var token Token
		err := rows.Scan(&token.ID, &token.Token, &token.UserID, &token.Access,
			&token.AccessExpiry, &token.Refresh)
		if err != nil {
			t.log.Err(err).Msg("failed to scan token")
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
	prefixLen := len(t.APITokenPrefix)
	copy(tokenBytes[0:prefixLen], []byte(t.APITokenPrefix))
	_, err := rand.Read(tokenBytes[prefixLen:])
	if err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)
	return token, nil
}
