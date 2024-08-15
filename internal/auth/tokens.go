package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type User struct {
	ID       string
	Username string
}

type Token struct {
	ID     string
	Token  string
	UserID string
}

var ErrInvalidToken = errors.New("db: invalid api token")
var ErrInvalidUser = errors.New("db: invalid user")

type TokenClient struct {
	db  *sql.DB
	log *zerolog.Logger
}

func NewTokenClient() *TokenClient {
	logger := log.With().Str("name", "Token Client").Logger()
	return &TokenClient{
		log: &logger,
	}
}

func (t *TokenClient) OpenDB(driver, dataSourceName string) error {
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

func (t *TokenClient) CloseDB() error {
	if err := t.db.Close(); err != nil {
		return err
	}
	t.log.Info().Msg("database connection closed")
	t.db = nil
	t.log = nil
	return nil
}

func (t TokenClient) InitDB() error {
	t.log.Info().Msg("initialising database")
	var err error

	// Create the user table if it does not exist
	t.log.Debug().Msg("creating user table")
	_, err = t.db.Exec(
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY,
			username TEXT NOT NULL UNIQUE
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
			token TEXT NOT NULL,
			user UUID NOT NULL,
			FOREIGN KEY (user) REFERENCES users (id)
		)`)
	if err != nil {
		t.log.Error().Err(err).Msg("failed to create token table")
		return err
	}

	t.log.Info().Msg("database initialised")
	return nil
}

func (t TokenClient) GetUserByUsername(username string) (*User, error) {
	logger := t.log.With().Str("username", username).Logger()
	logger.Debug().Msg("getting user by username")

	user := &User{}
	err := t.db.QueryRow(
		`SELECT id, username FROM users 
		WHERE username = $1`, username).
		Scan(&user.ID, &user.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Debug().Msg("user not found")
			return nil, ErrInvalidUser
		}
		logger.Debug().Err(err).Msg("failed to get user by username")
		return nil, err
	}

	logger.Debug().Msg("user found")
	return user, nil
}

func (t TokenClient) CreateUser(username string) (*User, error) {
	logger := t.log.With().Str("username", username).Logger()
	logger.Debug().Msg("creating user")

	user := &User{}
	err := t.db.QueryRow(
		`INSERT INTO users (id, username) 
		VALUES ($1, $2) 
		RETURNING id, username`, uuid.New().String(), username).
		Scan(&user.ID, &user.Username)
	if err != nil {
		logger.Debug().Err(err).Msg("failed to create user")
		return nil, err
	}

	logger.Debug().Msg("user created")
	return user, nil
}

func (t TokenClient) GetToken(apiToken string) (*Token, error) {
	t.log.Debug().Msg("getting token by api token")

	token := &Token{}
	err := t.db.QueryRow(
		`SELECT id, token, user FROM tokens WHERE token = $1`, apiToken).
		Scan(&token.ID, &token.Token, &token.UserID)
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

func (t TokenClient) CreateToken(userID string) (*Token, error) {
	t.log.Debug().Msg("creating token")

	token := &Token{}
	apiToken, err := generateToken()
	if err != nil {
		t.log.Err(err).Msg("failed to generate token")
		return nil, err
	}
	t.log.Debug().Msg("token generated")

	err = t.db.QueryRow(
		`INSERT INTO tokens (id, token, user) 
		VALUES ($1, $2, $3) 
		RETURNING id, token, user`,
		uuid.New().String(), apiToken, userID).
		Scan(&token.ID, &token.Token, &token.UserID)
	if err != nil {
		t.log.Err(err).Msg("failed to create token")
		return nil, err
	}

	t.log.Debug().Msg("token created")
	return token, nil
}

func (t TokenClient) GetJWTToken(apiToken string) (string, error) {
	// This function is not implemented yet
	return apiToken, nil
}

func generateToken() (string, error) {
	tokenBytes := make([]byte, 16)
	copy(tokenBytes[0:4], []byte("EODH"))
	_, err := rand.Read(tokenBytes[4:])
	if err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)
	return token, nil
}
