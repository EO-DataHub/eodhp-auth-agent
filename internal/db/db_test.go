//go:build !production

package db

import (
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

// Setup fixture for tests
func setup() *TokenDB {
	logger := log.With().Str("name", "token db").Logger()
	crypto, err := newCrypto("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		panic(err)
	}
	c := &TokenDB{
		crypto: crypto,
		log:    &logger,
	}
	err = c.OpenDB("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	err = c.InitDB()
	if err != nil {
		panic(err)
	}
	return c
}

// Teardown fixture for tests
func teardown(c *TokenDB) {
	c.CloseDB()
}

func TestGetToken_TokenExists(t *testing.T) {
	// Setup fixture
	c := setup()
	defer teardown(c)

	// Initialise a user
	userID := uuid.New().String()


	// Initialise a token
	token := Token{
		ID:           uuid.New().String(),
		Token:        "testtoken",
		UserID:       userID,
		Access:       "testaccess",
		AccessExpiry: 0,
		Refresh:      "testrefresh",
	}
	err := c.CreateToken(token)
	assert.NoError(t, err)

	// Get the token
	result, err := c.GetTokenByAPIToken(token.Token)
	assert.NoError(t, err)
	assert.Equal(t, token.Token, result.Token)
}

func TestGetToken_TokenDoesNotExist(t *testing.T) {
	// Setup fixture
	c := setup()
	defer teardown(c)

	apiToken, err := c.GenerateAPIToken()
	assert.NoError(t, err)

	// Get the token
	_, err = c.GetTokenByAPIToken(apiToken)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestUpdateToken_Updated(t *testing.T) {
	// Setup fixture
	c := setup()
	defer teardown(c)

	// Initialise a token
	token := Token{
		ID:           uuid.New().String(),
		Token:        "testtoken",
		UserID:       "user-id",
		Access:       "testaccess",
		AccessExpiry: 0,
		Refresh:      "testrefresh",
	}
	err := c.CreateToken(token)
	assert.NoError(t, err)

	token.Access = "newaccess"
	token.Refresh = "newrefresh"
	token.AccessExpiry = 3600

	err = c.UpdateToken(token)
	assert.NoError(t, err)

	// Get the token
	result, err := c.GetTokenByAPIToken(token.Token)
	assert.NoError(t, err)
	assert.Equal(t, token.Access, result.Access)
	assert.Equal(t, token.Refresh, result.Refresh)
	assert.Equal(t, token.AccessExpiry, result.AccessExpiry)
}
