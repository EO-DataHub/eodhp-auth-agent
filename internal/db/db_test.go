//go:build !production

package db

import (
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

// Setup fixture for tests
func setup() *TokenDB {
	c := &TokenDB{}
	err := c.OpenDB("sqlite3", ":memory:")
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

func TestGetUserID_UserExists(t *testing.T) {
	// Setup fixture
	c := setup()
	defer teardown(c)

	// Initialise a user
	user := User{
		ID:       uuid.New().String(),
		Username: "testuser",
	}
	err := c.CreateUser(user)
	assert.NoError(t, err)

	// Get the user ID
	result, err := c.GetUserByID(user.ID)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, result.ID)
}

func TestGetUserID_UserDoesNotExist(t *testing.T) {
	// Setup fixture
	c := setup()
	defer teardown(c)

	// Initialise another user
	user := User{
		ID:       uuid.New().String(),
		Username: "anotheruser",
	}
	err := c.CreateUser(user)
	assert.NoError(t, err)

	// Get the user ID
	_, err = c.GetUserByID(uuid.New().String())
	assert.ErrorIs(t, err, ErrInvalidUser)
}

func TestGetToken_TokenExists(t *testing.T) {
	// Setup fixture
	c := setup()
	defer teardown(c)

	// Initialise a user
	user := User{
		ID:       uuid.New().String(),
		Username: "testuser",
	}
	err := c.CreateUser(user)
	assert.NoError(t, err)

	// Initialise a token
	token := Token{
		ID:           uuid.New().String(),
		Token:        "testtoken",
		UserID:       user.ID,
		Access:       "testaccess",
		AccessExpiry: 0,
		Refresh:      "testrefresh",
	}
	err = c.CreateToken(token)
	assert.NoError(t, err)

	// Get the token
	result, err := c.GetToken(token.Token)
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
	_, err = c.GetToken(apiToken)
	assert.ErrorIs(t, err, ErrInvalidToken)
}
