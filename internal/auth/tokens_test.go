package auth

import (
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestGetUserID_UserExists(t *testing.T) {
	c := createTokenClient()
	defer c.CloseDB()

	// Initialise a user
	user, err := c.CreateUser("testuser")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Get the user ID
	result, err := c.GetUserByUsername(user.Username)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}

	if result.ID != user.ID {
		t.Fatalf("expected user ID %s, got %s", user.ID, result.ID)
	}
}

func TestGetUserID_UserDoesNotExist(t *testing.T) {
	c := createTokenClient()
	defer c.CloseDB()

	_, err := c.CreateUser("anotheruser")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Get the user ID
	_, err = c.GetUserByUsername("testuser")
	if err == nil {
		if err != ErrInvalidUser {
			t.Fatalf("expected invalid user error, got %v", err)
		}

		t.Fatalf("expected user to not exist")
	}
}

func TestGetToken_TokenExists(t *testing.T) {
	c := createTokenClient()
	defer c.CloseDB()

	// Initialise a user
	user, err := c.CreateUser("test-user")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Initialise a token
	token, err := c.CreateToken(user.ID)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Get the token
	_, err = c.GetToken(token.Token)
	if err != nil {
		t.Fatalf("failed to get token: %v", err)
	}
}

func TestGetToken_TokenDoesNotExist(t *testing.T) {
	c := createTokenClient()
	defer c.CloseDB()

	apiToken, err := generateToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Get the token
	_, err = c.GetToken(apiToken)
	if err == nil {
		if err != ErrInvalidToken {
			t.Fatalf("expected invalid token error, got %v", err)
		}

		t.Fatalf("expected token to not exist")
	}
}

func createTokenClient() *TokenClient {
	c := &TokenClient{}
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
