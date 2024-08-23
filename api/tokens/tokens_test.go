package tokens

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/api/middleware"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func setupKeycloakClient(handler http.Handler) (*httptest.Server,
	*keycloak.KeycloakClient) {

	server := httptest.NewServer(handler)

	k := keycloak.NewKeycloakClient(keycloak.KeycloakClientInputs{
		KeycloakURL:  server.URL,
		Realm:        "test",
		ClientID:     "myclient",
		ClientSecret: "mysecret",
	})
	return server, k
}

func setupTokenDB() *db.TokenDB {
	d := db.NewTokenDB(db.TokenDBInputs{
		Secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Prefix: "TEST",
	})
	err := d.OpenDB("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	err = d.InitDB()
	if err != nil {
		panic(err)
	}
	return d
}

func TestListTokensHandler_Authenticated_Success(t *testing.T) {
	// Setup the token DB
	d := setupTokenDB()
	defer d.CloseDB()

	// Populate the DB with some tokens
	tokens := make([]db.Token, 3)
	userID := "ABCDEFG-12345678"
	for i := range tokens {
		tokens[i] = db.Token{
			ID:           uuid.New().String(),
			Token:        fmt.Sprintf("test-token-%d", i),
			UserID:       userID,
			Access:       fmt.Sprintf("test-access-%d", i),
			AccessExpiry: time.Now().Add(time.Hour).Unix(),
			Refresh:      fmt.Sprintf("test-refresh-%d", i),
		}
		err := d.CreateToken(tokens[i])
		assert.NoError(t, err)
	}

	// Populate the DB with a token for a different user
	err := d.CreateToken(db.Token{
		ID:           uuid.New().String(),
		Token:        "test-token-4",
		UserID:       "TUVWXYZ-87654321",
		Access:       "test-access-4",
		AccessExpiry: time.Now().Add(time.Hour).Unix(),
		Refresh:      "test-refresh-4",
	})
	assert.NoError(t, err)

	// Create handler
	handler := ListTokensHandler(d)

	// Setup request and response
	r := httptest.NewRequest("GET", "/tokens", nil)
	claims := &authn.Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: userID,
		},
	}
	ctx := context.WithValue(r.Context(), middleware.ClaimsKey, *claims)
	w := httptest.NewRecorder()

	// Test the handler
	handler.ServeHTTP(w, r.WithContext(ctx))
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response body
	var response []GetTokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(response), 3)
}

func TestCreateTokenHandler_Authenticated_Success(t *testing.T) {
	// Setup Token DB
	tokenDB := setupTokenDB()
	defer tokenDB.CloseDB()

	// Setup auth server response for Keycloak Client
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &keycloak.TokenResponse{
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
			ExpiresIn:    3600,
		}
		w.WriteHeader(http.StatusOK)
		respBody, err := json.Marshal(resp)
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.Write(respBody)
		if err != nil {
			t.Fatal(err)
		}
	})
	server, k := setupKeycloakClient(h)
	defer server.Close()

	// Create handler
	handler := CreateTokenHandler(tokenDB, k)

	// Setup request and response
	r := httptest.NewRequest("POST", "/tokens", nil)
	userID := "ABCDEFG-12345678"
	claims := authn.Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: userID,
		},
	}
	token, err := authn.CreateJWTToken(claims, "secret-key")
	assert.NoError(t, err)
	ctx := context.WithValue(r.Context(), middleware.TokenKey, token)
	ctx = context.WithValue(ctx, middleware.ClaimsKey, claims)
	w := httptest.NewRecorder()

	// Test the handler
	handler.ServeHTTP(w, r.WithContext(ctx))
	assert.Equal(t, http.StatusAccepted, w.Code)

	// Parse the response body
	var response CreateTokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, "", response.ID)
	assert.NotEqual(t, "", response.Token)
	assert.Equal(t, userID, response.UserID)

	// Check object was created in DB
	dbToken, err := tokenDB.GetTokenByID(response.ID, userID)
	assert.NoError(t, err)
	assert.Equal(t, response.ID, dbToken.ID)
}

func TestGetTokenHandler_Authenticated_Success(t *testing.T) {
	// Setup the token DB
	d := setupTokenDB()
	defer d.CloseDB()

	// Populate the DB with a token
	tokenID := uuid.New().String()
	userID := "ABCDEFG-12345678"
	err := d.CreateToken(db.Token{
		ID:           tokenID,
		Token:        "test-token-1",
		UserID:       userID,
		Access:       "test-access-1",
		AccessExpiry: time.Now().Add(time.Hour).Unix(),
		Refresh:      "test-refresh-1",
	})
	assert.NoError(t, err)

	// Create handler
	handler := GetTokenHandler(d)

	// Setup request and response
	r := httptest.NewRequest("GET", fmt.Sprintf("/tokens/%s", tokenID), nil)
	claims := &authn.Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: userID,
		},
	}
	r = mux.SetURLVars(r, map[string]string{"token_id": tokenID})
	ctx := context.WithValue(r.Context(), middleware.ClaimsKey, *claims)
	w := httptest.NewRecorder()

	// Test the handler
	handler.ServeHTTP(w, r.WithContext(ctx))
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response body
	var response GetTokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, tokenID, response.ID)
	assert.Equal(t, userID, response.UserID)
}

func TestDeleteTokenHandler_Authenticated_Success(t *testing.T) {
	// Setup the token DB
	d := setupTokenDB()
	defer d.CloseDB()

	// Populate the DB with a token
	tokenID := uuid.New().String()
	userID := "ABCDEFG-12345678"
	err := d.CreateToken(db.Token{
		ID:           tokenID,
		Token:        "test-token-1",
		UserID:       userID,
		Access:       "test-access-1",
		AccessExpiry: time.Now().Add(time.Hour).Unix(),
		Refresh:      "test-refresh-1",
	})
	assert.NoError(t, err)

	// Create handler
	handler := DeleteTokenHandler(d)

	// Setup request and response
	r := httptest.NewRequest("DELETE", fmt.Sprintf("/tokens/%s", tokenID), nil)
	claims := &authn.Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: userID,
		},
	}
	r = mux.SetURLVars(r, map[string]string{"token_id": tokenID})
	ctx := context.WithValue(r.Context(), middleware.ClaimsKey, *claims)
	w := httptest.NewRecorder()

	// Test the handler
	handler.ServeHTTP(w, r.WithContext(ctx))
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Check object was deleted from DB
	_, err = d.GetTokenByID(tokenID, userID)
	assert.ErrorIs(t, err, db.ErrNotFound)
}

func TestListTokensHandler_NoTokens_SuccessEmptyList(t *testing.T) {
	// Setup the token DB
	d := setupTokenDB()
	defer d.CloseDB()

	userID := "ABCDEFG-12345678"

	// Populate the DB with a token for a different user
	err := d.CreateToken(db.Token{
		ID:           uuid.New().String(),
		Token:        "test-token-4",
		UserID:       "TUVWXYZ-87654321",
		Access:       "test-access-4",
		AccessExpiry: time.Now().Add(time.Hour).Unix(),
		Refresh:      "test-refresh-4",
	})
	assert.NoError(t, err)

	// Create handler
	handler := ListTokensHandler(d)

	// Setup request and response
	r := httptest.NewRequest("GET", "/tokens", nil)
	claims := &authn.Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: userID,
		},
	}
	ctx := context.WithValue(r.Context(), middleware.ClaimsKey, *claims)
	w := httptest.NewRecorder()

	// Test the handler
	handler.ServeHTTP(w, r.WithContext(ctx))
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response body
	var response []GetTokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(response), 0)
}

func TestGetTokenHandler_RequestTokenForAnotherUser_NotFound(t *testing.T) {
	// Setup the token DB
	d := setupTokenDB()
	defer d.CloseDB()

	// Populate the DB with a token
	tokenID := uuid.New().String()
	userID := "ABCDEFG-12345678"
	err := d.CreateToken(db.Token{
		ID:           tokenID,
		Token:        "test-token-1",
		UserID:       "TUVWXYZ-87654321", // another user
		Access:       "test-access-1",
		AccessExpiry: time.Now().Add(time.Hour).Unix(),
		Refresh:      "test-refresh-1",
	})
	assert.NoError(t, err)

	// Create handler
	handler := GetTokenHandler(d)

	// Setup request and response
	r := httptest.NewRequest("GET", fmt.Sprintf("/tokens/%s", tokenID), nil)
	claims := &authn.Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: userID,
		},
	}
	r = mux.SetURLVars(r, map[string]string{"token_id": tokenID})
	ctx := context.WithValue(r.Context(), middleware.ClaimsKey, *claims)
	w := httptest.NewRecorder()

	// Test the handler
	handler.ServeHTTP(w, r.WithContext(ctx))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteTokenHandler_RequestTokenForAnotherUser_NotFound(t *testing.T) {
	// Setup the token DB
	d := setupTokenDB()
	defer d.CloseDB()

	// Populate the DB with a token
	tokenID := uuid.New().String()
	userID := "ABCDEFG-12345678"
	err := d.CreateToken(db.Token{
		ID:           tokenID,
		Token:        "test-token-1",
		UserID:       "TUVWXYZ-87654321", // another user
		Access:       "test-access-1",
		AccessExpiry: time.Now().Add(time.Hour).Unix(),
		Refresh:      "test-refresh-1",
	})
	assert.NoError(t, err)

	// Create handler
	handler := DeleteTokenHandler(d)

	// Setup request and response
	r := httptest.NewRequest("GET", fmt.Sprintf("/tokens/%s", tokenID), nil)
	claims := &authn.Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: userID,
		},
	}
	r = mux.SetURLVars(r, map[string]string{"token_id": tokenID})
	ctx := context.WithValue(r.Context(), middleware.ClaimsKey, *claims)
	w := httptest.NewRecorder()

	// Test the handler
	handler.ServeHTTP(w, r.WithContext(ctx))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetTokenHandler_NotAuthenticated_Unauthorized(t *testing.T) {
	// Setup the token DB
	d := setupTokenDB()
	defer d.CloseDB()

	// Populate the DB with a token
	tokenID := uuid.New().String()
	userID := "ABCDEFG-12345678"
	err := d.CreateToken(db.Token{
		ID:           tokenID,
		Token:        "test-token-1",
		UserID:       userID,
		Access:       "test-access-1",
		AccessExpiry: time.Now().Add(time.Hour).Unix(),
		Refresh:      "test-refresh-1",
	})
	assert.NoError(t, err)

	// Create handler
	handler := GetTokenHandler(d)

	// Setup request and response with no authentication
	r := httptest.NewRequest("GET", fmt.Sprintf("/tokens/%s", tokenID), nil)
	r = mux.SetURLVars(r, map[string]string{"token_id": tokenID})
	w := httptest.NewRecorder()

	// Test the handler
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
