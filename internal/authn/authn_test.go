//go:build !production

package authn

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

type mockTokens struct {
	getToken     *db.Token
	getErr       error
	getCalled    bool
	updateErr    error
	updateCalled bool
}

func (m *mockTokens) GetTokenByAPIToken(apiToken string) (*db.Token, error) {
	m.getCalled = true

	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.getToken, nil
}

func (m *mockTokens) UpdateToken(token db.Token) error {
	m.updateCalled = true
	if m.updateErr != nil {
		return m.updateErr
	}
	return nil
}

func (m *mockTokens) IsAPIToken(token string) bool {
	return strings.HasPrefix(token, "api")
}

type mockAuth struct {
	refreshToken  *keycloak.TokenResponse
	refreshErr    error
	refreshCalled bool
}

func (m *mockAuth) RefreshToken(refreshToken string) (*keycloak.TokenResponse,
	error) {

	m.refreshCalled = true
	if m.refreshErr != nil {
		return nil, m.refreshErr
	}
	return m.refreshToken, nil
}

func TestIsAuthenticated_ValidBearerToken_Authenticated(t *testing.T) {
	// Create a valid auth response bearer token
	token, err := CreateJWTToken(Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: "abcd-1234",
		},
		Username: "testuser",
		RealmAccess: struct {
			Roles []string `json:"roles"`
		}{
			Roles: []string{"test_role_1", "test_role_2"},
		},
	}, "secret")
	if err != nil {
		t.Fatalf("Error creating JWT token: %v", err)
	}

	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(AuthResponseAccessTokenHeader, token)
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	// Create a new authenticator
	a, err := NewAuthenticator(AuthenticatorInputs{
		AuthURL: server.URL,
	}, &mockTokens{}, &mockAuth{})
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}

	// Create a new request with an access token
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal("Error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer access-token")

	// Method under test
	authenticated, claims, err := a.IsAuthenticated(w, req)

	// Check result
	assert.NoError(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, fmt.Sprintf("Bearer %s", token),
		w.Header().Get("Authorization"))
	assert.Equal(t, "testuser", claims.Username)
	assert.Equal(t, 2, len(claims.RealmAccess.Roles))
	assert.Equal(t, "test_role_1", claims.RealmAccess.Roles[0])
	assert.Equal(t, "test_role_2", claims.RealmAccess.Roles[1])
	assert.False(t, a.tokenDB.(*mockTokens).getCalled)
	assert.False(t, a.tokenDB.(*mockTokens).updateCalled)
	assert.False(t, a.auth.(*mockAuth).refreshCalled)
}

func TestIsAuthenticated_ValidAPIToken_Authenticated(t *testing.T) {
	// Create a valid auth response bearer token
	token, err := CreateJWTToken(Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: "abcd-1234",
		},
		Username: "testuser",
		RealmAccess: struct {
			Roles []string `json:"roles"`
		}{
			Roles: []string{"test_role_1", "test_role_2"},
		},
	}, "secret")
	if err != nil {
		t.Fatalf("Error creating JWT token: %v", err)
	}

	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(AuthResponseAccessTokenHeader, token)
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	// Create a new authenticator
	a, err := NewAuthenticator(AuthenticatorInputs{
		AuthURL: server.URL,
	}, &mockTokens{
		getToken: &db.Token{
			ID:           "token-id",
			Token:        "api-token",
			UserID:       "user-id",
			Access:       "access-token",
			AccessExpiry: time.Now().Add(time.Hour).Unix(),
			Refresh:      "refresh-token",
		},
	}, &mockAuth{})
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}

	// Create a new request with a API token
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal("Error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer api-token")

	// Method under test
	authenticated, claims, err := a.IsAuthenticated(w, req)

	// Check result
	assert.NoError(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, fmt.Sprintf("Bearer %s", token),
		w.Header().Get("Authorization"))
	assert.Equal(t, "testuser", claims.Username)
	assert.Equal(t, 2, len(claims.RealmAccess.Roles))
	assert.Equal(t, "test_role_1", claims.RealmAccess.Roles[0])
	assert.Equal(t, "test_role_2", claims.RealmAccess.Roles[1])
	assert.True(t, a.tokenDB.(*mockTokens).getCalled)
	assert.False(t, a.tokenDB.(*mockTokens).updateCalled)
	assert.False(t, a.auth.(*mockAuth).refreshCalled)
}

func TestIsAuthenticated_AccessTokenRequiresRefresh_Authenticated(t *testing.T) {
	// Create a valid auth response bearer token
	token, err := CreateJWTToken(Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: "abcd-1234",
		},
		Username: "testuser",
		RealmAccess: struct {
			Roles []string `json:"roles"`
		}{
			Roles: []string{"test_role_1", "test_role_2"},
		},
	}, "secret")
	if err != nil {
		t.Fatalf("Error creating JWT token: %v", err)
	}

	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(AuthResponseAccessTokenHeader, token)
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	// Create a new authenticator
	a, err := NewAuthenticator(AuthenticatorInputs{
		AuthURL: server.URL,
	}, &mockTokens{
		getToken: &db.Token{
			ID:           "token-id",
			Token:        "api-token",
			UserID:       "user-id",
			Access:       "access-token",
			AccessExpiry: time.Now().Add(-10 * time.Minute).Unix(), // Expired
			Refresh:      "refresh-token",
			Expires:      time.Now().Add(time.Hour).Unix(),
		},
	}, &mockAuth{
		refreshToken: &keycloak.TokenResponse{
			Access:    "new-access",
			Refresh:   "new-refresh",
			ExpiresIn: 3600,
		},
	})
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}

	// Create a new request with a API token
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal("Error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer api-token")

	// Method under test
	authenticated, claims, err := a.IsAuthenticated(w, req)

	// Check result
	assert.NoError(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, fmt.Sprintf("Bearer %s", token),
		w.Header().Get("Authorization"))
	assert.Equal(t, "testuser", claims.Username)
	assert.Equal(t, 2, len(claims.RealmAccess.Roles))
	assert.Equal(t, "test_role_1", claims.RealmAccess.Roles[0])
	assert.Equal(t, "test_role_2", claims.RealmAccess.Roles[1])
	assert.True(t, a.tokenDB.(*mockTokens).getCalled)
	assert.True(t, a.tokenDB.(*mockTokens).updateCalled)
	assert.True(t, a.auth.(*mockAuth).refreshCalled)
}

func TestIsAuthenticated_NoAuth_Unauthenticated(t *testing.T) {
	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
	defer server.Close()

	// Create a new authenticator
	a, err := NewAuthenticator(AuthenticatorInputs{
		AuthURL: server.URL,
	}, &mockTokens{}, &mockAuth{})
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}

	// Create a new request with an no authorization
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal("Error creating request: %w", err)
	}

	// Method under test
	authenticated, claims, err := a.IsAuthenticated(w, req)

	// Check result
	assert.NoError(t, err)
	assert.False(t, authenticated)
	assert.Equal(t, "", w.Header().Get("Authorization"))
	assert.Equal(t, claims.Subject, "")
	assert.Equal(t, claims.Username, "")
	assert.Equal(t, len(claims.RealmAccess.Roles), 0)
	assert.False(t, a.tokenDB.(*mockTokens).getCalled)
	assert.False(t, a.tokenDB.(*mockTokens).updateCalled)
	assert.False(t, a.auth.(*mockAuth).refreshCalled)
}
