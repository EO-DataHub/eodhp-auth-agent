package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
)

type mockTokens struct {
	token string
	err   error
}

func (m *mockTokens) exchangeTokenForBearer(token string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.token, nil
}

func TestAuthenticator_ValidAPIToken(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
		tokens: &mockTokens{
			token: "test-bearer",
		},
	}

	// Create a new request with an API token
	req, err := http.NewRequest(http.MethodGet, "https://test.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Token test-token")

	authRequest, err := a.createAuthRequest(req)

	if err != nil {
		t.Fatalf("Expected request to be created")
	}

	if authRequest.Header.Get("Authorization") != "Bearer test-bearer" {
		t.Fatalf("Incorrect Authorization header: %s",
			authRequest.Header.Get("Authorization"))
	}

	if _, err := authRequest.Cookie("test-cookie"); err == nil {
		t.Fatalf("No cookie should be attached")
	}
}

func TestAuthenticator_ValidBearerToken(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
	}

	// Create a new request with an API token
	req, err := http.NewRequest(http.MethodGet, "https://test.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-bearer")

	authRequest, err := a.createAuthRequest(req)

	if err != nil {
		t.Fatalf("Expected request to be created")
	}

	if authRequest.Header.Get("Authorization") != "Bearer test-bearer" {
		t.Fatalf("Incorrect Authorization header: %s",
			authRequest.Header.Get("Authorization"))
	}

	if cookie, err := authRequest.Cookie("test-cookie"); err == nil {
		t.Fatalf("No cookie should be attached: %s", cookie.Value)
	}
}

func TestAuthenticator_ValidSession(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
	}

	// Create a new request with an API token
	req, err := http.NewRequest(http.MethodGet, "https://test.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.AddCookie(&http.Cookie{
		Name:  "test-cookie",
		Value: "abcdefghi",
	})

	authRequest, err := a.createAuthRequest(req)

	if err != nil {
		t.Fatalf("Expected request to be created")
	}

	cookie, err := authRequest.Cookie("test-cookie")
	if err != nil {
		t.Fatalf("Expected cookie to be attached")
	}

	if cookie.Value != "abcdefghi" {
		t.Fatalf("Incorrect Cookie: %s", cookie.Value)
	}

	if header := authRequest.Header.Get("Authorization"); header != "" {
		t.Fatalf("No Authorization header should be attached: %s", header)
	}
}

func TestAuthenticator_NoAuth(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
	}

	// Create a new request with an API token
	req, err := http.NewRequest(http.MethodGet, "https://test.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	authRequest, err := a.createAuthRequest(req)

	if err != nil {
		t.Fatalf("Expected request to be created")
	}

	if header := authRequest.Header.Get("Authorization"); header != "" {
		t.Fatalf("No Authorization header should be attached: %s", header)
	}

	if cookie, err := authRequest.Cookie("test-cookie"); err == nil {
		t.Fatalf("No cookie should be attached: %s", cookie.Value)
	}
}

func TestAuthenticator_TokenError(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
		tokens: &mockTokens{
			err: ErrInvalidToken,
		},
	}

	// Create a new request with an API token
	req, err := http.NewRequest(http.MethodGet, "https://test.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Token test-token")

	authRequest, err := a.createAuthRequest(req)

	if err != nil {
		t.Fatalf("Expected request to be created")
	}

	if header := authRequest.Header.Get("Authorization"); header != "" {
		t.Fatalf("No Authorization header should be attached: %s", header)
	}

	if cookie, err := authRequest.Cookie("test-cookie"); err == nil {
		t.Fatalf("No cookie should be attached: %s", cookie.Value)
	}
}

func TestAuthenticator_Authenticated(t *testing.T) {
	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := setSuccessResponse(w); err != nil {
				t.Fatalf("Error creating response: %v", err)
			}
		}))
	defer server.Close()

	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			AuthURL:    server.URL,
			AuthMethod: http.MethodGet,
			CookieName: "test-cookie",
		},
		client: server.Client(),
		tokens: &mockTokens{
			token: "test-bearer",
		},
	}

	// Create a new request with an API token
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	isAuthenticated, claims := a.IsAuthenticated(req)

	if !isAuthenticated {
		t.Fatalf("Expected request to be authenticated")
	}

	if claims.Username != "test-user" {
		t.Fatalf("Incorrect username: %s", claims.Username)
	}

	if len(claims.RealmAccess.Roles) != 1 {
		t.Fatalf("Incorrect number of roles: %d", len(claims.RealmAccess.Roles))
	}

	if claims.RealmAccess.Roles[0] != "test-role" {
		t.Fatalf("Incorrect role: %s", claims.RealmAccess.Roles[0])
	}
}

func TestAuthenticator_Unauthenticated(t *testing.T) {
	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
	defer server.Close()

	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			AuthURL:    server.URL,
			AuthMethod: http.MethodGet,
			CookieName: "test-cookie",
		},
		client: server.Client(),
		tokens: &mockTokens{
			token: "test-bearer",
		},
	}

	// Create a new request with an API token
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	isAuthenticated, claims := a.IsAuthenticated(req)

	if isAuthenticated {
		t.Fatalf("Expected request to be unauthenticated")
	}

	if claims.Username != "" {
		t.Fatalf("Incorrect username: %s", claims.Username)
	}

	if len(claims.RealmAccess.Roles) != 0 {
		t.Fatalf("Incorrect number of roles: %d", len(claims.RealmAccess.Roles))
	}
}

func setSuccessResponse(w http.ResponseWriter) error {
	claims := &Claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		Username: "test-user",
		RealmAccess: struct {
			Roles []string `json:"roles"`
		}{
			Roles: []string{"test-role"},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secret := []byte("your-secret-key")
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return err
	}
	w.Header().Set("X-Auth-Request-Access-Token",
		fmt.Sprintf("Bearer %s", tokenString))
	w.WriteHeader(http.StatusOK)
	return nil
}
