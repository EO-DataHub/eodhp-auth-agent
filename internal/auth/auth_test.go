package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
		CookieName: "test-cookie",
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
		CookieName: "test-cookie",
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
		CookieName: "test-cookie",
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
		CookieName: "test-cookie",
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

func TestAuthenticator_ExchangeError(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		CookieName: "test-cookie",
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
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	// Create a new authenticator
	a := Authenticator{
		AuthServer: server.URL,
		AuthMethod: http.MethodGet,
		CookieName: "test-cookie",
		client:     server.Client(),
		tokens: &mockTokens{
			token: "test-bearer",
		},
	}

	// Create a new request with an API token
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	isAuthenticated := a.IsAuthenticated(req)

	if !isAuthenticated {
		t.Fatalf("Expected request to be authenticated")
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
		AuthServer: server.URL,
		AuthMethod: http.MethodGet,
		CookieName: "test-cookie",
		client:     server.Client(),
		tokens: &mockTokens{
			token: "test-bearer",
		},
	}

	// Create a new request with an API token
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	isAuthenticated := a.IsAuthenticated(req)

	if isAuthenticated {
		t.Fatalf("Expected request to be unauthenticated")
	}
}
