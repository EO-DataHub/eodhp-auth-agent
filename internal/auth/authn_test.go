package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
)

type mockTokens struct {
	token string
	err   error
}

func (m *mockTokens) GetJWTToken(apiToken string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.token, nil
}

func TestCreateAuthRequest_ValidAPIToken(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		tokens: &mockTokens{
			token: "jwt-token",
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, "https://test.com")
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer A1B2C3D4")

	authRequest, err := a.createAuthRequest(req)

	if err != nil {
		t.Fatalf("Expected request to be created")
	}

	if authRequest.Header.Get("Authorization") != "Bearer jwt-token" {
		t.Fatalf("Incorrect Authorization header: %s",
			authRequest.Header.Get("Authorization"))
	}

	if _, err := authRequest.Cookie("test-cookie"); err == nil {
		t.Fatalf("No cookie should be attached")
	}
}

func TestCreateAuthRequest_ValidBearerToken(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
	}

	// Create token
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
	token, err := createJWTToken(claims)
	if err != nil {
		t.Fatal("Failed to create JWT token")
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, "https://test.com")
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	authRequest, err := a.createAuthRequest(req)

	if err != nil {
		t.Fatalf("Expected request to be created")
	}

	if authRequest.Header.Get("Authorization") !=
		fmt.Sprintf("Bearer %s", token) {

		t.Fatalf("Incorrect Authorization header: %s",
			authRequest.Header.Get("Authorization"))
	}

	if cookie, err := authRequest.Cookie("test-cookie"); err == nil {
		t.Fatalf("No cookie should be attached: %s", cookie.Value)
	}
}

func TestCreateAuthRequest_ValidSession(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, "https://test.com")
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

func TestCreateAuthRequest_NoAuth(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, "https://test.com")
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

func TestCreateAuthRequest_TokenError(t *testing.T) {
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
	req, err := createRequest(http.MethodGet, "https://test.com")
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

func TestIsAuthenticated_Authenticated(t *testing.T) {
	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := setAuthenticatedResponse(w); err != nil {
				t.Fatalf("Error creating response: %v", err)
			}
		}))
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Error parsing URL: %v", err)
	}

	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			AuthURL:    server.URL,
			AuthMethod: http.MethodGet,
			CookieName: "test-cookie",
			Domains:    []string{parsedURL.Host},
		},
		client: server.Client(),
		tokens: &mockTokens{
			token: "test-bearer",
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, server.URL)
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

func TestIsAuthenticated_Unauthenticated(t *testing.T) {
	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Error parsing URL: %v", err)
	}

	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			AuthURL:    server.URL,
			AuthMethod: http.MethodGet,
			CookieName: "test-cookie",
			Domains:    []string{parsedURL.Host},
		},
		client: server.Client(),
		tokens: &mockTokens{
			token: "test-bearer",
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, server.URL)
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

func TestIsAuthenticated_UnallowedOrigin(t *testing.T) {
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
			Domains:    []string{server.URL},
		},
		client: server.Client(),
		tokens: &mockTokens{
			token: "test-bearer",
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, server.URL)
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

func TestIsOriginAllowed_OriginAllowedSpecific(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			Domains: []string{"example.com", "test.com"},
		},
	}

	// Create a new request with the origin set
	req, err := createRequest(http.MethodGet, "https://test.com")
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	if isAllowed, err := a.isHostAllowed(req); err != nil {
		t.Fatalf("Error checking origin")
	} else if !isAllowed {
		t.Fatalf("Expected origin to be allowed")
	}
}

func TestIsOriginAllowed_OriginAllowedWildcard(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			Domains: []string{"*"},
		},
	}

	// Create a new request with the origin set
	req, err := createRequest(http.MethodGet, "https://test.com")
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	if isAllowed, err := a.isHostAllowed(req); err != nil {
		t.Fatalf("Error checking origin")
	} else if !isAllowed {
		t.Fatalf("Expected origin to be allowed")
	}
}

func TestIsOriginAllowed_OriginNotAllowed(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			Domains: []string{"test.com"},
		},
	}

	// Create a new request with the origin set
	req, err := createRequest(http.MethodGet, "https://example.com")
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	if isAllowed, err := a.isHostAllowed(req); err != nil {
		t.Fatalf("Error checking origin")
	} else if isAllowed {
		t.Fatalf("Expected origin to be disallowed")
	}
}

func TestIsOriginAllowed_OriginAllowedPartialWildcard(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			Domains: []string{"*.test.com"},
		},
	}

	// Create a new request with the origin set
	req, err := createRequest(http.MethodGet, "https://sub.test.com")
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	if isAllowed, err := a.isHostAllowed(req); err != nil {
		t.Fatalf("Error checking origin")
	} else if !isAllowed {
		t.Fatalf("Expected origin to be allowed")
	}
}

func createRequest(method, url string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func setAuthenticatedResponse(w http.ResponseWriter) error {
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
	token, err := createJWTToken(claims)
	if err != nil {
		return err
	}
	w.Header().Set("X-Auth-Request-Access-Token",
		fmt.Sprintf("Bearer %s", token))
	w.WriteHeader(http.StatusOK)
	return nil
}

func createJWTToken(claims *Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secret := []byte("your-secret-key")
	signedToken, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}
