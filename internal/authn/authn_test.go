//go:build !production

package authn

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer A1B2C3D4")

	authRequest, err := a.createAuthRequest(req)

	assert.NoError(t, err)
	assert.Equal(t, authRequest.Header.Get("Authorization"), "Bearer jwt-token")

	_, err = authRequest.Cookie("test-cookie")
	assert.Error(t, err)
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
	assert.NoError(t, err)

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, "https://test.com")
	assert.NoError(t, err)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	authRequest, err := a.createAuthRequest(req)
	assert.NoError(t, err)

	assert.Equal(t, authRequest.Header.Get("Authorization"),
		fmt.Sprintf("Bearer %s", token))

	_, err = authRequest.Cookie("test-cookie")
	assert.Error(t, err)
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
	assert.NoError(t, err)

	req.AddCookie(&http.Cookie{
		Name:  "test-cookie",
		Value: "abcdefghi",
	})

	authRequest, err := a.createAuthRequest(req)
	assert.NoError(t, err)

	cookie, err := authRequest.Cookie("test-cookie")
	assert.NoError(t, err)
	assert.Equal(t, cookie.Value, "abcdefghi")
	assert.Equal(t, authRequest.Header.Get("Authorization"), "")
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
	assert.NoError(t, err)

	authRequest, err := a.createAuthRequest(req)
	assert.NoError(t, err)
	assert.Equal(t, authRequest.Header.Get("Authorization"), "")

	_, err = authRequest.Cookie("test-cookie")
	assert.Error(t, err)
}

func TestCreateAuthRequest_TokenError(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
		tokens: &mockTokens{
			err: db.ErrInvalidToken,
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, "https://test.com")
	assert.NoError(t, err)

	req.Header.Set("Authorization", "Token test-token")

	authRequest, err := a.createAuthRequest(req)
	assert.NoError(t, err)
	assert.Equal(t, authRequest.Header.Get("Authorization"), "")

	_, err = authRequest.Cookie("test-cookie")
	assert.Error(t, err)
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
	assert.NoError(t, err)

	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			AuthURL:    server.URL,
			AuthMethod: http.MethodGet,
			CookieName: "test-cookie",
			Domains:    []string{parsedURL.Host},
		},
		http: server.Client(),
		tokens: &mockTokens{
			token: "test-bearer",
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, server.URL)
	assert.NoError(t, err)

	isAuthenticated, claims := a.IsAuthenticated(req)

	assert.True(t, isAuthenticated)
	assert.Equal(t, claims.Username, "test-user")
	assert.Equal(t, claims.RealmAccess.Roles, []string{"test-role"})
}

func TestIsAuthenticated_Unauthenticated(t *testing.T) {
	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	assert.NoError(t, err)

	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			AuthURL:    server.URL,
			AuthMethod: http.MethodGet,
			CookieName: "test-cookie",
			Domains:    []string{parsedURL.Host},
		},
		http: server.Client(),
		tokens: &mockTokens{
			token: "test-bearer",
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, server.URL)
	assert.NoError(t, err)

	isAuthenticated, claims := a.IsAuthenticated(req)
	assert.False(t, isAuthenticated)
	assert.Equal(t, claims.Username, "")
	assert.Equal(t, claims.RealmAccess.Roles, []string([]string(nil)))
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
		http: server.Client(),
		tokens: &mockTokens{
			token: "test-bearer",
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, server.URL)
	assert.NoError(t, err)

	isAuthenticated, claims := a.IsAuthenticated(req)
	assert.False(t, isAuthenticated)
	assert.Equal(t, claims.Username, "")
	assert.Equal(t, claims.RealmAccess.Roles, []string([]string(nil)))
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
	assert.NoError(t, err)

	isAllowed, err := a.isHostAllowed(req)
	assert.NoError(t, err)
	assert.True(t, isAllowed)
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
	assert.NoError(t, err)

	isAllowed, err := a.isHostAllowed(req)
	assert.NoError(t, err)
	assert.True(t, isAllowed)
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
	assert.NoError(t, err)

	isAllowed, err := a.isHostAllowed(req)
	assert.NoError(t, err)
	assert.False(t, isAllowed)
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
	assert.NoError(t, err)

	isAllowed, err := a.isHostAllowed(req)
	assert.NoError(t, err)
	assert.True(t, isAllowed)
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
