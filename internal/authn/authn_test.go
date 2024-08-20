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
	getToken  *db.Token
	getErr    error
	updateErr error
}

func (m *mockTokens) GetToken(apiToken string) (*db.Token, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.getToken, nil
}

func (m *mockTokens) UpdateToken(token db.Token) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	return nil
}

func TestCreateAuthRequest_ValidAPIToken_AuthHeaderSet(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		tokenDB: &mockTokens{
			getToken: &db.Token{
				ID:           "token-id",
				Token:        "test-token",
				UserID:       "user-id",
				Access:       "access-token",
				AccessExpiry: time.Now().Add(time.Hour).Unix(),
				Refresh:      "refresh-token",
			},
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, "https://test.com")
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer A1B2C3D4")

	authRequest, err := a.createAuthRequest(req)

	assert.NoError(t, err)
	assert.Equal(t, authRequest.Header.Get("Authorization"),
		"Bearer access-token")

	_, err = authRequest.Cookie("test-cookie")
	assert.Error(t, err)
}

func TestCreateAuthRequest_ValidBearerToken_AuthHeaderSet(t *testing.T) {
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

	// Create a new request with an bearer token
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

func TestCreateAuthRequest_ValidSession_AuthHeaderSet(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
	}

	// Create a new request with a session cookie
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

func TestCreateAuthRequest_NoAuth_NoAuthHeaderSet(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
	}

	// Create a new request with no authentication
	req, err := createRequest(http.MethodGet, "https://test.com")
	assert.NoError(t, err)

	authRequest, err := a.createAuthRequest(req)
	assert.NoError(t, err)
	assert.Equal(t, authRequest.Header.Get("Authorization"), "")

	_, err = authRequest.Cookie("test-cookie")
	assert.Error(t, err)
}

func TestCreateAuthRequest_InvalidAPIToken_NoAuthSet(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			CookieName: "test-cookie",
		},
		tokenDB: &mockTokens{
			getErr: db.ErrInvalidToken,
		},
	}

	// Create a new request with an invalid API token
	req, err := createRequest(http.MethodGet, "https://test.com")
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Token invalid-token")

	authRequest, err := a.createAuthRequest(req)
	assert.NoError(t, err)
	assert.Equal(t, authRequest.Header.Get("Authorization"), "")

	_, err = authRequest.Cookie("test-cookie")
	assert.Error(t, err)
}

func TestGetAuthenticatedClaims_ValidAPIToken_Authenticated(t *testing.T) {
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
		tokenDB: &mockTokens{
			getToken: &db.Token{
				ID:           "token-id",
				Token:        "test-token",
				UserID:       "user-id",
				Access:       "access-token",
				AccessExpiry: time.Now().Add(time.Hour).Unix(),
				Refresh:      "refresh-token",
			},
		},
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, server.URL)
	assert.NoError(t, err)

	claims, err := a.GetAuthenticatedClaims(req)

	assert.Nil(t, err)
	assert.Equal(t, claims.Username, "test-user")
	assert.Equal(t, claims.Subject, "test-subject")
	assert.Equal(t, claims.RealmAccess.Roles, []string{"test-role"})
}

func TestGetAuthenticatedClaims_NoAuth_Unauthenticated(t *testing.T) {
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
	}

	// Create a new request without any authentication
	req, err := createRequest(http.MethodGet, server.URL)
	assert.NoError(t, err)

	claims, err := a.GetAuthenticatedClaims(req)
	assert.ErrorIs(t, err, ErrAuthFailed)
	assert.Nil(t, claims)
}

func TestGetAuthenticatedClaims_UnallowedIsHostAllowed_ReturnErr(t *testing.T) {
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
	}

	// Create a new request with an API token
	req, err := createRequest(http.MethodGet, server.URL)
	assert.NoError(t, err)

	claims, err := a.GetAuthenticatedClaims(req)
	assert.ErrorIs(t, err, ErrInvalidHost)
	assert.Nil(t, claims)
}

func TestIsHostAllowed_AllowedSpecific_True(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			Domains: []string{"example.com", "test.com"},
		},
	}

	// Create a new request with the for host
	req, err := createRequest(http.MethodGet, "https://test.com")
	assert.NoError(t, err)

	isAllowed, err := a.isHostAllowed(req)
	assert.NoError(t, err)
	assert.True(t, isAllowed)
}

func TestIsHostAllowed_AllowedWildcard_True(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			Domains: []string{"*"},
		},
	}

	// Create a new request with the host set
	req, err := createRequest(http.MethodGet, "https://test.com")
	assert.NoError(t, err)

	isAllowed, err := a.isHostAllowed(req)
	assert.NoError(t, err)
	assert.True(t, isAllowed)
}

func TestIsHostAllowed_NotAllowed_False(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			Domains: []string{"test.com"},
		},
	}

	// Create a new request with the host set
	req, err := createRequest(http.MethodGet, "https://example.com")
	assert.NoError(t, err)

	isAllowed, err := a.isHostAllowed(req)
	assert.NoError(t, err)
	assert.False(t, isAllowed)
}

func TestIsHostAllowed_HostAllowedPartialWildcard_True(t *testing.T) {
	// Create a new authenticator
	a := Authenticator{
		AuthenticatorInputs: AuthenticatorInputs{
			Domains: []string{"*.test.com"},
		},
	}

	// Create a new request with the host set
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
			Subject:   "test-subject",
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
