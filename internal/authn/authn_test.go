//go:build !production

package authn

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
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

func TestProxyAuthRequest_ValidBearerToken_Authenticated(t *testing.T) {
	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Authorization", "Bearer server-token")
			w.WriteHeader(http.StatusOK)
		}))
	defer server.Close()

	// Create a new authenticator
	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Error parsing URL: %v", err)
	}
	a, err := NewAuthenticator(AuthenticatorInputs{
		AuthURL: server.URL,
		Domains: []string{parsedURL.Host},
	}, &mockTokens{}, &mockAuth{})
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}

	// Create a new request with a bearer token
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal("Error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer access-token")

	// Method under test
	authenticated, err := a.IsAuthenticated(w, req)

	// Check result
	assert.NoError(t, err)
	assert.True(t, authenticated)
	assert.Equal(t, "Bearer server-token", w.Header().Get("Authorization"))
}

// func TestCreateAuthRequest_ValidAPIToken_AuthHeaderSet(t *testing.T) {
// 	// Create a new authenticator
// 	a := Authenticator{
// 		tokenDB: &mockTokens{
// 			getToken: &db.Token{
// 				ID:           "token-id",
// 				Token:        "test-token",
// 				UserID:       "user-id",
// 				Access:       "access-token",
// 				AccessExpiry: time.Now().Add(time.Hour).Unix(),
// 				Refresh:      "refresh-token",
// 			},
// 		},
// 	}

// 	// Create a new request with an API token
// 	req, err := createRequest(http.MethodGet, "https://test.com")
// 	assert.NoError(t, err)
// 	req.Header.Set("Authorization", "Bearer api-token")

// 	authRequest, err := a.createAuthRequest(req)

// 	assert.NoError(t, err)
// 	assert.Equal(t, authRequest.Header.Get("Authorization"),
// 		"Bearer access-token")

// 	assert.True(t, a.tokenDB.(*mockTokens).getCalled)
// 	assert.False(t, a.tokenDB.(*mockTokens).updateCalled)
// }

// func TestCreateAuthRequest_ExpiredAPIToken_AuthHeaderSet(t *testing.T) {
// 	// Create a new authenticator
// 	a := Authenticator{
// 		tokenDB: &mockTokens{
// 			getToken: &db.Token{
// 				ID:           "token-id",
// 				Token:        "test-token",
// 				UserID:       "user-id",
// 				Access:       "expired-token",
// 				AccessExpiry: time.Now().Add(-1 * time.Minute).Unix(),
// 				Refresh:      "refresh-token",
// 			},
// 		},
// 		auth: &mockAuth{
// 			refreshToken: &keycloak.TokenResponse{
// 				AccessToken:  "new-access",
// 				RefreshToken: "new-refresh",
// 				ExpiresIn:    3600,
// 			},
// 		},
// 	}

// 	// Create a new request with an API token
// 	req, err := createRequest(http.MethodGet, "https://test.com")
// 	assert.NoError(t, err)
// 	req.Header.Set("Authorization", "Bearer api-token")

// 	authRequest, err := a.createAuthRequest(req)

// 	assert.NoError(t, err)
// 	assert.Equal(t, "Bearer new-access",
// 		authRequest.Header.Get("Authorization"))

// 	_, err = authRequest.Cookie("test-cookie")
// 	assert.Error(t, err)

// 	assert.True(t, a.tokenDB.(*mockTokens).getCalled)
// 	assert.True(t, a.tokenDB.(*mockTokens).updateCalled)
// 	assert.True(t, a.auth.(*mockAuth).refreshCalled)
// }

// func TestCreateAuthRequest_ValidBearerToken_AuthHeaderSet(t *testing.T) {
// 	// Create a new authenticator
// 	a := Authenticator{
// 		AuthenticatorInputs: AuthenticatorInputs{
// 			CookieName: "test-cookie",
// 		},
// 		tokenDB: &mockTokens{},
// 	}

// 	// Create a new request with an bearer token
// 	req, err := createRequest(http.MethodGet, "https://test.com")
// 	assert.NoError(t, err)
// 	req.Header.Set("Authorization", "Bearer access-token")

// 	// Create auth request
// 	authRequest, err := a.createAuthRequest(req)
// 	assert.NoError(t, err)

// 	// Check that the Authorization header is set
// 	assert.Equal(t, "Bearer access-token",
// 		authRequest.Header.Get("Authorization"))
// }

// func TestCreateAuthRequest_ValidSession_AuthHeaderSet(t *testing.T) {
// 	// Create a new authenticator
// 	a := Authenticator{
// 		AuthenticatorInputs: AuthenticatorInputs{
// 			CookieName: "test-cookie",
// 		},
// 	}

// 	// Create a new request with a session cookie
// 	req, err := createRequest(http.MethodGet, "https://test.com")
// 	assert.NoError(t, err)
// 	req.AddCookie(&http.Cookie{
// 		Name:  "test-cookie",
// 		Value: "abcdefghi",
// 	})

// 	authRequest, err := a.createAuthRequest(req)
// 	assert.NoError(t, err)

// 	cookie, err := authRequest.Cookie("test-cookie")
// 	assert.NoError(t, err)
// 	assert.Equal(t, "abcdefghi", cookie.Value)
// 	assert.Equal(t, "", authRequest.Header.Get("Authorization"))
// }

// func TestCreateAuthRequest_NoAuth_NoAuthHeaderSet(t *testing.T) {
// 	// Create a new authenticator
// 	a := Authenticator{
// 		AuthenticatorInputs: AuthenticatorInputs{
// 			CookieName: "test-cookie",
// 		},
// 	}

// 	// Create a new request with no authentication
// 	req, err := createRequest(http.MethodGet, "https://test.com")
// 	assert.NoError(t, err)

// 	authRequest, err := a.createAuthRequest(req)
// 	assert.NoError(t, err)
// 	assert.Equal(t, "", authRequest.Header.Get("Authorization"))
// }

// func TestIsAuthenticated_ValidAPIToken_Authenticated(t *testing.T) {
// 	// Create a new test HTTP server
// 	server := httptest.NewServer(
// 		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			if err := setAuthenticatedResponse(w); err != nil {
// 				t.Fatalf("Error creating response: %v", err)
// 			}
// 		}))
// 	defer server.Close()

// 	parsedURL, err := url.Parse(server.URL)
// 	assert.NoError(t, err)

// 	// Create a new authenticator
// 	a := Authenticator{
// 		AuthenticatorInputs: AuthenticatorInputs{
// 			AuthURL:    server.URL,
// 			AuthMethod: http.MethodGet,
// 			CookieName: "test-cookie",
// 			Domains:    []string{parsedURL.Host},
// 		},
// 		http: server.Client(),
// 		tokenDB: &mockTokens{
// 			getToken: &db.Token{
// 				ID:           "token-id",
// 				Token:        "test-token",
// 				UserID:       "user-id",
// 				Access:       "access-token",
// 				AccessExpiry: time.Now().Add(time.Hour).Unix(),
// 				Refresh:      "refresh-token",
// 			},
// 		},
// 	}

// 	// Create a new request with an API token
// 	req, err := createRequest(http.MethodGet, server.URL)
// 	assert.NoError(t, err)

// 	authenticated, _, err := a.IsAuthenticated(req)

// 	assert.NoError(t, err)
// 	assert.True(t, authenticated)
// }

// func TestIsAuthenticated_NoAuth_Unauthenticated(t *testing.T) {
// 	// Create a new test HTTP server
// 	server := httptest.NewServer(
// 		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			w.WriteHeader(http.StatusUnauthorized)
// 		}))
// 	defer server.Close()

// 	parsedURL, err := url.Parse(server.URL)
// 	assert.NoError(t, err)

// 	// Create a new authenticator
// 	a := Authenticator{
// 		AuthenticatorInputs: AuthenticatorInputs{
// 			AuthURL:    server.URL,
// 			AuthMethod: http.MethodGet,
// 			CookieName: "test-cookie",
// 			Domains:    []string{parsedURL.Host},
// 		},
// 		http: server.Client(),
// 	}

// 	// Create a new request without any authentication
// 	req, err := createRequest(http.MethodGet, server.URL)
// 	assert.NoError(t, err)

// 	authenticated, _, err := a.IsAuthenticated(req)
// 	assert.NoError(t, err)
// 	assert.False(t, authenticated)
// }

// func TestIsAuthenticated_UnallowedIsHostAllowed_ReturnErr(t *testing.T) {
// 	// Create a new test HTTP server
// 	server := httptest.NewServer(
// 		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			w.WriteHeader(http.StatusUnauthorized)
// 		}))
// 	defer server.Close()

// 	// Create a new authenticator
// 	a := Authenticator{
// 		AuthenticatorInputs: AuthenticatorInputs{
// 			AuthURL:    server.URL,
// 			AuthMethod: http.MethodGet,
// 			CookieName: "test-cookie",
// 			Domains:    []string{server.URL},
// 		},
// 		http: server.Client(),
// 	}

// 	// Create a new request with an API token
// 	req, err := createRequest(http.MethodGet, server.URL)
// 	assert.NoError(t, err)

// 	authenticated, _, err := a.IsAuthenticated(req)
// 	assert.ErrorIs(t, err, ErrInvalidHost)
// 	assert.False(t, authenticated)
// }

// func TestIsHostAllowed_AllowedSpecific_True(t *testing.T) {
// 	// Create a new authenticator
// 	a := Authenticator{
// 		AuthenticatorInputs: AuthenticatorInputs{
// 			Domains: []string{"example.com", "test.com"},
// 		},
// 	}

// 	// Create a new request with the for host
// 	req, err := createRequest(http.MethodGet, "https://test.com")
// 	assert.NoError(t, err)

// 	isAllowed, err := a.isHostAllowed(req)
// 	assert.NoError(t, err)
// 	assert.True(t, isAllowed)
// }

// func TestIsHostAllowed_AllowedWildcard_True(t *testing.T) {
// 	// Create a new authenticator
// 	a := Authenticator{
// 		AuthenticatorInputs: AuthenticatorInputs{
// 			Domains: []string{"*"},
// 		},
// 	}

// 	// Create a new request with the host set
// 	req, err := createRequest(http.MethodGet, "https://test.com")
// 	assert.NoError(t, err)

// 	isAllowed, err := a.isHostAllowed(req)
// 	assert.NoError(t, err)
// 	assert.True(t, isAllowed)
// }

// func TestIsHostAllowed_NotAllowed_False(t *testing.T) {
// 	// Create a new authenticator
// 	a := Authenticator{
// 		AuthenticatorInputs: AuthenticatorInputs{
// 			Domains: []string{"test.com"},
// 		},
// 	}

// 	// Create a new request with the host set
// 	req, err := createRequest(http.MethodGet, "https://example.com")
// 	assert.NoError(t, err)

// 	isAllowed, err := a.isHostAllowed(req)
// 	assert.NoError(t, err)
// 	assert.False(t, isAllowed)
// }

// func TestIsHostAllowed_HostAllowedPartialWildcard_True(t *testing.T) {
// 	// Create a new authenticator
// 	a := Authenticator{
// 		AuthenticatorInputs: AuthenticatorInputs{
// 			Domains: []string{"*.test.com"},
// 		},
// 	}

// 	// Create a new request with the host set
// 	req, err := createRequest(http.MethodGet, "https://sub.test.com")
// 	assert.NoError(t, err)

// 	isAllowed, err := a.isHostAllowed(req)
// 	assert.NoError(t, err)
// 	assert.True(t, isAllowed)
// }
