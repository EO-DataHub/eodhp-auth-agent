package authn

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/golang-jwt/jwt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type AuthenticatorInputs struct {
	Name    string   `yaml:"name"`
	AuthURL string   `yaml:"auth_url"`
	Domains []string `yaml:"domains"`
}

type Authenticator struct {
	AuthenticatorInputs
	proxy        *httputil.ReverseProxy
	hostPatterns []regexp.Regexp
	tokenDB      TokenDB
	auth         AuthClient
}

type TokenDB interface {
	GetTokenByAPIToken(apiToken string) (*db.Token, error)
	IsAPIToken(token string) bool
	UpdateToken(token db.Token) error
}

type AuthClient interface {
	RefreshToken(refreshToken string) (*keycloak.TokenResponse, error)
}

var ErrInvalidHost = errors.New("authn: invalid host")
var ErrInvalidJWT = errors.New("authn: invalid jwt token")
var ErrMissingAuthResponseClaims = errors.New(
	"authn: missing auth response claims")

func NewAuthenticator(inputs AuthenticatorInputs, tokenDB TokenDB,
	auth AuthClient) (*Authenticator, error) {

	url, err := url.Parse(inputs.AuthURL)
	if err != nil {
		return nil, fmt.Errorf(
			"authenticator %s: Could not parse auth url: %w", inputs.Name, err)
	}

	// Precompile regex patterns for host matching
	hostPatterns := compileGlobPatterns(inputs.Domains)

	return &Authenticator{
		AuthenticatorInputs: inputs,
		proxy:               httputil.NewSingleHostReverseProxy(url),
		hostPatterns:        hostPatterns,
		tokenDB:             tokenDB,
		auth:                auth,
	}, nil
}

type Claims struct {
	jwt.StandardClaims
	Username    string `json:"preferred_username"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

type AuthResponse struct {
	IsAuthenticated      bool
	Claims               Claims
	AuthenticationHeader string
}

// Authenticates the request by proxying it to the authentication server and
// checking the response status code. If the response status code is 2xx, the
// request is considered authenticated.
//
// The response writer is updated with the response from the upstream server and
// should be used to write the response to the client. The final status code has
// not been set, and should be with w.WriteHeader(statusCode) by the calling
// function.
func (a Authenticator) IsAuthenticated(req *http.Request) (bool, error) {

	logger := zerolog.Ctx(req.Context()).With().
		Str("authenticator", a.Name).Logger()

	// Check the target domain of the request, deny if not allowed
	isHostAllowed := a.isHostAllowed(req.Host)
	if !isHostAllowed {
		logger.Debug().Err(ErrInvalidHost).Msg("host not allowed")
		return false, ErrInvalidHost
	}
	logger.Debug().Msg("host allowed")

	// Check if the request is using auth-agent API token for authentication
	if hasAPIToken, token := a.hasAPIToken(req); hasAPIToken {
		// Exchange API token for JWT token
		jwtToken, err := a.exchangeAPIToken(token)
		if err != nil {
			logger.Error().Err(err).Msg("failed to exchange API token")
			// Continue as request may be authenticated by other means
		} else {
			// Replace API token with JWT token in Authorization header
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwtToken))
		}
	}

	// Proxy the response to the authentication server
	logger.Info().Msg("proxying request to auth server")
	w2 := NewAuthRW(w)
	a.proxy.ServeHTTP(w2, req)
	logger.Info().Msg("proxy response received")

	for k, v := range w2.Header() {
		logger.Info().Msgf("auth response header: %s: %s", k, v)
	}

	// Return the authentication decision. The proxy response is also caputed in
	// the response writer, which should normally have been passed by reference.
	return w2.IsAuthenticated(), nil
}

func (a Authenticator) isHostAllowed(host string) bool {
	for _, pattern := range a.hostPatterns {
		matched := pattern.Match([]byte(host))
		if matched {
			return true
		}
	}
	return false
}

// Checks if the request Authorization header contains an API token. If so,
// returns the token and true, otherwise returns an empty string and false.
func (a Authenticator) hasAPIToken(req *http.Request) (bool, string) {
	// Extract Authorization header
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		// No further processing required
		return false, ""
	}

	// Check if Authorization header is Bearer token
	if !strings.HasPrefix(authHeader, "Bearer ") {
		// No further processing required
		return false, ""
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Check if token has API prefix
	if !a.tokenDB.IsAPIToken(token) {
		// No further processing required
		return false, ""
	}

	return true, token
}

// Exchange API token for JWT access token from the token database. If the
// access token has expired, it is refreshed using the refresh token and the
// database is updated with the new access and refresh token.
func (a *Authenticator) exchangeAPIToken(apiToken string) (string, error) {
	// Get token from DB
	token, err := a.tokenDB.GetTokenByAPIToken(apiToken)
	if err != nil {
		return "", fmt.Errorf("failed to get token by api token: %w", err)
	}

	// Check token access expiry
	if !token.IsValid() {
		// Token has expired, refresh it
		tokenResponse, err := a.auth.RefreshToken(token.Refresh)
		if err != nil {
			return "", fmt.Errorf("failed to refresh token: %w", err)
		}

		// Update DB with new access token
		token.Access = tokenResponse.Access
		token.Refresh = tokenResponse.Refresh
		token.AccessExpiry = time.Now().Unix() + int64(tokenResponse.ExpiresIn)
		err = a.tokenDB.UpdateToken(*token)
		if err != nil {
			return "", fmt.Errorf("failed to update token: %w", err)
		}
	}

	// Return access token
	return token.Access, nil
}

type authRW struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func NewAuthRW(w http.ResponseWriter) *authRW {
	return &authRW{
		ResponseWriter: w,
		body:           bytes.NewBuffer(nil),
	}
}

func (w *authRW) IsAuthenticated() bool {
	return w.statusCode >= 200 && w.statusCode < 300
}

func (w *authRW) WriteHeader(statusCode int) {
	log.Debug().Msgf("auth response status code: %d", statusCode)
	w.statusCode = statusCode
}

func (w *authRW) Write(b []byte) (int, error) {
	return w.body.Write(b)
}
