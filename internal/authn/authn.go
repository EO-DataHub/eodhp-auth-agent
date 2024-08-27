package authn

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/rs/zerolog"
)

type AuthenticatorInputs struct {
	Name    string   `yaml:"name"`
	AuthURL string   `yaml:"auth_url"`
	Domains []string `yaml:"domains"`
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
var ErrMissingAuthResponseClaims = errors.New(
	"authn: missing auth response claims")

const AuthResponseAccessTokenHeader = "X-Auth-Request-Access-Token"

type Authenticator struct {
	AuthenticatorInputs
	http         *http.Client
	hostPatterns []regexp.Regexp
	tokenDB      TokenDB
	auth         AuthClient
}

func NewAuthenticator(inputs AuthenticatorInputs, tokenDB TokenDB,
	auth AuthClient) (*Authenticator, error) {

	return &Authenticator{
		AuthenticatorInputs: inputs,
		http:                &http.Client{},
		hostPatterns:        compileGlobPatterns(inputs.Domains),
		tokenDB:             tokenDB,
		auth:                auth,
	}, nil
}

func (a Authenticator) IsAuthenticated(w http.ResponseWriter,
	req *http.Request) (bool, *Claims, error) {

	logger := zerolog.Ctx(req.Context()).With().
		Str("authenticator", a.Name).Logger()

	// Check the target domain of the request, deny if not allowed
	isHostAllowed := a.isHostAllowed(req.Host)
	if !isHostAllowed {
		logger.Debug().Err(ErrInvalidHost).Msg("host not allowed")
		return false, nil, ErrInvalidHost
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

	// Send authentication request to the auth server
	r2, err := http.NewRequest(http.MethodGet, a.AuthURL, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create auth request")
		return false, nil, err
	}
	r2.Host, r2.Header = req.Host, req.Header
	resp, err := a.http.Do(r2)
	if err != nil {
		logger.Error().Err(err).Msg("failed to send auth request")
		return false, nil, err
	}

	// Check the response status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Debug().Int("status_code", resp.StatusCode).
			Msg("auth request failed")
		return false, nil, nil
	}

	// Copy authentication response headers to the response writer
	copyHeader(w.Header(), resp.Header)
	// Replace ID token with access token in Authorization header
	w.Header().Set("Authorization", resp.Header.Get(AuthResponseAccessTokenHeader))
	w.Header().Del(AuthResponseAccessTokenHeader)

	// Parse the claims from the auth response Authorization header
	claims, err := ParseClaims(strings.TrimPrefix(
		w.Header().Get("Authorization"), "Bearer "))
	if err != nil {
		logger.Warn().Err(err).Msg("failed to parse claims")
		return true, &claims, err
	} else {
		logger.Debug().Interface("claims", claims).Msg("parsed claims")
	}

	return true, &claims, nil
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
