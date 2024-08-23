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
	"github.com/golang-jwt/jwt"
	"github.com/rs/zerolog"
)

type AuthenticatorInputs struct {
	Name       string   `yaml:"name"`
	AuthURL    string   `yaml:"auth_url"`
	AuthMethod string   `yaml:"auth_method"`
	CookieName string   `yaml:"cookie_name"`
	Domains    []string `yaml:"domains"`
}

type Authenticator struct {
	AuthenticatorInputs
	http    *http.Client
	tokenDB TokenDB
	auth    AuthClient
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
	auth AuthClient) *Authenticator {

	return &Authenticator{
		AuthenticatorInputs: inputs,
		http:                &http.Client{},
		tokenDB:             tokenDB,
		auth:                auth,
	}
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

func (a Authenticator) IsAuthenticated(req *http.Request) (
	bool, *http.Response, error) {

	logger := zerolog.Ctx(req.Context()).With().
		Str("authenticator", a.Name).Logger()

	// Check the target domain of the request, deny if not allowed
	if isAllowed, err := a.isHostAllowed(req); err != nil {
		logger.Error().Err(err).Msg("failed to check domain")
		return false, nil, err
	} else if !isAllowed {
		logger.Debug().Err(ErrInvalidHost).Msg("host not allowed")
		return false, nil, ErrInvalidHost
	}
	logger.Debug().Msg("host allowed")

	authRequest, err := a.createAuthRequest(req)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create auth request")
		return false, nil, err
	}
	logger.Debug().Msg("authentication request created")

	// Send the authentication request
	authResp, err := a.http.Do(authRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to send authentication request")
		return false, nil, err
	}
	defer authResp.Body.Close()
	logger.Debug().Msg("authentication request sent")

	// Check the response status code is outwith the 2xx range
	if authResp.StatusCode < 200 || authResp.StatusCode >= 300 {
		logger.Info().
			Int("status_code", authResp.StatusCode).
			Msg("authentication request failed")
		return false, authResp, nil
	}
	logger.Info().
		Int("status_code", authResp.StatusCode).
		Msg("authentication request succeeded")

	return true, authResp, nil
}



func (a Authenticator) isHostAllowed(req *http.Request) (bool, error) {
	for _, pattern := range a.Domains {
		// Convert wildcard pattern to regular expression
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

		matched, err := regexp.MatchString(regexPattern, req.Host)
		if err != nil {
			return false, fmt.Errorf("failed to match host: %w", err)
		}
		if matched {
			return true, nil
		}
	}

	return false, nil
}

func (a Authenticator) createAuthRequest(req *http.Request) (*http.Request, error) {
	// Create a new request to the authentication URL
	authReq, err := http.NewRequest("GET", a.AuthURL, nil)
	if err != nil {
		return nil, err
	}
	// Copy the headers from the original request to the auth request
	authReq.Header = req.Header

	// Extract Authorization header
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		// No further processing required
		return authReq, nil
	}

	// Check if Authorization header is Bearer token
	if !strings.HasPrefix(authHeader, "Bearer ") {
		// No further processing required
		return authReq, nil
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Check if token has API prefix
	if !a.tokenDB.IsAPIToken(token) {
		// No further processing required
		return authReq, nil
	}

	// Exchange API token for JWT token
	jwtToken, err := a.exchangeAPIToken(token)
	if err != nil {
		// Request can still be sent to upstream as may be authenticated by
		// other means (e.g. session cookie)
		return authReq, nil
	}

	// Replace API token with JWT token in Authorization header
	authReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

	return authReq, nil
}

func (a *Authenticator) exchangeAPIToken(apiToken string) (string, error) {
	// Get token from DB
	token, err := a.tokenDB.GetTokenByAPIToken(apiToken)
	if err != nil {
		return "", fmt.Errorf("failed to get token by api token: %w", err)
	}

	// Check token access expiry
	if token.IsValid() {
		// Refresh token if access has expired
		tokenResponse, err := a.auth.RefreshToken(token.Refresh)
		if err != nil {
			return "", fmt.Errorf("failed to refresh token: %w", err)
		}

		// Update DB with new access token
		token.Access = tokenResponse.AccessToken
		token.Refresh = tokenResponse.RefreshToken
		token.AccessExpiry = time.Now().Unix() + int64(tokenResponse.ExpiresIn)
		err = a.tokenDB.UpdateToken(*token)
		if err != nil {
			return "", fmt.Errorf("failed to update token: %w", err)
		}
	}

	// Return access token
	return token.Access, nil
}
