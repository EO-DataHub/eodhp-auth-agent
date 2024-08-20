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
	UpdateToken(token db.Token) error
}

type AuthClient interface {
	RefreshToken(refreshToken string) (*keycloak.TokenResponse, error)
}

var ErrInvalidHost = errors.New("authn: invalid host")
var ErrAuthFailed = errors.New("authn: authentication failed")
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

// GetAuthenticatedClaims checks if the request is authenticated.
//
// A request can only be successfully authenticated if an authenticator for the
// request host domain is present. The authenticator will attempt authentication
// as follows:
//
//  1. If the Authorization header contains a Bearer access token, attach to the
//     authorization request.
//  2. Else if the Authorization header contains an API Token, use that to
//     exchange for a Bearer token and attach the Bearer access token to the
//     authorization request.
//  3. If a session token cookie is present, attach to the request.
//
// If the request is authenticated, the claims are returned.
func (a Authenticator) GetAuthenticatedClaims(r *http.Request) (*Claims, error) {
	logger := zerolog.Ctx(r.Context()).With().
		Str("authenticator", a.Name).Str("host", r.Host).Logger()

	// Check the target domain of the request, deny if not allowed
	if isAllowed, err := a.isHostAllowed(r); err != nil {
		logger.Error().Err(err).Msg("failed to check domain")
		return nil, err
	} else if !isAllowed {
		return nil, ErrInvalidHost
	}
	logger.Debug().Msg("host allowed")

	// Create the authentication request
	authRequest, err := a.createAuthRequest(r)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create authentication request")
		return nil, err
	}
	logger.Debug().Msg("authentication request created")

	// Send the authentication request
	resp, err := a.http.Do(authRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to send authentication request")
		return nil, err
	}
	defer resp.Body.Close()
	logger.Debug().Msg("authentication request sent")

	// Check the response status code is outwith the 2xx range
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Info().
			Int("status_code", resp.StatusCode).
			Msg("authentication request failed")
		return nil, ErrAuthFailed
	}
	logger.Info().
		Int("status_code", resp.StatusCode).
		Msg("authentication request succeeded")

	// Extract the JWT claims from the response
	claimsHeaderName := "X-Auth-Request-Access-Token"
	authHeader := resp.Header.Get(claimsHeaderName)
	if authHeader == "" {
		logger.Error().Str("claims header", claimsHeaderName).
			Err(ErrMissingAuthResponseClaims)
		return nil, ErrMissingAuthResponseClaims
	}

	claims, err := ParseJWTToken(
		strings.TrimPrefix(authHeader, "Bearer "))
	if err != nil {
		logger.Error().Err(err).Str("claims header", claimsHeaderName).
			Msg("failed to extract claims from auth response")
		return nil, err
	}

	logger.Debug().Interface("claims", claims).Msg("claims extracted")
	logger.Info().Str("username", claims.Username).Msg("user authenticated")

	return claims, nil
}

func (a Authenticator) isHostAllowed(r *http.Request) (bool, error) {
	logger := *zerolog.Ctx(r.Context())

	logger.Debug().Msg("checking host domain")
	for _, pattern := range a.Domains {
		// Convert wildcard pattern to regular expression
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

		matched, err := regexp.MatchString(regexPattern, r.Host)
		if err != nil {
			logger.Error().Str("pattern", pattern).Err(err).
				Msg("error checking host domain")
		}
		if matched {
			logger.Debug().Str("pattern", pattern).Msg("host domain allowed")
			return true, nil
		}
	}

	logger.Debug().Strs("domains", a.Domains).Msg("domain not allowed")
	return false, nil
}

func (a Authenticator) createAuthRequest(r *http.Request) (*http.Request, error) {
	logger := zerolog.Ctx(r.Context())

	// Create a subrequest to authenticate via upstream service
	authRequest, err := http.NewRequestWithContext(
		r.Context(), "GET", a.AuthURL, nil)
	if err != nil {
		return nil, err
	}

	// Extract the auth header and attach to the auth request, if present
	token, err := a.getJWTToken(r)
	if err == nil {
		logger.Debug().Msg("jwt extracted from authorization header")
		// Set the JWT token as a bearer token in Authorization header
		authRequest.Header.Set(
			"Authorization", fmt.Sprintf("Bearer %s", token))
	} else {
		logger.Debug().Err(err).
			Msg("failed to extract jwt from authorization header")
	}

	// Extract the session token cookie and attach to the auth request, if
	// present
	if a.CookieName != "" {
		cookie, err := r.Cookie(a.CookieName)
		if err == nil {
			logger.Debug().Msg("session token found")
			// Attach the named session cookie to the auth request
			authRequest.AddCookie(cookie)
		} else {
			if err == http.ErrNoCookie {
				logger.Debug().Msg("no session token found")
			} else {
				logger.Debug().Msgf("error reading cookie: %s", err.Error())
			}
		}
	}

	return authRequest, nil
}

func (a Authenticator) getJWTToken(
	r *http.Request) (string, error) {

	logger := zerolog.Ctx(r.Context())

	// Check if Authorization header is present
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("no authorization header")
		logger.Debug().Err(err)
		return "", err
	}

	// Check if Authorization header is Bearer token
	if !strings.HasPrefix(authHeader, "Bearer ") {
		err := errors.New(
			"invalid authorization header, should be bearer token")
		logger.Debug().Err(err)
		return "", err
	}

	// Check if Bearer token is JWT, return it as is if so
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if _, err := ParseJWTToken(token); err == nil {
		logger.Debug().Msg("bearer token is jwt")
		// Return the JWT token from the Authorization header
		return token, nil
	}
	logger.Debug().
		Msg("bearer token is not jwt, assuming it is api token")

	// Exchange API token for JWT token, return the JWT token if successful
	token, err := a.exchangeAPIToken(token)
	if err == nil {
		logger.Debug().Msg("api token exchanged for jwt token")
		// Return the JWT token exchanged from the API token
		return token, nil
	} else {
		logger.Debug().Err(err).
			Msg("failed to exchange api token for jwt token")
		return "", err
	}
}

func (a *Authenticator) exchangeAPIToken(apiToken string) (string, error) {
	// Get token from DB
	token, err := a.tokenDB.GetTokenByAPIToken(apiToken)
	if err != nil {
		return "", err
	}

	// Check token access expiry
	if token.IsValid() {
		// Refresh token if access has expired
		tokenResponse, err := a.auth.RefreshToken(token.Refresh)
		if err != nil {
			return "", err
		}

		// Update DB with new access token
		token.Access = tokenResponse.AccessToken
		token.Refresh = tokenResponse.RefreshToken
		token.AccessExpiry = time.Now().Unix() + int64(tokenResponse.ExpiresIn)
		err = a.tokenDB.UpdateToken(*token)
		if err != nil {
			return "", err
		}
	}

	// Return access token
	return token.Access, nil
}

func ParseJWTToken(token string) (*Claims, error) {
	claims := &Claims{}
	// Check if token is JWT by attempting to parse it
	if t, err := jwt.ParseWithClaims(token, claims, nil); err != nil {
		// Ignore validation errors (no need to check signing of key)
		if _, ok := err.(*jwt.ValidationError); !ok {
			return nil, err
		}

		// Check if token was decoded successfully
		if t == nil {
			// Return an error if the token was not decoded successfully
			return nil, errors.New("invalid jwt token")
		}
	}
	return claims, nil
}
