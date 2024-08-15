package auth

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

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
	client *http.Client
	tokens TokenExchanger
}

func NewAuthenticator(inputs AuthenticatorInputs,
	tokenClient TokenExchanger) *Authenticator {

	return &Authenticator{
		AuthenticatorInputs: inputs,
		client:              &http.Client{},
		tokens:              tokenClient,
	}
}

type TokenExchanger interface {
	GetJWTToken(apiToken string) (string, error)
}

type Claims struct {
	jwt.StandardClaims
	Username    string `json:"preferred_username"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// IsAuthenticated checks if the request is authenticated.
//
// A request can only be successfully authenticated if the host domain is
// allowed.
//
// Each authentication method is mutually exclusive. The order of precedence is
// as follows:
//  1. If the Authorization header contains an API Token, use that to exchange
//     for a Bearer token and attach the Bearer token to the
//     authorization request.
//  2. If the Authorization header contains a Bearer token, attach to the
//     authorization request.
//  3. If a session token cookie is present, attach to the request.
//
// If the request is authenticated, the claims are returned.
func (a *Authenticator) IsAuthenticated(r *http.Request) (bool, *Claims) {
	logger := zerolog.Ctx(r.Context()).With().
		Str("authenticator", a.Name).Str("host", r.Host).Logger()

	// Initialise an empty claims struct, this will be returned even in event
	// of an error
	claims := &Claims{}

	// Check the target domain of the request, deny if not allowed
	if isAllowed, err := a.isHostAllowed(r); err != nil {
		logger.Error().Err(err).Msg("Failed to check domain")
		return false, claims
	} else if !isAllowed {
		return false, claims
	}
	logger.Debug().Msg("Host allowed")

	// Create the authentication request
	authRequest, err := a.createAuthRequest(r)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create authentication request")
		return false, claims
	}
	logger.Debug().Msg("Authentication request created")

	// Send the authentication request
	resp, err := a.client.Do(authRequest)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to send authentication request")
		return false, claims
	}
	defer resp.Body.Close()
	logger.Debug().Msg("Authentication request sent")

	// Check the response status code is outwith the 2xx range
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Info().
			Int("status_code", resp.StatusCode).
			Msg("Cookie authentication request failed")
		return false, claims
	}
	logger.Info().
		Int("status_code", resp.StatusCode).
		Msg("Cookie authentication request succeeded")

	// Extract the JWT claims from the response
	claimsHeaderName := "X-Auth-Request-Access-Token"
	authHeader := resp.Header.Get(claimsHeaderName)
	if authHeader != "" {
		if _, err := jwt.ParseWithClaims(
			strings.TrimPrefix(authHeader, "Bearer "), claims, nil); err != nil {
			// Ignore validation errors (no need to check signing of key)
			if _, ok := err.(*jwt.ValidationError); !ok {
				logger.Warn().Str("claims header", claimsHeaderName).Err(err).
					Msg("Failed to decode bearer token")
			}
		}
	} else {
		logger.Warn().Str("claims header", claimsHeaderName).
			Msg("Header missing from response")
	}
	logger.Debug().Interface("claims", claims).Msg("Claims extracted")
	logger.Info().Str("username", claims.Username).Msg("User authenticated")

	return true, claims
}

func (a *Authenticator) isHostAllowed(r *http.Request) (bool, error) {
	logger := *zerolog.Ctx(r.Context())

	logger.Debug().Msg("Checking host domain")
	for _, pattern := range a.Domains {
		// Convert wildcard pattern to regular expression
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

		matched, err := regexp.MatchString(regexPattern, r.Host)
		if err != nil {
			logger.Error().Str("pattern", pattern).Err(err).
				Msg("Error checking host domain")
		}
		if matched {
			logger.Debug().Str("pattern", pattern).Msg("Host domain allowed")
			return true, nil
		}
	}

	logger.Debug().Strs("domains", a.Domains).Msg("Domain not allowed")
	return false, nil
}

func (a *Authenticator) createAuthRequest(r *http.Request) (*http.Request, error) {
	logger := zerolog.Ctx(r.Context())

	// Create a subrequest to authenticate via upstream service
	authRequest, err := http.NewRequestWithContext(
		r.Context(), "GET", a.AuthURL, nil)
	if err != nil {
		return nil, err
	}

	// Extract the auth header and attach to the auth request, if present
	token, err := a.getAuthorizationJWTToken(r)
	if err == nil {
		logger.Debug().Msg("JWT extracted from Authorization header")
		// Set the JWT token as a bearer token in Authorization header
		authRequest.Header.Set(
			"Authorization", fmt.Sprintf("Bearer %s", token))
	} else {
		logger.Debug().Err(err).
			Msg("Failed to extract JWT from Authorization header")
	}

	// Extract the session token cookie and attach to the auth request, if
	// present
	if a.CookieName != "" {
		cookie, err := r.Cookie(a.CookieName)
		if err == nil {
			logger.Debug().Msg("Session token found")
			// Attach the named session cookie to the auth request
			authRequest.AddCookie(cookie)
		} else {
			if err == http.ErrNoCookie {
				logger.Debug().Msg("No session token found")
			} else {
				logger.Debug().Msgf("Error reading cookie: %s", err.Error())
			}
		}
	}

	return authRequest, nil
}

func (a *Authenticator) getAuthorizationJWTToken(
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
	if _, err := parseJWTToken(token); err == nil {
		logger.Debug().Msg("Bearer token is JWT")
		// Return the JWT token from the Authorization header
		return token, nil
	}
	logger.Debug().
		Msg("Bearer token is not JWT, assuming it is API token")

	// Exchange API token for JWT token, return the JWT token if successful
	token, err := a.tokens.GetJWTToken(token)
	if err == nil {
		logger.Debug().Msg("API token exchanged for JWT token")
		// Return the JWT token exchanged from the API token
		return token, nil
	} else {
		logger.Debug().Err(err).Msg("Failed to exchange API token for JWT")
		return "", err
	}
}

func parseJWTToken(token string) (*Claims, error) {
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
