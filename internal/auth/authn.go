package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/rs/zerolog"
)

type AuthenticatorInputs struct {
	Name           string   `yaml:"name"`
	AuthURL        string   `yaml:"auth_url"`
	AuthMethod     string   `yaml:"auth_method"`
	CookieName     string   `yaml:"cookie_name"`
	AllowedOrigins []string `yaml:"allowed_origins"`
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
	exchangeTokenForBearer(token string) (string, error)
}

type Claims struct {
	jwt.StandardClaims
	Username    string `json:"preferred_username"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// IsAuthenticated checks if the request is authenticated. Each authentication
// method is mutually exclusive. The order of precedence is as follows:
//  1. If the Authorization header contains an API Token, use that to exchange
//     for a Bearer token and attach the Bearer token to the
//     authorization request.
//  2. If the Authorization header contains a Bearer token, attach to the
//     authorization request.
//  3. If a session token cookie is present, attach to the request.
func (a *Authenticator) IsAuthenticated(r *http.Request) (bool, *Claims) {
	logger := zerolog.Ctx(r.Context()).With().
		Str("authenticator", a.Name).Logger()

	// Initialise an empty claims struct, this will be returned even in event
	// of an error
	claims := &Claims{}

	// Check the origin is allowed
	if isAllowed, err := a.isOriginAllowed(r); err != nil {
		logger.Error().Err(err).Msg("Failed to check origin")
		return false, claims
	} else if !isAllowed {
		logger.Debug().Strs("allowed_origins", a.AllowedOrigins).
			Msg("Origin not allowed")
		return false, claims
	}
	logger.Debug().Str("origin", r.Header.Get("Origin")).Msg("Origin allowed")

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
				logger.Warn().Err(err).Msg("Failed to decode bearer token")
			}
		}
	} else {
		logger.Warn().Msgf("'%s' header missing from auth response",
			claimsHeaderName)
	}
	logger.Debug().Interface("claims", claims).Msg("Claims extracted")
	logger.Info().Str("username", claims.Username).Msg("User authenticated")

	return true, claims
}

func (a *Authenticator) isOriginAllowed(r *http.Request) (bool, error) {
	logger := *zerolog.Ctx(r.Context())

	origin := r.Header.Get("Origin")
	parsedURL, err := url.Parse(origin)
	if err != nil {
		logger.Error().Err(err).Str("origin", origin).
			Msg("Failed to parse origin")
		return false, err
	}
	host := parsedURL.Hostname()

	logger = logger.With().Str("host", host).Logger()
	logger.Debug().Msg("Checking origin")

	for _, pattern := range a.AllowedOrigins {
		// Convert wildcard pattern to regular expression
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

		matched, err := regexp.MatchString(regexPattern, host)
		if err != nil {
			logger.Error().Str("pattern", pattern).Err(err).
				Msg("Error checking origin")
		}
		if matched {
			logger.Debug().Str("pattern", pattern).Msg("Origin allowed")
			return true, nil
		}
	}

	logger.Debug().Strs("allowed_origins", a.AllowedOrigins).
		Msg("Origin not allowed")
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

	// Extract the auth header
	authHeader := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(authHeader, "Token "):
		logger.Debug().Msg("API Token found in Authorization header")
		token := strings.TrimPrefix(authHeader, "Token ")
		bearer, err := a.tokens.exchangeTokenForBearer(token)
		if err != nil {
			logger.Warn().Err(err).Msgf(
				"Failed to exchange API token for bearer token")
			break
		}
		logger.Debug().Msg("API token exchnaged for bearer token")
		// Attach the bearer token to the auth request
		authRequest.Header.Set(
			"Authorization", fmt.Sprintf("Bearer %s", bearer))
	case strings.HasPrefix(authHeader, "Bearer "):
		logger.Debug().Msg("Bearer found in Authorization header")
		// Attach the bearer token to the auth request
		authRequest.Header.Set("Authorization", authHeader)
	case a.CookieName != "":
		cookie, err := r.Cookie(a.CookieName)
		if err != nil {
			if err == http.ErrNoCookie {
				logger.Debug().Msg("No session token found")
			} else {
				logger.Debug().Msgf("Error reading cookie: %s", err.Error())
			}
			break
		}
		logger.Debug().Msg("Session token found")
		// Attach the named session cookie to the auth request
		authRequest.AddCookie(cookie)
	}

	return authRequest, nil
}
