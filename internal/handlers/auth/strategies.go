package auth

import (
	"net/http"
	"regexp"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authz"
	"github.com/rs/zerolog"
)

const OriginalHost = "X-Original-Host"
const OriginalURI = "X-Original-URI"
const OriginalMethod = "X-Original-Method"

type AuthStrategyInputs struct {
	Name                    string   `yaml:"name"`
	Domains                 []string `yaml:"domains"`
	AuthenticationURL       string   `yaml:"authentication_url"`
	AuthorizationURL        string   `yaml:"authorization_url"`
	AccessTokenExpiryMargin int16    `yaml:"access_token_expiry_margin"`
}

type Authenticator interface {
	IsAuthenticated(w http.ResponseWriter, req *http.Request) (bool,
		authn.Claims, error)
}
type Authorizer interface {
	IsAuthorized(req *http.Request, body authz.OPARequestBody) (bool, error)
}

type AuthStrategy struct {
	AuthStrategyInputs
	hostPatterns []regexp.Regexp
	authn        Authenticator
	authz        Authorizer
}

func NewAuthStrategy(inputs AuthStrategyInputs, tokenDB authn.TokenDB,
	auth authn.AuthClient) (*AuthStrategy, error) {

	var err error

	// Create the authenticator
	var authenticator Authenticator
	if inputs.AuthenticationURL != "" {
		authenticator, err = authn.NewAuthenticator(authn.AuthenticatorInputs{
			Name:    inputs.Name,
			AuthURL: inputs.AuthenticationURL,
		}, tokenDB, auth)
		if err != nil {
			return nil, err
		}
	}

	// Create the authorizer
	var authorizer Authorizer
	if inputs.AuthorizationURL != "" {
		authorizer = authz.NewAuthorizer(authz.AuthorizerInputs{
			Name:         inputs.Name,
			OPAClientURL: inputs.AuthorizationURL,
		})
	} else {
		authorizer = NullAuthZ{
			Name: inputs.Name,
		}
	}

	return &AuthStrategy{
		AuthStrategyInputs: inputs,
		hostPatterns:       compileGlobPatterns(inputs.Domains),
		authn:              authenticator,
		authz:              authorizer,
	}, nil
}

func (a AuthStrategy) ProcessRequest(w http.ResponseWriter, req *http.Request) (
	bool, bool) {

	logger := zerolog.Ctx(req.Context())

	// Check authentication, returning claims if authenticated
	isAuthenticated, claims, err := a.authn.IsAuthenticated(w, req)
	if err != nil {
		logger.Error().Err(err).Msg("authentication failed")
	}

	// Use the claims from the authenticated request to check authorization
	host := req.Header.Get(OriginalHost)
	if host == "" {
		logger.Debug().Msgf("authz: %s header empty, using Host header as fallback",
			OriginalHost)
		host = req.Host
	}

	isAuthorized, err := a.authz.IsAuthorized(req, authz.OPARequestBody{
		Input: authz.OPARequestBodyInput{
			Authenticated: isAuthenticated,
			Host:          host,
			Path:          req.Header.Get(OriginalURI),
			Method:        req.Header.Get(OriginalMethod),
			Claims:        claims,
		},
	})
	if err != nil {
		logger.Error().Err(err).Msg("authorization failed")
	}

	return isAuthenticated, isAuthorized
}

func (a AuthStrategy) IsHostAllowed(host string) bool {
	for _, pattern := range a.hostPatterns {
		matched := pattern.Match([]byte(host))
		if matched {
			return true
		}
	}
	return false
}

type NullAuthZ struct {
	Name string
}

func (a NullAuthZ) IsAuthorized(r *http.Request, body authz.OPARequestBody) (
	bool, error) {

	logger := zerolog.Ctx(r.Context()).With().Str("authorizer", a.Name).Logger()
	result := true
	logger.Debug().Interface("authz request", body).Bool("result",
		result).Msg("authorization response received")
	return result, nil
}
