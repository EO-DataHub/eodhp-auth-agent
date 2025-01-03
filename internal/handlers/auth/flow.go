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

type AuthFlowInputs struct {
	Name              string   `yaml:"name"`
	Domains           []string `yaml:"domains"`
	AuthenticationURL string   `yaml:"authentication_url"`
	AuthorizationURL  string   `yaml:"authorization_url"`
}

type Authenticator interface {
	IsAuthenticated(w http.ResponseWriter, req *http.Request) (bool,
		authn.Claims, error)
}
type Authorizer interface {
	IsAuthorized(req *http.Request, body authz.OPARequestBody) (bool, error)
}

type AuthFlow struct {
	AuthFlowInputs
	hostPatterns []regexp.Regexp
	authn        Authenticator
	authz        Authorizer
}

func NewAuthFlow(inputs AuthFlowInputs, tokenDB authn.TokenDB,
	auth authn.AuthClient) (*AuthFlow, error) {

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
	}

	return &AuthFlow{
		AuthFlowInputs: inputs,
		hostPatterns:   compileGlobPatterns(inputs.Domains),
		authn:          authenticator,
		authz:          authorizer,
	}, nil
}

func (a AuthFlow) ProcessRequest(w http.ResponseWriter, req *http.Request) (
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
			Username: claims.Username,
			Host:     host,
			Path:     req.Header.Get(OriginalURI),
			Roles:    claims.RealmAccess.Roles,
			Method:   req.Method,
		},
	})
	if err != nil {
		logger.Error().Err(err).Msg("authorization failed")
	}

	return isAuthenticated, isAuthorized
}

func (a AuthFlow) IsHostAllowed(host string) bool {
	for _, pattern := range a.hostPatterns {
		matched := pattern.Match([]byte(host))
		if matched {
			return true
		}
	}
	return false
}
