package auth

import (
	"fmt"
	"net/http"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authz"
	"github.com/rs/zerolog"
)

const OriginalURI string = "X-Original-URI"

type Authenticator interface {
	IsAuthenticated(w http.ResponseWriter, req *http.Request) (bool,
		*authn.Claims, error)
}
type Authorizer interface {
	IsAuthorized(req *http.Request, body authz.OPARequestBody) (bool, error)
}

func AuthHandler(authenticators []Authenticator,
	authorizer Authorizer) http.HandlerFunc {

	return func(w http.ResponseWriter, req *http.Request) {
		originalURI := req.Header.Get(OriginalURI)

		logger := zerolog.Ctx(req.Context()).With().Str("original_uri",
			originalURI).Logger()

		// Loop through the authenticators in order and break on the first
		// to pass authentication, returning the claims from that authenticator
		isAuthenticated := false
		var claims authn.Claims
		for _, authenticator := range authenticators {
			authenticated, claims_, _ := authenticator.IsAuthenticated(w, req)
			if authenticated {
				logger.Info().Msg("request authenticated")
				isAuthenticated = true
				claims = *claims_
				break
			}
		}

		// Use the claims from the authenticated request to check authorization
		isAuthorized, err := authorizer.IsAuthorized(req, authz.OPARequestBody{
			Input: authz.OPARequestBodyInput{
				Username: claims.Username,
				Roles:    claims.RealmAccess.Roles,
				Path:     originalURI,
			},
		})
		if err != nil {
			logger.Error().Err(err).Msg("authorization failed")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))
			return
		}

		// Handle authentication requests
		if isAuthorized {
			logger.Info().Msg("request is authorized")
			w.WriteHeader(http.StatusOK)
		} else if !isAuthenticated {
			logger.Info().Msg("request requires authentication")
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			logger.Info().Msg("request authorization failed")
			w.WriteHeader(http.StatusForbidden)
		}
		w.Write([]byte(fmt.Sprintf("Authenticated: %t, Authorized: %t",
			isAuthenticated, isAuthorized)))
	}
}
