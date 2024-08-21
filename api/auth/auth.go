package auth

import (
	"fmt"
	"net/http"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authz"
	"github.com/rs/zerolog"
)

type Authenticator interface {
	GetAuthenticatedClaims(r *http.Request) (*authn.Claims, error)
}
type Authorizer interface {
	IsAuthorized(r *http.Request, body authz.OPARequestBody) (bool, error)
}

func AuthHandler(authenticators []Authenticator,
	authorizer Authorizer) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().Logger()

		// Initialise authentication variables
		isAuthenticated := false
		claims := &authn.Claims{}

		// Loop through the authenticators in order and break on the first
		// to pass authentication, returning the claims from that authenticator
		for _, authenticator := range authenticators {
			c, err := authenticator.GetAuthenticatedClaims(r)
			if err != nil {
				continue
			}

			// If err is nil, the request is authenticated
			isAuthenticated = true
			claims = c
			break
		}
		if isAuthenticated {
			logger = logger.With().Str("user", claims.Username).Logger()
			logger.Info().Msg("request authenticated")
		} else {
			logger.Info().Msg("request not authenticated")
		}

		// Use the claims from the authenticated request to check authorization
		isAuthorized, err := authorizer.IsAuthorized(r, authz.OPARequestBody{
			Input: authz.OPARequestBodyInput{
				Username: claims.Username,
				Roles:    claims.RealmAccess.Roles,
				Path:     r.URL.Path,
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
			logger.Info().Msg("request authorized")
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
