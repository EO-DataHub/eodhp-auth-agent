package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authz"
	"github.com/rs/zerolog"
)

const OriginalURI string = "X-Original-URI"

type Authenticator interface {
	IsAuthenticated(w http.ResponseWriter, req *http.Request) (bool, error)
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
		for _, authenticator := range authenticators {
			authenticated, _ := authenticator.IsAuthenticated(w, req)
			if authenticated {
				isAuthenticated = true
				break
			}
		}

		// If the request is authenticated, parse the claims from the
		// Authorization header
		claims := authn.Claims{}
		if isAuthenticated {
			logger.Info().Msg("request authenticated")
			var err error
			logger.Debug().Str("authorization", w.Header().Get("Authorization")).
				Msg("authorization header") // TODO: remove
			claims, err = authn.ParseClaims(strings.TrimPrefix(
				w.Header().Get("Authorization"), "Bearer "))
			if err != nil {
				logger.Warn().Err(err).Msg("failed to parse claims")
			} else {
				logger.Debug().Interface("claims", claims).Msg("parsed claims")
			}
		} else {
			logger.Info().Msg("request not authenticated")
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
