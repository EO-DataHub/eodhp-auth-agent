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
	IsAuthenticated(r *http.Request) (bool, *http.Response, error)
}
type Authorizer interface {
	IsAuthorized(r *http.Request, body authz.OPARequestBody) (bool, error)
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
		claims := authn.Claims{}
		for _, authenticator := range authenticators {
			authenticated, resp, _ := authenticator.IsAuthenticated(req)
			if !authenticated {
				continue
			}

			isAuthenticated = true
			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			for key, values := range resp.Header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			var err error
			claims, err = authn.ParseClaims(resp.Header.Get("Authorization"))
			if err != nil {
				logger.Error().Str("header", "Authorization").Err(err).
					Msg("failed to parse claims")
			}
			break
		}
		if isAuthenticated {
			logger = logger.With().Str("user", claims.Username).Logger()
			logger.Info().Msg("request authenticated")
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
