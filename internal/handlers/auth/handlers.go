package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/handlers/middleware"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/rs/zerolog"
)

type AuthProcessor interface {
	ProcessRequest(w http.ResponseWriter, req *http.Request) (bool, bool)
	IsHostAllowed(host string) bool
}

func AuthHandler(flows []AuthProcessor) http.HandlerFunc {

	return func(w http.ResponseWriter, req *http.Request) {
		logger := zerolog.Ctx(req.Context()).With().Str("original uri",
			req.Header.Get(OriginalURI)).Logger()

		logger.Debug().Msg("received request")

		var isAuthenticated, isAuthorized, hostAllowed bool
		for _, flow := range flows {
			if !flow.IsHostAllowed(req.Host) {
				continue
			}

			isAuthenticated, isAuthorized = flow.ProcessRequest(w, req)
			hostAllowed = true
			break
		}

		if !hostAllowed {
			logger.Warn().Msg("no auth flow matched the request")
		}

		// Handle authentication requests
		if isAuthorized {
			w.WriteHeader(http.StatusOK)
		} else if !isAuthenticated {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
		w.Write([]byte(fmt.Sprintf("Authenticated: %t, Authorized: %t",
			isAuthenticated, isAuthorized)))
	}
}

func InspectTokenHandler(auth *keycloak.KeycloakClient) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "inspect token").Logger()

		// Get the token from the context
		authToken := r.Context().Value(middleware.TokenKey).(string)

		// Inspect the token
		claims, err := auth.IntrospectToken(authToken)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to inspect token")
			http.Error(w, "Failed to inspect token", http.StatusUnauthorized)
			return
		}

		// Write the response
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(claims)
	}
}
