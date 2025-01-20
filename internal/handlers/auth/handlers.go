package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

func IntrospectAuthHandler(auth *keycloak.KeycloakClient) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "introspect auth").Logger()

		// Get the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			logger.Debug().Msg("authorization header missing")
			http.Error(w, "authorization header missing",
				http.StatusBadRequest)
			return
		}

		// Check the Authorization header format
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			logger.Error().Msg("invalid auth header format, should be bearer")
			http.Error(w, "invalid auth header format, should be bearer",
				http.StatusBadRequest)
			return
		}

		// Inspect the token
		claims, err := auth.IntrospectToken(token)
		if err != nil {
			logger.Error().Err(err).Msg("failed to introspect auth")
			http.Error(w, fmt.Errorf("failed to introspect auth: %w", err).Error(),
				http.StatusInternalServerError)
			return
		}

		// Write the response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(claims)
	}
}
