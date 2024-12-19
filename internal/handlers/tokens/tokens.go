package tokens

import (
	"encoding/json"
	"net/http"
	"time"

	v1 "github.com/EO-DataHub/eodhp-auth-agent/api/v1"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/handlers/middleware"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

func ListTokensHandler(tokenDB *db.TokenDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "list tokens").Logger()

		// Get the user ID from the claims
		claims, ok := r.Context().Value(middleware.ClaimsKey).(authn.Claims)
		if !ok {
			logger.Error().Msg("No claims found in context")
			http.Error(w, "No claims found in context", http.StatusUnauthorized)
			return
		}
		userID := claims.Subject
		if userID == "" {
			logger.Error().Msg("No user ID in claims")
			http.Error(w, "No user ID in claims", http.StatusUnauthorized)
			return
		}

		// List the tokens for the user
		tokens, err := tokenDB.ListUserTokens(userID)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to list tokens")
			http.Error(w, "Failed to list tokens",
				http.StatusInternalServerError)
			return
		}

		// Write the response
		w.WriteHeader(http.StatusOK)
		response := make([]v1.GetTokenResponse, len(tokens))
		for i, token := range tokens {
			response[i] = v1.GetTokenResponse{
				ID:      token.ID,
				UserID:  token.UserID,
				Name:    token.Name,
				Scope:   token.Scope,
				Expiry:  time.Unix(token.Expires, 0).Format(time.RFC3339),
				Created: time.Unix(token.Created, 0).Format(time.RFC3339),
			}
		}
		json.NewEncoder(w).Encode(response)
	}
}

func CreateTokenHandler(tokenDB *db.TokenDB, auth *keycloak.KeycloakClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "create token").Logger()

		// Get the user ID from the claims
		claims := r.Context().Value(middleware.ClaimsKey).(authn.Claims)
		if claims.Subject == "" {
			logger.Error().Msg("No user ID in claims")
			http.Error(w, "No user ID in claims", http.StatusUnauthorized)
			return
		}

		// Get the token from the context
		authToken := r.Context().Value(middleware.TokenKey).(string)

		// Get the scope from the payload
		req := v1.CreateTokenRequest{
			Expires: 30, // default expiry time is 30 days
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Error().Err(err).Msg("Failed to decode request")
			http.Error(w, "Failed to decode request",
				http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			logger.Error().Msg("Name is required")
			http.Error(w, "Name is required", http.StatusBadRequest)
			return
		}
		if req.Expires > 30 {
			logger.Error().Msg("Expiry time is too long")
			http.Error(w, "Expiry time exceeds 30 day maximum",
				http.StatusBadRequest)
			return
		}

		// Get the offline token from the Keycloak client
		resp, err := auth.ExchangeToken(authToken, req.Scope)
		if err != nil {
			var errStatus int
			if err, ok := err.(*keycloak.HTTPError); ok {
				errStatus = err.Status
			} else {
				errStatus = http.StatusInternalServerError
			}
			logger.Error().Err(err).Msg("Failed to get offline token")
			http.Error(w, err.Error(), errStatus)
			return
		}

		// Generate API token
		apiToken, err := tokenDB.GenerateAPIToken()
		if err != nil {
			logger.Error().Err(err).Msg("Failed to generate API token")
			http.Error(w, "Failed to generate API token",
				http.StatusInternalServerError)
			return
		}

		// Create the token and save to the database
		token := db.Token{
			ID:     uuid.New().String(),
			Token:  apiToken,
			UserID: claims.Subject,
			Access: resp.Access,
			AccessExpiry: time.Now().Add(time.Duration(resp.ExpiresIn) *
				time.Second).Unix(),
			Refresh: resp.Refresh,
			Name:    req.Name,
			Scope:   req.Scope,
			Expires: time.Now().Add(time.Duration(req.Expires) *
				time.Hour * 24).Unix(), // Now + d days
			Created: time.Now().Unix(),
		}
		if err = tokenDB.CreateToken(token); err != nil {
			logger.Error().Err(err).Msg("Failed to create token")
			http.Error(w, "Failed to create token",
				http.StatusInternalServerError)
			return
		}

		// Write the response
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(v1.CreateTokenResponse{
			GetTokenResponse: v1.GetTokenResponse{
				ID:      token.ID,
				UserID:  token.UserID,
				Name:    token.Name,
				Scope:   token.Scope,
				Expiry:  time.Unix(token.Expires, 0).Format(time.RFC3339),
				Created: time.Unix(token.Created, 0).Format(time.RFC3339),
			},
			Token: token.Token,
		})
	}
}

func GetTokenHandler(tokenDB *db.TokenDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "get token").Logger()

		// Get the token ID from the request URL
		tokenID := mux.Vars(r)["token_id"]

		// Get the user ID from the claims
		claims, ok := r.Context().Value(middleware.ClaimsKey).(authn.Claims)
		if !ok {
			logger.Error().Msg("No claims found in context")
			http.Error(w, "No claims found in context", http.StatusUnauthorized)
			return
		}
		userID := claims.Subject
		if userID == "" {
			logger.Error().Msg("No user ID in claims")
			http.Error(w, "No user ID in claims", http.StatusUnauthorized)
			return
		}

		// Get the token from the database
		token, err := tokenDB.GetTokenByID(tokenID, userID)
		if err != nil {
			if err == db.ErrNotFound {
				logger.Error().Err(err).Msg("Token not found")
				http.Error(w, "Token not found", http.StatusNotFound)
				return
			}
			logger.Error().Err(err).Msg("Failed to get token")
			http.Error(w, "Failed to get token", http.StatusInternalServerError)
			return
		}

		// Write the response
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(v1.GetTokenResponse{
			ID:      token.ID,
			UserID:  token.UserID,
			Name:    token.Name,
			Scope:   token.Scope,
			Expiry:  time.Unix(token.Expires, 0).Format(time.RFC3339),
			Created: time.Unix(token.Created, 0).Format(time.RFC3339),
		})
	}
}

func DeleteTokenHandler(tokenDB *db.TokenDB, auth *keycloak.KeycloakClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "delete token").Logger()

		// Get the token ID from the request URL
		tokenID := mux.Vars(r)["token_id"]

		// Get the user ID from the claims
		claims, ok := r.Context().Value(middleware.ClaimsKey).(authn.Claims)
		if !ok {
			logger.Error().Msg("No claims found in context")
			http.Error(w, "No claims found in context", http.StatusUnauthorized)
			return
		}
		userID := claims.Subject
		if userID == "" {
			logger.Error().Msg("No user ID in claims")
			http.Error(w, "No user ID in claims", http.StatusUnauthorized)
			return
		}

		// Revoke the token in Keycloak
		token, err := tokenDB.GetTokenByID(tokenID, userID)
		if err != nil {
			if err == db.ErrNotFound {
				logger.Error().Err(err).Msg("Token not found")
				http.Error(w, "Token not found", http.StatusNotFound)
				return
			}
			logger.Error().Err(err).Msg("Failed to get token")
			http.Error(w, "Failed to get token", http.StatusInternalServerError)
			return
		}
		if err := auth.RevokeToken(token.Refresh); err != nil {
			logger.Error().Err(err).Msg("Failed to revoke token")
			http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
			return
		}

		// Delete the token from the database
		if err := tokenDB.DeleteTokenByID(tokenID, userID); err != nil {
			if err == db.ErrNotFound {
				logger.Error().Err(err).Msg("Token not found")
				http.Error(w, "Token not found", http.StatusNotFound)
				return
			}
			logger.Error().Err(err).Msg("Failed to delete token")
			http.Error(w, "Failed to delete token",
				http.StatusInternalServerError)
			return
		}

		// Write the response
		w.WriteHeader(http.StatusNoContent)
	}
}
