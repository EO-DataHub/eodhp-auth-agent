package tokens

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/api/middleware"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type GetTokenResponse struct {
	ID     string `json:"id"`
	UserID string `json:"user"`
}

type CreateTokenResponse struct {
	GetTokenResponse `json:",inline"`
	Token            string `json:"token"`
}

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
		response := make([]GetTokenResponse, len(tokens))
		for i, token := range tokens {
			response[i] = GetTokenResponse{
				ID:     token.ID,
				UserID: token.UserID,
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

		// Get the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			logger.Debug().Msg("Authorization header missing")
			http.Error(w, "Authorization header missing",
				http.StatusUnauthorized)
			return
		}

		// Check the Authorization header format
		authToken := strings.TrimPrefix(authHeader, "Bearer ")
		if authToken == authHeader {
			logger.Error().Msg("Invalid authorization header")
			http.Error(w, "Invalid authorization header",
				http.StatusUnauthorized)
			return
		}

		// Get the offline token from the Keycloak client
		resp, err := auth.GetOfflineToken(authToken)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to get offline token")
			http.Error(w, "Failed to get offline token",
				http.StatusInternalServerError)
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
			Access: resp.AccessToken,
			AccessExpiry: time.Now().Add(time.Duration(resp.ExpiresIn) *
				time.Second).Unix(),
			Refresh: resp.RefreshToken,
		}
		if err = tokenDB.CreateToken(token); err != nil {
			logger.Error().Err(err).Msg("Failed to create token")
			http.Error(w, "Failed to create token",
				http.StatusInternalServerError)
			return
		}

		// Write the response
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(CreateTokenResponse{
			GetTokenResponse: GetTokenResponse{
				ID:     token.ID,
				UserID: token.UserID,
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
		json.NewEncoder(w).Encode(GetTokenResponse{
			ID:     token.ID,
			UserID: token.UserID,
		})
	}
}

func DeleteTokenHandler(tokenDB *db.TokenDB) http.HandlerFunc {
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

		// Delete the token from the database
		err := tokenDB.DeleteTokenByID(tokenID, userID)
		if err != nil {
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
