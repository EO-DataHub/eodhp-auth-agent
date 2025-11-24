package tokens

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	v1 "github.com/EO-DataHub/eodhp-auth-agent/api/v1"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/handlers/middleware"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// @Summary Get workspace user token
// @Description Get a workspace user token by ID. {user-id} can be set to "me" to use the token owner's user id.
// @Tags api-token workspace
// @Accept json
// @Produce json
// @Param workspace path string true "Workspace ID" example(my-workspace)
// @Param user-id path string true "User ID" example(me)
// @Param token-id path string true "Token ID" example(454f4448000000000000000000000000)
// @Success 200 {object} v1.GetTokenResponse
// @Failure 400 {object} string
// @Failure 401 {object} string
// @Failure 500 {object} string
// @Router /workspaces/{workspace}/{user-id}/tokens/{token-id} [get]
func GetTokenHandler(tokenDB *db.TokenDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "get token").Logger()

		// Read path params
		vars := mux.Vars(r)
		workspace := vars["workspace"]
		userID := vars["user-id"]
		tokenID := vars["token-id"]

		// Get the token from the database
		token, err := tokenDB.GetUserToken(tokenID, workspace, userID)
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
			ID:        token.ID,
			UserID:    token.UserID,
			Name:      token.Name,
			Workspace: token.Workspace,
			Scope:     token.Scope,
			Expiry:    time.Unix(token.Expires, 0).Format(time.RFC3339),
			Created:   time.Unix(token.Created, 0).Format(time.RFC3339),
		})
	}
}

// @Summary Get workspace user tokens
// @Description Get workspace user tokens. {user-id} can be set to "me" to use the token owner's user id.
// @Tags api-token workspace
// @Accept json
// @Produce json
// @Param workspace path string true "Workspace ID" example(my-workspace)
// @Param user-id path string true "User ID" example(me)
// @Success 200 {array} v1.GetTokenResponse
// @Failure 400 {object} string
// @Failure 401 {object} string
// @Failure 500 {object} string
// @Router /workspaces/{workspace}/{user-id}/tokens [get]
func ListTokensHandler(tokenDB *db.TokenDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "list tokens").Logger()

		// Read path params
		vars := mux.Vars(r)
		workspace := vars["workspace"]
		userID := vars["user-id"]

		// List the tokens for the user
		tokens, err := tokenDB.ListUserTokens(workspace, userID)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to list tokens")
			http.Error(w, "Failed to list tokens",
				http.StatusInternalServerError)
			return
		}

		// Write the response
		w.WriteHeader(http.StatusOK)
		response := make([]v1.GetTokenResponse, 0, len(tokens))
		for _, token := range tokens {
			response = append(response, v1.GetTokenResponse{
				ID:        token.ID,
				UserID:    token.UserID,
				Name:      token.Name,
				Workspace: token.Workspace,
				Scope:     token.Scope,
				Expiry:    time.Unix(token.Expires, 0).Format(time.RFC3339),
				Created:   time.Unix(token.Created, 0).Format(time.RFC3339),
			})
		}
		json.NewEncoder(w).Encode(response)
	}
}

// @Summary Create workspace user tokens
// @Description Create workspace a user token. {user-id} can be set to "me" to use the token owner's user id.
// @Tags api-token workspace
// @Accept json
// @Produce json
// @Param workspace path string true "Workspace ID" example(my-workspace)
// @Param user-id path string true "User ID" example(me)
// @Success 201 {object} v1.CreateTokenResponse
// @Failure 400 {object} string
// @Failure 401 {object} string
// @Failure 500 {object} string
// @Router /workspaces/{workspace}/{user-id}/tokens [post]
func CreateTokenHandler(tokenDB *db.TokenDB, auth *keycloak.KeycloakClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "create token").Logger()

		// Read path params
		vars := mux.Vars(r)
		workspace := vars["workspace"]
		userID := vars["user-id"]

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
		scope := fmt.Sprintf("offline_access workspace:%s", workspace)
		resp, err := auth.ExchangeToken(authToken, scope, true)
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
			ID:        uuid.New().String(),
			Token:     apiToken,
			Name:      req.Name,
			Workspace: workspace,
			UserID:    userID,
			Scope:     scope,
			Access:    resp.Access,
			AccessExpiry: time.Now().Add(time.Duration(resp.ExpiresIn) *
				time.Second).Unix(),
			Refresh: resp.Refresh,
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
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(v1.CreateTokenResponse{
			GetTokenResponse: v1.GetTokenResponse{
				ID:        token.ID,
				UserID:    token.UserID,
				Name:      token.Name,
				Workspace: token.Workspace,
				Scope:     token.Scope,
				Expiry:    time.Unix(token.Expires, 0).Format(time.RFC3339),
				Created:   time.Unix(token.Created, 0).Format(time.RFC3339),
			},
			Token: token.Token,
		})
	}
}

// @Summary Delete workspace user token
// @Description Delete a workspace user token by ID. {user-id} can be set to "me" to use the token owner's user id.
// @Tags api-token workspace
// @Accept json
// @Produce json
// @Param workspace path string true "Workspace ID" example(my-workspace)
// @Param user-id path string true "User ID" example(me)
// @Param token-id path string true "Token ID" example(454f4448000000000000000000000000)
// @Success 204 "No Content"
// @Failure 400 {object} string
// @Failure 401 {object} string
// @Failure 500 {object} string
// @Router /workspaces/{workspace}/{user-id}/tokens/{token-id} [delete]
func DeleteTokenHandler(tokenDB *db.TokenDB, auth *keycloak.KeycloakClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "delete token").Logger()

		// Read path params
		vars := mux.Vars(r)
		workspace := vars["workspace"]
		userID := vars["user-id"]
		tokenID := vars["token-id"]

		// Revoke the token in Keycloak
		token, err := tokenDB.GetUserToken(tokenID, workspace, userID)
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
		if err := tokenDB.DeleteTokenByID(tokenID); err != nil {
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
