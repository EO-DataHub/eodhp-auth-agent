package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type contextKey string

const ClaimsKey contextKey = "claims"

func JWTMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "jwt middleware").Logger()

		// Get the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			logger.Debug().Msg("Authorization header missing")
			http.Error(w, "Authorization header missing",
				http.StatusUnauthorized)
			return
		}

		// Check the Authorization header format
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			logger.Error().Msg("Invalid token format")
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		// Parse the token for JWT claims
		claims, err := authn.ParseJWTToken(token)
		if err != nil {
			logger.Error().Err(err).Msg("Invalid token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add the claims to the context
		ctx := context.WithValue(r.Context(), ClaimsKey, *claims)
		logger.Info().Str("user", claims.Username).Msg("Token verified")
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// Middleware to add additional context to each request
func WithLogger(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := log.With().
			Str("method", r.Method).
			Str("url", r.URL.String()).
			Str("remote_addr", r.RemoteAddr).
			Time("timestamp", time.Now()).
			Logger()
		ctx := logger.WithContext(r.Context())
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
