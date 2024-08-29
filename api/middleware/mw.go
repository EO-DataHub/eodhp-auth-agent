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
type tokenKey string

const ClaimsKey contextKey = "claims"
const TokenKey tokenKey = "token"

func JWTMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "jwt middleware").Logger()

		// Get the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			logger.Debug().Msg("authorization header missing")
			http.Error(w, "authorization header missing",
				http.StatusUnauthorized)
			return
		}

		// Check the Authorization header format
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			logger.Error().Msg("invalid token format")
			http.Error(w, "invalid token format", http.StatusUnauthorized)
			return
		}

		// Parse the token for JWT claims
		claims, err := authn.ParseClaims(token)
		if err != nil {
			logger.Error().Err(err).Msg("invalid bearer jwt token")
			http.Error(w, "invalid bearer jwt token", http.StatusUnauthorized)
			return
		}
		logger.Debug().Str("user", claims.Username).Msg("token verified")

		// Add the token and claims to the context
		ctx := context.WithValue(r.Context(), TokenKey, token)
		ctx = context.WithValue(ctx, ClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// Middleware to add additional context to each request
func WithLogger(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := log.With().
			Str("host", r.Host).
			Str("method", r.Method).
			Str("url", r.URL.String()).
			Str("remote_addr", r.RemoteAddr).
			Time("timestamp", time.Now()).
			Logger()
		ctx := logger.WithContext(r.Context())
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
