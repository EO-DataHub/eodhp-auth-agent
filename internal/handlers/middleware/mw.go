package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type contextKey string
type tokenKey string
type Claims struct {
	jwt.StandardClaims
	Workspaces []string `json:"workspaces"`
}

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
			logger.Error().Msg("invalid auth header format, should be bearer")
			http.Error(w, "invalid auth header format, should be bearer",
				http.StatusUnauthorized)
			return
		}

		// Parse the token for JWT claims
		claims := Claims{}
		err := authn.ParseClaims(token, &claims)
		if err != nil {
			logger.Error().Err(err).Msg("invalid bearer jwt token")
			http.Error(w, "invalid bearer jwt token", http.StatusUnauthorized)
			return
		}
		logger.Debug().Str("userid", claims.Subject).Msg("token verified")

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

// For `user` path parameter, `user` may be set to "me". Detect when this is the
// case and replace with the user ID from the JWT claims.
//
// Must be after JWTMiddleware in the middleware chain.
func ConvertMeToUser(next http.HandlerFunc, param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "convert me to user").Logger()

		vars := mux.Vars(r)
		user := vars[param]

		// Pass through if user is not "me"
		if user != "me" {
			logger.Debug().Str("user", user).Msg("user not me")
			next.ServeHTTP(w, r)
			return
		}

		// Get the user ID from the claims
		claims, ok := r.Context().Value(ClaimsKey).(Claims)
		if !ok {
			logger.Error().Msg("no claims found in context. This middleware " +
				"must be called after JWTMiddleware")
			http.Error(w, "no claims found in context", http.StatusUnauthorized)
			return
		}
		userID := claims.Subject
		if userID == "" {
			logger.Error().Msg("no user ID in claims")
			http.Error(w, "no user ID in claims", http.StatusUnauthorized)
			return
		}

		// Replace "me" with the user ID
		vars[param] = userID
		logger.Debug().Str("user", userID).Msg("replaced me with user")

		// Call the next handler
		next.ServeHTTP(w, r)
	}
}

// Middleware to check workspace authorization.
//
// Must be after JWTMiddleware in the middleware chain.
func WorkspaceAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "workspace auth middleware").Logger()

		vars := mux.Vars(r)
		workspace := vars["workspace"]

		// Get the claims from the context
		claims, ok := r.Context().Value(ClaimsKey).(Claims)
		if !ok {
			logger.Error().Msg("no claims found in context. This middleware " +
				"must be called after JWTMiddleware")
			http.Error(w, "no claims found in context", http.StatusUnauthorized)
			return
		}

		// Check if the workspace is in the user's workspaces
		if claims.Workspaces == nil || !contains(claims.Workspaces, workspace) {
			logger.Error().Msg("user not authorized for workspace")
			http.Error(w, "user not authorized for workspace",
				http.StatusForbidden)
			return
		}

		logger.Debug().Str("user", claims.Subject).Str("workspace", workspace).
			Msg("user authorized for workspace")

		// Call the next handler
		next.ServeHTTP(w, r)
	}
}

// Check if a string is in a slice of strings
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
