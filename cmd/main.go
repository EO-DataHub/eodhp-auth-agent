package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authz"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/jackc/pgx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type contextKey string

const claimsKey contextKey = "claims"

func main() {
	// Parse command line flags
	logLevel := flag.String("log", "warn", "sets the log level")
	host := flag.String("host", "127.0.0.1", "port to run the server on")
	port := flag.Int("port", 8080, "port to run the server on")
	configPath := flag.String("config", "", "path to config file (required)")
	flag.Parse()

	// Set the log level
	setLogging(*logLevel)

	// Load the config file
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	// Create the database client
	tokenDB := db.NewTokenDB(config.APITokenConfig)
	tokenDB.OpenDB(config.Database.Driver, config.Database.Source)
	defer tokenDB.CloseDB()

	// Create the Keycloak client
	kcClient := keycloak.NewKeycloakClient(config.Keycloak)

	// Create the authenticators
	authenticators := make([]authn.Authenticator, len(config.Authenticators))
	for i, a := range config.Authenticators {
		authenticators[i] = *authn.NewAuthenticator(a, tokenDB, kcClient)
	}

	// Create the authorizer
	authorizer := authz.NewAuthorizer(config.Authorizer)

	// Create routes
	r := mux.NewRouter()
	r.HandleFunc("/", HomeHandler).Methods(http.MethodGet)

	// The auth route does not use the JWT middleware
	r.HandleFunc("/auth", withLogger(authHandler(authenticators, authorizer))).
		Methods(http.MethodGet)

	// The CRUD routes all use the same middleware
	var middleware = func(next http.HandlerFunc) http.HandlerFunc {
		return withLogger(jwtMiddleware(next))
	}
	r.HandleFunc("/tokens", middleware(listTokensHandler(tokenDB))).
		Methods(http.MethodGet)
	r.HandleFunc("/tokens", middleware(createTokenHandler(tokenDB, kcClient))).
		Methods(http.MethodPost)
	r.HandleFunc("/tokens/{token_id}", middleware(getTokenHandler(tokenDB))).
		Methods(http.MethodGet)
	r.HandleFunc("/tokens/{token_id}", middleware(deleteTokenHandler(tokenDB))).
		Methods(http.MethodDelete)

	// Start the server
	fmt.Printf("Starting server on %s:%d\n", *host, *port)
	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", *host, *port), r); err != nil {
		log.Error().Err(err).Msg("Could not start server")
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Welcome to the auth agent"))
}

func authHandler(authenticators []authn.Authenticator,
	authorizer authz.Authorizer) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().Logger()

		// Initialise authentication variables
		isAuthenticated := false
		claims := &authn.Claims{}

		// Loop through the authenticators in order and break on the first
		// to pass authentication, returning the claims from that authenticator
		for _, authenticator := range authenticators {
			c, err := authenticator.GetAuthenticatedClaims(r)
			if err == nil {
				continue
			}

			// If err is nil, the request is authenticated
			isAuthenticated = true
			claims = c
			break
		}
		if isAuthenticated {
			logger = logger.With().Str("user", claims.Username).Logger()
			logger.Info().Msg("request authenticated")
		} else {
			logger.Info().Msg("request not authenticated")
		}

		// Use the claims from the authenticated request to check authorization
		isAuthorized, err := authorizer.IsAuthorized(r, *claims)
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

func jwtMiddleware(next http.HandlerFunc) http.HandlerFunc {
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
		ctx := context.WithValue(r.Context(), claimsKey, *claims)
		logger.Info().Str("user", claims.Username).Msg("Token verified")
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func listTokensHandler(tokenDB *db.TokenDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "list tokens").Logger()

		// Get the user ID from the claims
		claims, ok := r.Context().Value(claimsKey).(authn.Claims)
		if !ok {
			logger.Error().Msg("No claims found in context")
			http.Error(w, "No claims found in context",
				http.StatusInternalServerError)
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
			http.Error(w, "Failed to list tokens", http.StatusInternalServerError)
			return
		}

		// Write the response
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tokens)
	}
}

func createTokenHandler(tokenDB *db.TokenDB, auth *keycloak.KeycloakClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "create token").Logger()

		// Get the user ID from the claims
		claims := r.Context().Value(claimsKey).(authn.Claims)
		if claims.Username == "" {
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
			http.Error(w, "Failed to get offline token", http.StatusInternalServerError)
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
		json.NewEncoder(w).Encode(token)
	}
}

func getTokenHandler(db *db.TokenDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenID := mux.Vars(r)["token_id"]
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "get token").Logger()

		// Get the token from the database
		token, err := db.GetTokenByID(tokenID)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to get token")
			http.Error(w, "Failed to get token", http.StatusInternalServerError)
			return
		}

		// Write the response
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(token)
	}
}

func deleteTokenHandler(db *db.TokenDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenID := mux.Vars(r)["token_id"]
		logger := zerolog.Ctx(r.Context()).With().
			Str("handler", "delete token").Logger()

		// Delete the token from the database
		err := db.DeleteTokenByID(tokenID)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to delete token")
			http.Error(w, "Failed to delete token",
				http.StatusInternalServerError)
			return
		}

		// Write the response
		w.WriteHeader(http.StatusNoContent)
	}
}

type config struct {
	Authenticators []authn.AuthenticatorInputs   `yaml:"authenticators"`
	Authorizer     authz.AuthorizerInputs        `yaml:"authorizer"`
	Keycloak       keycloak.KeycloakClientInputs `yaml:"keycloak"`
	Database       databaseConfig                `yaml:"database"`
	APITokenConfig db.APITokenConfig             `yaml:"api_token"`
}

type databaseConfig struct {
	Driver string `yaml:"driver"`
	Source string `yaml:"source"`
}

func loadConfig(path string) (*config, error) {
	// Read the config file
	if path == "" {
		err := errors.New("--config flag is required")
		log.Fatal().Err(err).Msg("Config file not provided")
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to read config file")
		return nil, err
	}
	c := &config{}
	if err := c.loadConfig(data); err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
		return nil, err
	}

	return c, nil
}

func (c *config) loadConfig(data []byte) error {
	// Unmarshal the YAML data into the config struct
	err := yaml.Unmarshal(data, &c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal file")
		return err
	}

	return nil
}

// Middleware to add additional context to each request
func withLogger(next http.HandlerFunc) http.HandlerFunc {
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

func setLogging(level string) {
	zerolog.TimestampFunc = func() time.Time {
		return time.Now().UTC()
	}

	switch strings.ToLower(level) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}
}
