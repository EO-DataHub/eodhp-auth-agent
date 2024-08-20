package main

import (
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
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

func main() {
	// Parse command line flags
	logLevel := flag.String("debug", "info", "sets the log level")
	port := flag.Int("port", 8080, "port to run the server on")
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	// Set the log level
	setLogLevel(*logLevel)

	// Load the config file
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	// Create the database client
	tokenDB := db.TokenDB{
		APITokenPrefix: config.ApiTokenPrefix,
	}
	tokenDB.OpenDB(config.Database.Driver, config.Database.Source)
	defer tokenDB.CloseDB()

	// Create the Keycloak client
	kcClient := keycloak.NewKeycloakClient(config.Keycloak)

	// Create the authenticators
	authenticators := make([]authn.Authenticator, len(config.Authenticators))
	for i, a := range config.Authenticators {
		authenticators[i] = *authn.NewAuthenticator(a, &tokenDB, kcClient)
	}

	// Create the authorizer
	authorizer := authz.NewAuthorizer(config.Authorizer)

	// Create routes
	http.HandleFunc("/auth", withLogger(authHandler(
		authenticators, authorizer)))

	// Start the server
	fmt.Printf("Starting server on :%d", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Error().Err(err).Msg("Could not start server")
	}
}

func authHandler(authenticators []authn.Authenticator,
	authorizer authz.Authorizer) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		// Initialise authentication variables
		isAuthenticated := false
		claims := &authn.Claims{}

		// Loop through the authenticators in order and break on the first
		// to pass authentication, returning the claims from that authenticator
		for _, authenticator := range authenticators {
			c, err := authenticator.GetAuthenticatedClaims(r)
			if err != nil {
				continue
			}

			// If err is nil, the request is authenticated
			isAuthenticated = true
			claims = c
			break
		}

		// Use the claims from the authenticated request to check authorization
		isAuthorized, err := authorizer.IsAuthorized(r, *claims)
		if err != nil {
			log.Error().Err(err).Msg("Failed to check authorization")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))
			return
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

// Configuration parameters for the auth agent. Authenticators contain a list of
// allowed origins. In order to optimise the search for the correct authenticator,
// the order of the authenticators is important. The first authenticator in the
// list will be checked first. It is suggested to order the authenticators from
// most to least specific, in terms of allowed origins.
type config struct {
	Authenticators []authn.AuthenticatorInputs   `yaml:"authenticators"`
	Authorizer     authz.AuthorizerInputs        `yaml:"authorizer"`
	Keycloak       keycloak.KeycloakClientInputs `yaml:"keycloak"`
	Database       databaseConfig                `yaml:"database"`
	ApiTokenPrefix string                        `yaml:"api_token_prefix"`
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

// Set the log level of the application. Default is warn.
func setLogLevel(level string) {
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
