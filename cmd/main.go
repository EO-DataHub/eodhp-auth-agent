package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/auth"
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

	// Start the server
	http.HandleFunc("/auth", withLogger(authHandler(*config)))
	fmt.Printf("Starting server on :%d", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Error().Err(err).Msg("Could not start server")
	}
}

func authHandler(c config) func(w http.ResponseWriter, r *http.Request) {
	// Create the authenticators and authorizer, included in returned closure
	tokenClient := auth.NewTokenClient()
	authenticators := make([]auth.Authenticator, len(c.authenticators))
	for i, a := range c.authenticators {
		authenticators[i] = *auth.NewAuthenticator(a, tokenClient)
	}
	authorizer := auth.NewAuthorizer()

	return func(w http.ResponseWriter, r *http.Request) {
		// Initialise authentication variables
		var isAuthenticated bool
		var claims *auth.Claims

		// Loop through the authenticators in order and break on the first
		// to pass authentication, returning the claims from that authenticator
		for _, authenticator := range authenticators {
			isAuthenticated, claims = authenticator.IsAuthenticated(r)
			if isAuthenticated {
				break
			}
		}

		// Use the claims from the authenticated request to check authorization
		isAuthorized := authorizer.IsAuthorized(r, *claims)

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
	authenticators []auth.AuthenticatorInputs `yaml:"authenticators"`
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
	err := yaml.Unmarshal(data, c)
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
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}
