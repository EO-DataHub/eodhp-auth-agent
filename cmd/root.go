package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/api/auth"
	"github.com/EO-DataHub/eodhp-auth-agent/api/middleware"
	"github.com/EO-DataHub/eodhp-auth-agent/api/tokens"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authz"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	logLevel   string
	host       string
	port       int
	configPath string
	config     *Config
)

var rootCmd = &cobra.Command{
	Use:   "auth-agent",
	Short: "Auth Agent",
	Long: `Auth Agent is a CLI tool for managing platform authentication 
		and authorization.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Set the log level
		setLogging(logLevel)

		// Load the config file
		var err error
		config, err = loadConfig(configPath)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to load config")
		}

		// Create the database client
		tokenDB := db.NewTokenDB(config.APIToken)
		err = tokenDB.OpenDB(config.Database.Driver, config.Database.Source)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to open database")
		}
		defer tokenDB.CloseDB()

		// Create the Keycloak client
		kcClient := keycloak.NewKeycloakClient(config.Keycloak)

		// Create the authenticators
		authenticators := make([]auth.Authenticator, len(config.Authenticators))
		for i, a := range config.Authenticators {
			var err error
			authenticators[i], err = authn.NewAuthenticator(a, tokenDB,
				kcClient)
			if err != nil {
				log.Fatal().Str("authenticator", a.Name).Err(err).
					Msg("Failed to create authenticator")
			}
		}

		// Create the authorizer
		authorizer := authz.NewAuthorizer(config.Authorizer)

		// Create routes
		r := mux.NewRouter()

		// The auth route does not use the JWT middleware
		r.HandleFunc("/auth", middleware.WithLogger(auth.AuthHandler(
			authenticators, authorizer))).Methods(http.MethodGet)

		// The CRUD routes all use the same middleware
		var middleware = func(next http.HandlerFunc) http.HandlerFunc {
			return middleware.WithLogger(middleware.JWTMiddleware(next))
		}
		r.HandleFunc("/tokens", middleware(tokens.ListTokensHandler(tokenDB))).
			Methods(http.MethodGet)
		r.HandleFunc("/tokens", middleware(tokens.CreateTokenHandler(tokenDB,
			kcClient))).Methods(http.MethodPost)
		r.HandleFunc("/tokens/{token_id}", middleware(tokens.GetTokenHandler(
			tokenDB))).Methods(http.MethodGet)
		r.HandleFunc("/tokens/{token_id}", middleware(tokens.DeleteTokenHandler(
			tokenDB))).Methods(http.MethodDelete)

		// Start the server
		fmt.Printf("Starting server on %s:%d\n", host, port)
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", host, port),
			r); err != nil {

			log.Error().Err(err).Msg("Could not start server")
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logLevel, "log", "warn",
		"sets the log level")
	rootCmd.PersistentFlags().StringVar(&host, "host", "0.0.0.0",
		"host to run the server on")
	rootCmd.PersistentFlags().IntVar(&port, "port", 8080,
		"port to run the server on")
	rootCmd.PersistentFlags().StringVar(&configPath, "config",
		"/etc/auth-agent/config.yaml", "path to config file")
}

type Config struct {
	Authenticators []authn.AuthenticatorInputs   `yaml:"authenticators"`
	Authorizer     authz.AuthorizerInputs        `yaml:"authorizer"`
	Keycloak       keycloak.KeycloakClientInputs `yaml:"keycloak"`
	Database       databaseConfig                `yaml:"database"`
	APIToken       db.TokenDBInputs              `yaml:"api_token"`
}

type databaseConfig struct {
	Driver string `yaml:"driver"`
	Source string `yaml:"source"`
}

func loadConfig(path string) (*Config, error) {
	// Read the config file
	if path == "" {
		err := errors.New("--config flag is required")
		log.Fatal().Err(err).Msg("Config file not provided")
		return nil, err
	}

	// Parse the template file
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		log.Fatal().Err(err).Msg("Error parsing config file template")
	}

	// Create a map of environment variables
	envVars := loadEnvVars()

	// Execute the template with the environment variables
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, envVars)
	if err != nil {
		log.Fatal().Err(err).Msg("Error executing config file template")
	}

	// Load the config
	c := &Config{}
	if err := c.loadConfig(buf.Bytes()); err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
		return nil, err
	}

	return c, nil
}

func (c *Config) loadConfig(data []byte) error {
	// Unmarshal the YAML data into the config struct
	err := yaml.Unmarshal(data, &c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal file")
		return err
	}

	return nil
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

func loadEnvVars() map[string]string {
	envVars := make(map[string]string)
	for _, env := range os.Environ() {
		kv := strings.Split(env, "=")
		if len(kv) == 2 {
			envVars[kv[0]] = kv[1]
		}
	}
	return envVars
}
