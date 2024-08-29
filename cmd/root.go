package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authz"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
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
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logLevel, "log", "warn",
		"sets the log level")
	rootCmd.PersistentFlags().StringVar(&configPath, "config",
		"/etc/auth-agent/config.yaml", "path to config file")
}

func setUp() *db.TokenDB {
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

	return tokenDB
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
