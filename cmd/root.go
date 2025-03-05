package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/handlers/auth"
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
		log.Fatal().Err(err).Msg("failed to load config")
	}

	fmt.Println("config loaded")
	fmt.Println("\nauth flows:")
	for _, flow := range config.AuthStrategies {
		fmt.Printf("- name: %s\n", flow.Name)
		fmt.Printf("  domains: %s\n", flow.Domains)
		fmt.Printf("  authentication url: %s\n", flow.AuthenticationURL)
		fmt.Printf("  authorization url: %s\n", flow.AuthorizationURL)
	}
	fmt.Printf("keycloak url: %s\n", config.Keycloak.KeycloakURL)
	fmt.Printf("realm: %s\n", config.Keycloak.Realm)
	fmt.Printf("client id: %s\n", config.Keycloak.ClientID)
	fmt.Printf("database driver: %s\n", config.Database.Driver)
	fmt.Printf("api prefix: %s\n", config.APIToken.Prefix)
	fmt.Printf("access token expiry margin: %d\n",
		config.APIToken.AccessTokenExpiryMargin)
	fmt.Printf("api available at: %s%s\n", config.Host, config.BasePath)
	fmt.Printf("docs available at: %s%s\n\n", config.Host, config.DocsPath)

	// Create the database client
	tokenDB := db.NewTokenDB(config.APIToken)
	err = tokenDB.OpenDB(config.Database.Driver, config.Database.Source)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open database")
	}

	// Check the database connection
	err = tokenDB.Ping()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to the database")
	}
	log.Info().Msg("connected to database")

	return tokenDB
}

type Config struct {
	Host           string                        `yaml:"host"`
	BasePath       string                        `yaml:"base_path"`
	DocsPath       string                        `yaml:"docs_path"`
	AuthStrategies []auth.AuthStrategyInputs     `yaml:"flows"`
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
		log.Fatal().Err(err).Msg("config file not provided")
		return nil, err
	}

	// Parse the template file
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		log.Fatal().Err(err).Msg("error parsing config file template")
	}

	// Create a map of environment variables
	envVars := loadEnvVars()

	// Execute the template with the environment variables
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, envVars)
	if err != nil {
		log.Fatal().Err(err).Msg("error executing config file template")
	}

	// Load the config
	c := &Config{
		APIToken: db.TokenDBInputs{
			AccessTokenExpiryMargin: 5,
		},
	} // initialise default values
	if err := c.loadConfig(buf.Bytes()); err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
		return nil, err
	}

	return c, nil
}

func (c *Config) loadConfig(data []byte) error {
	// Unmarshal the YAML data into the config struct
	err := yaml.Unmarshal(data, &c)
	if err != nil {
		log.Error().Err(err).Msg("failed to unmarshal file")
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
