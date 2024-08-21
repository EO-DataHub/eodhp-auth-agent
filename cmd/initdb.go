package cmd

import (
	"fmt"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var initdbCmd = &cobra.Command{
	Use:   "initdb",
	Short: "Initialize the database",
	Long:  `Initialize the database with the required tables and indexes.`,
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
		tokenDB := db.NewTokenDB(config.APITokenConfig)
		err = tokenDB.OpenDB(config.Database.Driver, config.Database.Source)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to open database")
		}
		defer tokenDB.CloseDB()

		err = tokenDB.InitDB()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize the database")
		}
		fmt.Println("Database initialized successfully")
	},
}

func init() {
	rootCmd.AddCommand(initdbCmd)
	initdbCmd.PersistentFlags().StringVar(&logLevel, "log", "warn",
		"sets the log level")
	initdbCmd.PersistentFlags().StringVar(&configPath, "config", "",
		"path to config file (required)")
}
