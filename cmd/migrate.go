package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(migrateCmd)
	migrateCmd.PersistentFlags().StringVar(&logLevel, "log", "warn",
		"sets the log level")
	migrateCmd.PersistentFlags().StringVar(&configPath, "config", "",
		"path to config file (required)")
}

var migrateCmd = &cobra.Command{
	Use:   "migrate [dir]",
	Short: "Run database migrations",
	Long:  `Run the database migrations in the migrations directory.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Set the log level
		setLogging(logLevel)

		// Load the config file
		var err error
		config, err = loadConfig(configPath)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to load config")
		}

		// Set up the database
		tokenDB := setUp()
		defer tokenDB.CloseDB()

		// Run the migrations
		log.Info().Msgf("Running migrations...")
		if err := tokenDB.Migrate(); err != nil {
			log.Fatal().Err(err).Msg("Failed to run migrations")
		}

		log.Info().Msg("Migrations complete")
	},
}
