package cmd

import (
	"fmt"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage tokens",
	Long:  `Manage tokens in the database.`,
}

// Define the create subcommand
var createTokenCmd = &cobra.Command{
	Use:   "create [user_id]",
	Short: "Create a new token",
	Long:  `Create a new token for a user.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userID := args[0]
		fmt.Printf("Creating token for user ID %s\n", userID)
		tokenDB := setUp()
		defer tokenDB.CloseDB()

		// Create the Keycloak client
		kcClient := keycloak.NewKeycloakClient(config.Keycloak)

		// Get client credentials
		clientToken, err := kcClient.GetClientCredentials()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get client credentials")
		}

		// Impersonate user
		userToken, err := kcClient.ImpersonateUser(clientToken.Access, userID)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to impersonate user")
		}

		// Get offline access token
		offlineToken, err := kcClient.GetOfflineToken(userToken.Access)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get offline token")
		}

		// Create the token
		apiToken, err := tokenDB.GenerateAPIToken()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to generate API token")
		}
		token := db.Token{
			ID:           uuid.New().String(),
			UserID:       userID,
			Token:        apiToken,
			Access:       offlineToken.Access,
			AccessExpiry: int64(offlineToken.ExpiresIn) + time.Now().Unix(),
			Refresh:      offlineToken.Refresh,
		}
		err = tokenDB.CreateToken(token)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create token")
		}

		fmt.Printf("Token created: %s\n", token.Token)
	},
}

var listTokenCmd = &cobra.Command{
	Use:   "list [user_id]",
	Short: "List all tokens",
	Long:  `List all tokens for a user.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userID := args[0]
		fmt.Printf("Listing tokens for user ID %s\n", userID)
		tokenDB := setUp()
		defer tokenDB.CloseDB()

		tokens, err := tokenDB.ListUserTokens(userID)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get tokens by user ID")
		}

		fmt.Printf("Found %d tokens for user ID %s\n", len(tokens), userID)
		for _, token := range tokens {
			fmt.Printf("ID: %s\n", token.ID)
		}
	},
}

var deleteTokenCmd = &cobra.Command{
	Use:   "delete [user_id] [token_id]",
	Short: "Delete a token",
	Long:  `Delete a token.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		userID := args[0]
		tokenID := args[1]
		fmt.Printf("Deleting token ID %s for user ID %s\n", tokenID, userID)
		tokenDB := setUp()
		defer tokenDB.CloseDB()

		err := tokenDB.DeleteTokenByID(userID, tokenID)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to delete token")
		}

	},
}

func init() {
	// Add subcommands to the main token command
	tokenCmd.AddCommand(createTokenCmd)
	tokenCmd.AddCommand(listTokenCmd)
	tokenCmd.AddCommand(deleteTokenCmd)

	// Add the token command to the root command
	rootCmd.AddCommand(tokenCmd)
}
