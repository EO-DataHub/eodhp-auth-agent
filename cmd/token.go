package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	// Add the token command to the root command
	rootCmd.AddCommand(tokenCmd)

	// Add subcommands to the main token command
	tokenCmd.AddCommand(createTokenCmd)
	tokenCmd.AddCommand(infoTokenCmd)
	tokenCmd.AddCommand(refreshTokenCmd)
	tokenCmd.AddCommand(listTokenCmd)
	tokenCmd.AddCommand(deleteTokenCmd)

	// Add flags to the info subcommand
	infoTokenCmd.Flags().Bool("access", false, "show access token")
	infoTokenCmd.Flags().Bool("refresh", false, "show refresh token")

	// Add flags to the refresh subcommand
	refreshTokenCmd.Flags().Bool("access", false, "show access token")
}

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage tokens",
	Long:  `Manage tokens in the database.`,
}

// Define the create subcommand
var createTokenCmd = &cobra.Command{
	Use:   "create [user_id] --scope [scope]",
	Short: "Create a new token",
	Long:  `Create a new token for a user.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get inputs
		userID := args[0]
		fmt.Printf("Creating token for user ID %s\n", userID)

		scope, err := cmd.Flags().GetString("scope")
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get scope flag")
		}
		scope = strings.ReplaceAll(scope, ",", " ")
		fmt.Printf("Requesting token with scope '%s'\n", scope)

		// Set up the database
		tokenDB := setUp()
		defer tokenDB.CloseDB()

		// Create the Keycloak client
		kcClient := keycloak.NewKeycloakClient(config.Keycloak)

		// Get client credentials
		clientToken, err := kcClient.GetClientCredentials()
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get client credentials")
		}

		// Impersonate user
		userToken, err := kcClient.ImpersonateUser(clientToken.Access, userID)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to impersonate user")
		}

		// Get offline access token
		offlineToken, err := kcClient.ExchangeToken(userToken.Access, scope)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get offline token")
		}

		// Create the token
		apiToken, err := tokenDB.GenerateAPIToken()
		if err != nil {
			log.Fatal().Err(err).Msg("failed to generate API token")
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
			log.Fatal().Err(err).Msg("failed to create token")
		}

		fmt.Printf("Token created: %s\n", token.Token)
	},
}

var infoTokenCmd = &cobra.Command{
	Use:   "info [api_token]",
	Short: "Get API token info",
	Long:  `Get API token info.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		apiToken := args[0]
		fmt.Printf("Get info for API token %s\n", apiToken)

		access, _ := cmd.Flags().GetBool("access")
		refresh, _ := cmd.Flags().GetBool("refresh")

		tokenDB := setUp()
		defer tokenDB.CloseDB()

		token, err := tokenDB.GetTokenByAPIToken(apiToken)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get api token")
		}

		fmt.Printf("ID: %s\n", token.ID)
		fmt.Printf("User ID: %s\n", token.UserID)
		if access {
			fmt.Printf("Access: %s\n", token.Access)
		}
		if refresh {
			fmt.Printf("Refresh: %s\n", token.Refresh)
		}
	},
}

var refreshTokenCmd = &cobra.Command{
	Use:   "refresh [api_token]",
	Short: "Refresh API token access token",
	Long:  `Refresh API token access token.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		apiToken := args[0]
		fmt.Printf("Refreshing API token %s access token\n", apiToken)

		access, _ := cmd.Flags().GetBool("access")

		tokenDB := setUp()
		defer tokenDB.CloseDB()

		token, err := tokenDB.GetTokenByAPIToken(apiToken)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get api token")
		}

		// Create the Keycloak client
		kcClient := keycloak.NewKeycloakClient(config.Keycloak)

		// Refresh token
		tokenResponse, err := kcClient.RefreshToken(token.Refresh)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to refresh token")
		}

		// Update DB with new access token
		token.Access = tokenResponse.Access
		token.Refresh = tokenResponse.Refresh
		token.AccessExpiry = time.Now().Unix() + int64(tokenResponse.ExpiresIn)
		err = tokenDB.UpdateToken(*token)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to update token")
		}

		fmt.Printf("Token ID %s refreshed\n", token.ID)
		if access {
			fmt.Printf("Access: %s\n", token.Access)
		}
	},
}

var listTokenCmd = &cobra.Command{
	Use:   "list [workspace] [user_id]",
	Short: "List all tokens",
	Long:  `List all tokens for a user in a workspace.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		workspace := args[0]
		userID := args[1]
		fmt.Printf("Listing tokens for user ID %s\n", userID)

		tokenDB := setUp()
		defer tokenDB.CloseDB()

		tokens, err := tokenDB.ListUserTokens(workspace, userID)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get tokens by user ID")
		}

		fmt.Printf("Found %d tokens for user ID %s\n", len(tokens), userID)
		for _, token := range tokens {
			fmt.Printf("ID: %s\n", token.ID)
		}
	},
}

var deleteTokenCmd = &cobra.Command{
	Use:   "delete [token_id]",
	Short: "Delete a token",
	Long:  `Delete a token.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		tokenID := args[0]
		fmt.Printf("Deleting token ID %s\n", tokenID)
		tokenDB := setUp()
		defer tokenDB.CloseDB()

		err := tokenDB.DeleteTokenByID(tokenID)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to delete token")
		}

	},
}
