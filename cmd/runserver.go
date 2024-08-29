package cmd

import (
	"fmt"
	"net/http"

	"github.com/EO-DataHub/eodhp-auth-agent/api/auth"
	"github.com/EO-DataHub/eodhp-auth-agent/api/middleware"
	"github.com/EO-DataHub/eodhp-auth-agent/api/tokens"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authz"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var runServerCmd = &cobra.Command{
	Use:   "runserver",
	Short: "Run the server",
	Long:  `Run the authentication and authorization server.`,
	Run: func(cmd *cobra.Command, args []string) {
		tokenDB := setUp()
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

func init() {
	rootCmd.AddCommand(runServerCmd)
	runServerCmd.Flags().StringVar(&host, "host", "0.0.0.0",
		"host to run the server on")
	runServerCmd.Flags().IntVar(&port, "port", 8080,
		"port to run the server on")
}
