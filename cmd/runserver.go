package cmd

import (
	"fmt"
	"net/http"

	"github.com/EO-DataHub/eodhp-auth-agent/api/auth"
	"github.com/EO-DataHub/eodhp-auth-agent/api/middleware"
	"github.com/EO-DataHub/eodhp-auth-agent/api/tokens"
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

		// Create the auth flows
		flows := make([]auth.AuthProcessor, len(config.AuthFlows))
		var err error
		for i, flowInputs := range config.AuthFlows {
			flows[i], err = auth.NewAuthFlow(flowInputs, tokenDB, kcClient)
			if err != nil {
				log.Fatal().Str("auth flow", flowInputs.Name).Err(err).
					Msg("failed to create auth flow")
			}
		}

		// Create routes
		r := mux.NewRouter()

		// The auth route does not use the JWT middleware
		r.HandleFunc("/auth", middleware.WithLogger(auth.AuthHandler(flows))).
			Methods(http.MethodGet)

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
			tokenDB, kcClient))).Methods(http.MethodDelete)

		// Start the server
		fmt.Printf("starting server on %s:%d\n", host, port)
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", host, port),
			r); err != nil {

			log.Error().Err(err).Msg("could not start server")
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
