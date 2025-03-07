package cmd

import (
	"fmt"
	"net/http"
	"path"

	docs "github.com/EO-DataHub/eodhp-auth-agent/docs"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/handlers/auth"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/handlers/health"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/handlers/middleware"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/handlers/tokens"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	httpSwagger "github.com/swaggo/http-swagger"
)

// @title EODHP Auth Agent API
// @version v1
// @description This is the API for the UK EO DataHub Auth Agent.
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
		flows := make([]auth.AuthProcessor, len(config.AuthStrategies))
		var err error
		for i, flowInputs := range config.AuthStrategies {
			flows[i], err = auth.NewAuthStrategy(flowInputs, tokenDB, kcClient)
			if err != nil {
				log.Fatal().Str("auth flow", flowInputs.Name).Err(err).
					Msg("failed to create auth flow")
			}
		}

		// Create routes under base path
		r := mux.NewRouter()
		api := r.PathPrefix(config.BasePath).Subrouter()

		// The auth routes do not use the JWT middleware
		// Auth routes are not intended as a public API, so are not on base path
		authApi := r.PathPrefix("/auth").Subrouter()
		authApi.Use(middleware.WithLogger)
		authApi.HandleFunc("", auth.AuthHandler(flows)).
			Methods(http.MethodGet)
		authApi.HandleFunc("/introspect", auth.IntrospectAuthHandler(kcClient)).
			Methods(http.MethodPost)

		// Token routes
		workspacesAPI := api.PathPrefix("/workspaces/{workspace}/{user-id}").Subrouter()
		workspacesAPI.Use(middleware.WithLogger)
		workspacesAPI.Use(middleware.JWTMiddleware)
		workspacesAPI.Use(middleware.WorkspaceAuthMiddleware)
		workspacesAPI.Use(middleware.ConvertMeToUser("user-id"))
		workspacesAPI.HandleFunc("/tokens", tokens.ListTokensHandler(tokenDB)).
			Methods(http.MethodGet)
		workspacesAPI.HandleFunc("/tokens", tokens.CreateTokenHandler(tokenDB,
			kcClient)).Methods(http.MethodPost)
		workspacesAPI.HandleFunc("/tokens/{token-id}", tokens.GetTokenHandler(
			tokenDB)).Methods(http.MethodGet)
		workspacesAPI.HandleFunc("/tokens/{token-id}", tokens.DeleteTokenHandler(
			tokenDB, kcClient)).Methods(http.MethodDelete)

		// Docs
		docs.SwaggerInfo.Host = config.Host
		docs.SwaggerInfo.BasePath = config.BasePath
		r.PathPrefix(config.DocsPath).Handler(httpSwagger.Handler(
			httpSwagger.URL(path.Join(config.DocsPath, "/doc.json")),
			httpSwagger.DeepLinking(true),
			httpSwagger.DocExpansion("none"),
			httpSwagger.DomID("swagger-ui"),
		)).Methods(http.MethodGet)

		// Health check
		r.HandleFunc("/health", health.GetHealth(tokenDB)).Methods(http.MethodGet)

		// Start the server
		fmt.Printf("serving on %s:%d\n", host, port)
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
