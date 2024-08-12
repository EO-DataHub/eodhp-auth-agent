package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Parse command line flags
	logLevel := flag.String("debug", "info", "sets the log level")
	flag.Parse()

	setLogLevel(*logLevel)

	http.HandleFunc("/auth", authHandler)

	fmt.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Error().Msgf("Could not start server: %s\n", err.Error())
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the authentication cookie from the request
	cookie, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not found, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("No session token found"))
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Error retrieving session token"))
		return
	}

	// Handle authentication requests
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Authentication endpoint. Session token: %s", cookie.Value)))
}

func setLogLevel(level string) {
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
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}
