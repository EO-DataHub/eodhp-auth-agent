package auth

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog"
)

type AuthProcessor interface {
	ProcessRequest(w http.ResponseWriter, req *http.Request) (bool, bool)
	IsHostAllowed(host string) bool
}

func AuthHandler(flows []AuthProcessor) http.HandlerFunc {

	return func(w http.ResponseWriter, req *http.Request) {
		originalHost := req.Header.Get(OriginalHost)
		originalURI := req.Header.Get(OriginalURI)

		logger := zerolog.Ctx(req.Context()).With().Str("original_host",
			originalHost).Str("original_uri", originalURI).Logger()

		logger.Debug().Msg("received request")

		req = req.WithContext(logger.WithContext(req.Context()))

		if originalHost == "" {
			logger.Warn().Str(OriginalHost, originalHost).
				Msg("missing original host, unexpected behaviour may occur")
		}
		if originalURI == "" {
			logger.Warn().Str(OriginalURI, originalURI).
				Msg("missing original uri, unexpected behaviour may occur")
		}

		var isAuthenticated, isAuthorized, broke bool
		for _, flow := range flows {
			if !flow.IsHostAllowed(req.Host) {
				continue
			}

			isAuthenticated, isAuthorized = flow.ProcessRequest(w, req)
			broke = true
			break
		}

		if !broke {
			logger.Warn().Msg("no auth flow matched the request")
		}

		// Handle authentication requests
		if isAuthorized {
			w.WriteHeader(http.StatusOK)
		} else if !isAuthenticated {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
		w.Write([]byte(fmt.Sprintf("Authenticated: %t, Authorized: %t",
			isAuthenticated, isAuthorized)))
	}
}
