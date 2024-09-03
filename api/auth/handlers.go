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
		logger := zerolog.Ctx(req.Context()).With().Str("original uri",
			req.Header.Get(OriginalURI)).Logger()

		logger.Debug().Msg("received request")

		var isAuthenticated, isAuthorized, hostAllowed bool
		for _, flow := range flows {
			if !flow.IsHostAllowed(req.Host) {
				continue
			}

			isAuthenticated, isAuthorized = flow.ProcessRequest(w, req)
			hostAllowed = true
			break
		}

		if !hostAllowed {
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
