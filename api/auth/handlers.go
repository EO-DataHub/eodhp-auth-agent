package auth

import (
	"fmt"
	"net/http"
)

type AuthProcessor interface {
	ProcessRequest(w http.ResponseWriter, req *http.Request) (bool, bool)
	IsHostAllowed(host string) bool
}

func AuthHandler(flows []AuthProcessor) http.HandlerFunc {

	return func(w http.ResponseWriter, req *http.Request) {
		var isAuthenticated, isAuthorized bool
		for _, flow := range flows {
			if !flow.IsHostAllowed(req.Host) {
				continue
			}

			isAuthenticated, isAuthorized = flow.ProcessRequest(w, req)
			break
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
