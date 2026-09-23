package health

import (
	"net/http"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
)

func GetHealth(tokenDB *db.TokenDB, jwtVerifier *authn.Verifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check the database connection
		if err := tokenDB.Ping(); err != nil {
			http.Error(w, "failed to connect to the database",
				http.StatusInternalServerError)
			return
		}

		// Until the verifier has loaded a signing key from Keycloak, every token
		// verification fails even for a genuinely valid token.
		if !jwtVerifier.Ready(r.Context()) {
			http.Error(w, "JWT verifier has not yet loaded signing keys from Keycloak",
				http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}
