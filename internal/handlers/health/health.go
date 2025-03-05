package health

import (
	"net/http"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/db"
)

func GetHealth(tokenDB *db.TokenDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check the database connection
		if err := tokenDB.Ping(); err != nil {
			http.Error(w, "failed to connect to the database",
				http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
