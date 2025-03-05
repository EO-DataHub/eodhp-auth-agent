package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestJWTMiddleware_ValidBearerToken_ClaimsPopulated(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value(ClaimsKey).(Claims)
		// Test claims
		assert.Equal(t, "abcd-1234", claims.Subject)
		w.WriteHeader(http.StatusOK)
	})

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	jwtToken, err := authn.CreateJWTToken(Claims{
		StandardClaims: jwt.StandardClaims{
			Subject: "abcd-1234",
		},
	}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

	mw := JWTMiddleware(next)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
}

func TestProxyAuthRequest_InvalidBearerToken_ClaimsNotPopulated(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value(ClaimsKey).(Claims)
		// Test claims
		if claims.Subject == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer invalid-token")

	mw := JWTMiddleware(next)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
}

func TestConvertMeToUser_Me_ReplaceWithUser(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Test user-id path param
		vars := mux.Vars(r)
		assert.Equal(t, "abcd-1234", vars["user-id"])
		w.WriteHeader(http.StatusOK)
	})

	r, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	r = mux.SetURLVars(r, map[string]string{"user-id": "me"})
	ctx := context.WithValue(r.Context(), ClaimsKey, Claims{
		StandardClaims: jwt.StandardClaims{Subject: "abcd-1234"},
		Workspaces:     []string{"my-workspace"}})
	w := httptest.NewRecorder()

	mw := ConvertMeToUser(next, "user-id")
	mw.ServeHTTP(w, r.WithContext(ctx))
}

func TestWorkspaceAuth_WorkspaceAuthorized_PassThroughRequest(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	r = mux.SetURLVars(r, map[string]string{"workspace": "my-workspace"})
	ctx := context.WithValue(r.Context(), ClaimsKey, Claims{
		StandardClaims: jwt.StandardClaims{Subject: "abcd-1234"},
		Workspaces:     []string{"my-workspace"}})
	w := httptest.NewRecorder()

	mw := WorkspaceAuthMiddleware(next)
	mw.ServeHTTP(w, r.WithContext(ctx))

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWorkspaceAuth_WorkspaceNotAuthorized_Forbidden(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	r = mux.SetURLVars(r, map[string]string{"workspace": "another-workspace"})
	ctx := context.WithValue(r.Context(), ClaimsKey, Claims{
		StandardClaims: jwt.StandardClaims{Subject: "abcd-1234"},
		Workspaces:     []string{"my-workspace"}})
	w := httptest.NewRecorder()

	mw := WorkspaceAuthMiddleware(next)
	mw.ServeHTTP(w, r.WithContext(ctx))

	assert.Equal(t, http.StatusForbidden, w.Code)
}
