package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testVerifier is a Verifier backed by a throwaway RSA keypair, so tests can sign tokens
// without talking to a real Keycloak JWKS endpoint.
func testVerifier(t *testing.T) (*authn.Verifier, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	verifier := authn.NewVerifierWithKeyFunc(func(*jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})

	return verifier, key
}

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
	verifier, key := testVerifier(t)
	jwtToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "abcd-1234",
			Audience: jwt.ClaimStrings{"account"},
		},
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

	mw := JWTMiddleware(verifier)(next)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestJWTMiddleware_ForgedSignature_Rejected(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called for a forged token")
	})

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := testVerifier(t)
	// Signed by a different key than the one the verifier checks against - the exact
	// bug that shipped, where ParseUnverified accepted this without checking.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwtToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "abcd-1234",
			Audience: jwt.ClaimStrings{"account"},
		},
	}).SignedString(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwtToken))

	mw := JWTMiddleware(verifier)(next)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
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

	verifier, _ := testVerifier(t)
	mw := JWTMiddleware(verifier)(next)
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
		RegisteredClaims: jwt.RegisteredClaims{Subject: "abcd-1234"},
		Workspaces:     []string{"my-workspace"}})
	w := httptest.NewRecorder()

	mw := ConvertMeToUser("user-id")(next)
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
		RegisteredClaims: jwt.RegisteredClaims{Subject: "abcd-1234"},
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
		RegisteredClaims: jwt.RegisteredClaims{Subject: "abcd-1234"},
		Workspaces:     []string{"my-workspace"}})
	w := httptest.NewRecorder()

	mw := WorkspaceAuthMiddleware(next)
	mw.ServeHTTP(w, r.WithContext(ctx))

	assert.Equal(t, http.StatusForbidden, w.Code)
}
