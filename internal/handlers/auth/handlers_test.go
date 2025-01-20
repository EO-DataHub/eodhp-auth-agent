package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/keycloak"
	"github.com/stretchr/testify/assert"
)

type AuthFlowMock struct {
	isAuthenticated bool
	isAuthorized    bool
	isHostAllowed   bool
	called          bool
}

func (a *AuthFlowMock) ProcessRequest(w http.ResponseWriter,
	req *http.Request) (bool, bool) {

	a.called = true
	return a.isAuthenticated, a.isAuthorized
}

func (a *AuthFlowMock) IsHostAllowed(string) bool {
	return a.isHostAllowed
}

func TestAuthHandler_AuthnAndAuthz_OK(t *testing.T) {
	// Create the mocks
	flows := []AuthProcessor{
		&AuthFlowMock{isHostAllowed: false},
		&AuthFlowMock{isAuthenticated: true, isAuthorized: true,
			isHostAllowed: true},
	}

	// Create the handler
	handler := AuthHandler(flows)

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(w, r)

	// Check results
	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, flows[0].(*AuthFlowMock).called)
	assert.True(t, flows[1].(*AuthFlowMock).called)
}

func TestAuthHandler_NoAuthnButAuthz_OK(t *testing.T) {
	// Create the mocks
	flows := []AuthProcessor{
		&AuthFlowMock{isHostAllowed: false},
		&AuthFlowMock{isAuthenticated: false, isAuthorized: true,
			isHostAllowed: true},
	}

	// Create the handler
	handler := AuthHandler(flows)

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(w, r)

	// Check results
	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, flows[0].(*AuthFlowMock).called)
	assert.True(t, flows[1].(*AuthFlowMock).called)
}

func TestAuthHandler_NoAuthnOrAuthz_Unauthorized(t *testing.T) {
	// Create the mocks
	flows := []AuthProcessor{
		&AuthFlowMock{isHostAllowed: false},
		&AuthFlowMock{isAuthenticated: false, isAuthorized: false,
			isHostAllowed: true},
	}

	// Create the handler
	handler := AuthHandler(flows)

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(w, r)

	// Check results
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, flows[0].(*AuthFlowMock).called)
	assert.True(t, flows[1].(*AuthFlowMock).called)
}

func TestAuthHandler_AuthnButNoAuthz_Forbidden(t *testing.T) {
	// Create the mocks
	flows := []AuthProcessor{
		&AuthFlowMock{isHostAllowed: false},
		&AuthFlowMock{isAuthenticated: true, isAuthorized: false,
			isHostAllowed: true},
	}

	// Create the handler
	handler := AuthHandler(flows)

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(w, r)

	// Check results
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, flows[0].(*AuthFlowMock).called)
	assert.True(t, flows[1].(*AuthFlowMock).called)
}

func TestAuthHandler_FirstAuthnAndAuthz_OK(t *testing.T) {
	// Create the mocks
	flows := []AuthProcessor{
		&AuthFlowMock{isAuthenticated: true, isAuthorized: true,
			isHostAllowed: true},
		&AuthFlowMock{isHostAllowed: false},
	}

	// Create the handler
	handler := AuthHandler(flows)

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(w, r)

	// Check results
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, flows[0].(*AuthFlowMock).called)
	assert.False(t, flows[1].(*AuthFlowMock).called)
}

func TestInspectTokenHandler_ValidToken_Success(t *testing.T) {
	// Setup auth server response for Keycloak Client
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`
				{
					"username": "jbloggs",
					"active": true
				}
			`))
		}))
	defer server.Close()

	k := keycloak.NewKeycloakClient(keycloak.KeycloakClientInputs{
		KeycloakURL:  server.URL,
		Realm:        "test",
		ClientID:     "myclient",
		ClientSecret: "mysecret",
	})

	// Create handler
	handler := IntrospectAuthHandler(k)

	// Setup request and response
	r := httptest.NewRequest("POST", "/introspect", nil)
	r.Header.Set("Authorization", "Bearer accesstoken")
	w := httptest.NewRecorder()

	// Test the handler
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response body
	var response keycloak.KeycloakResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, response["username"], "jbloggs")
	assert.Equal(t, response["active"], true)
}
