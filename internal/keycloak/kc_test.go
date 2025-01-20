//go:build !production

package keycloak

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewKeycloakClient(t *testing.T) {
	inputs := KeycloakClientInputs{
		KeycloakURL:  "https://example.com",
		Realm:        "myrealm",
		ClientID:     "myclient",
		ClientSecret: "mysecret",
	}

	client := NewKeycloakClient(inputs)

	assert.NotNil(t, client)
	assert.Equal(t, inputs.KeycloakURL, client.KeycloakURL)
	assert.Equal(t, inputs.Realm, client.Realm)
	assert.Equal(t, inputs.ClientID, client.ClientID)
	assert.Equal(t, inputs.ClientSecret, client.ClientSecret)
}

func TestKeycloakClient_RefreshToken_OK(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`
				{
					"access_token": "new_access",
					"refresh_token": "new_refresh",
					"expires_in": 3600
				}
			`))
		}))
	defer server.Close()

	client := &KeycloakClient{
		KeycloakClientInputs: KeycloakClientInputs{
			KeycloakURL:  server.URL,
			Realm:        "test",
			ClientID:     "myclient",
			ClientSecret: "mysecret",
		},
		http: server.Client(),
	}

	refreshToken := "myrefreshtoken"

	tokenResponse, err := client.RefreshToken(refreshToken)

	assert.NoError(t, err)
	assert.NotNil(t, tokenResponse)
	assert.Equal(t, tokenResponse.Access, "new_access")
	assert.NotEmpty(t, tokenResponse.Refresh, "new_refresh")
	assert.NotZero(t, tokenResponse.ExpiresIn, 3600)
}

func TestGetOfflineToken__OK(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`
				{
					"access_token": "new_access",
					"refresh_token": "new_refresh",
					"expires_in": 3600
				}
			`))
		}))
	defer server.Close()

	client := &KeycloakClient{
		KeycloakClientInputs: KeycloakClientInputs{
			KeycloakURL:  server.URL,
			Realm:        "test",
			ClientID:     "myclient",
			ClientSecret: "mysecret",
		},
		http: server.Client(),
	}

	userToken := "myusertoken"

	offlineToken, err := client.ExchangeToken(userToken, "offline_access")

	assert.NoError(t, err)
	assert.NotNil(t, offlineToken)
	assert.Equal(t, offlineToken.Access, "new_access")
	assert.NotEmpty(t, offlineToken.Refresh, "new_refresh")
	assert.NotZero(t, offlineToken.ExpiresIn, 3600)
}

func TestKeycloakClient_InspectToken_OK(t *testing.T) {
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

	client := &KeycloakClient{
		KeycloakClientInputs: KeycloakClientInputs{
			KeycloakURL:  server.URL,
			Realm:        "test",
			ClientID:     "myclient",
			ClientSecret: "mysecret",
		},
		http: server.Client(),
	}

	claims, err := client.IntrospectToken("accesstoken")

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, claims["username"], "jbloggs")
	assert.Equal(t, claims["active"], true)
}
