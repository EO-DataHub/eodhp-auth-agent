package keycloak

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/rs/zerolog"
)

type KeycloakClientInputs struct {
	KeycloakURL  string `yaml:"keycloak_url"`
	Realm        string `yaml:"realm"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

type KeycloakClient struct {
	KeycloakClientInputs
	http *http.Client
	log  *zerolog.Logger
}

func NewKeycloakClient(inputs KeycloakClientInputs) *KeycloakClient {
	logger := zerolog.New(os.Stdout).With().
		Str("name", "Keycloak Client").Logger()

	return &KeycloakClient{
		KeycloakClientInputs: inputs,
		http:                 &http.Client{},
		log:                  &logger,
	}
}

type TokenResponse struct {
	Access    string `json:"access_token"`
	Refresh   string `json:"refresh_token"`
	ExpiresIn int    `json:"expires_in"`
}

func (k KeycloakClient) RefreshToken(refreshToken string) (*TokenResponse,
	error) {

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", k.ClientID)
	data.Set("client_secret", k.ClientSecret)

	resp, err := k.http.PostForm(
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
			k.KeycloakURL, k.Realm), data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to refresh token, status code: %d",
			resp.StatusCode)
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}

func (k KeycloakClient) GetOfflineToken(accessToken string) (*TokenResponse,
	error) {

	data := url.Values{}
	data.Set("client_id", k.ClientID)
	data.Set("client_secret", k.ClientSecret)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", accessToken)
	data.Set("scope", "offline_access")

	resp, err := k.http.PostForm(
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
			k.KeycloakURL, k.Realm), data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to exchange token, status code: %d",
			resp.StatusCode)
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}

func (k KeycloakClient) GetClientCredentials() (*TokenResponse, error) {
	// Create the request
	formData := url.Values{
		"grant_type": {"client_credentials"},
	}
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
			k.KeycloakURL, k.Realm), bytes.NewBufferString(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(k.ClientID, k.ClientSecret)

	// Send the request
	resp, err := k.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"failed to get client credentials, status code: %d",
			resp.StatusCode)
	}

	// Decode the response
	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}

func (k KeycloakClient) ImpersonateUser(accessToken, subject string) (
	*TokenResponse, error) {

	// Create the request
	data := url.Values{}
	data.Set("client_id", k.ClientID)
	data.Set("client_secret", k.ClientSecret)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("reuqested_token_type",
		"urn:ietf:params:oauth:token-type:access_token")
	data.Set("requested_subject", subject)
	data.Set("scope", "openid")

	// Send the request
	resp, err := k.http.PostForm(
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
			k.KeycloakURL, k.Realm), data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to impersonate user, status code: %d",
			resp.StatusCode)
	}

	// Decode the response
	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}
