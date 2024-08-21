package keycloak

import (
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
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
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

func (k KeycloakClient) GetOfflineToken(user_token string) (*TokenResponse,
	error) {

	data := url.Values{}
	data.Set("client_id", k.ClientID)
	data.Set("client_secret", k.ClientSecret)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", user_token)

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
