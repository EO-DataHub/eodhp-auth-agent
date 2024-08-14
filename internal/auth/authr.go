package auth

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"
)

type opaRequestBody struct {
	Input struct {
		Username string   `json:"username"`
		Roles    []string `json:"roles"`
		Path     string   `json:"path"`
	} `json:"input"`
}

type opaResponseBody struct {
	Result bool `json:"result"`
}

type AuthorizerInputs struct {
	OPAClientURL string
}

type Authorizer struct {
	AuthorizerInputs
	client *http.Client
}

func NewAuthorizer(inputs AuthorizerInputs) Authorizer {
	return Authorizer{
		AuthorizerInputs: inputs,
		client:           &http.Client{},
	}
}

func (a Authorizer) IsAuthorized(r *http.Request, claims Claims) (bool, error) {
	logger := zerolog.Ctx(r.Context()).With().Str("authorizer", "OPA").Logger()

	// Create the OPA request body
	body := opaRequestBody{
		Input: struct {
			Username string   `json:"username"`
			Roles    []string `json:"roles"`
			Path     string   `json:"path"`
		}{
			Username: claims.Username,
			Roles:    claims.RealmAccess.Roles,
			Path:     r.URL.Path,
		},
	}

	// Create the authorization request
	authRequest, err := a.createAuthRequest(body)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create authorization request")
		return false, err
	}
	logger.Debug().Msg("Authentication request created")

	// Send the authorization request
	resp, err := a.client.Do(authRequest)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to send authorization request")
		return false, err
	}
	defer resp.Body.Close()

	// Unmarshal the response body
	var opaResp opaResponseBody
	err = json.NewDecoder(resp.Body).Decode(&opaResp)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to decode authorization response")
		return false, err
	}
	logger.Debug().Bool("result", opaResp.Result).
		Msg("Authorization response received")

	return opaResp.Result, nil
}

func (a Authorizer) createAuthRequest(
	body opaRequestBody) (*http.Request, error) {

	// Convert body variable into io.Reader
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader := bytes.NewReader(bodyBytes)

	// Create the authorization request
	authRequest, err := http.NewRequest("POST", a.OPAClientURL, bodyReader)
	if err != nil {
		return nil, err
	}

	return authRequest, nil
}
