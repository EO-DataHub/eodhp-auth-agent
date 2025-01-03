package authz

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"
)

type OPARequestBody struct {
	Input OPARequestBodyInput `json:"input"`
}

type OPARequestBodyInput struct {
	Username string   `json:"username"`
	Host     string   `json:"host"`
	Path     string   `json:"path"`
	Roles    []string `json:"roles"`
	Method   string   `json:"method"`
}

type opaResponseBody struct {
	Result bool `json:"result"`
}

type AuthorizerInputs struct {
	Name         string `yaml:"name"`
	OPAClientURL string `yaml:"opa_client_url"`
}

type Authorizer struct {
	AuthorizerInputs
	http *http.Client
}

func NewAuthorizer(inputs AuthorizerInputs) *Authorizer {
	return &Authorizer{
		AuthorizerInputs: inputs,
		http:             &http.Client{},
	}
}

func (a Authorizer) IsAuthorized(r *http.Request, body OPARequestBody) (bool,
	error) {

	logger := zerolog.Ctx(r.Context()).With().Str("authorizer", a.Name).Logger()

	// Create the authorization request
	authRequest, err := a.createAuthRequest(body)
	if err != nil {
		logger.Error().Err(err).Msg("failed to create authorization request")
		return false, err
	}
	logger.Debug().Msg("authorization request created")

	// Send the authorization request
	resp, err := a.http.Do(authRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to send authorization request")
		return false, err
	}
	defer resp.Body.Close()

	// Unmarshal the response body
	var opaResp opaResponseBody
	err = json.NewDecoder(resp.Body).Decode(&opaResp)
	if err != nil {
		logger.Error().Err(err).Msg("failed to decode authorization response")
		return false, err
	}
	logger.Debug().Interface("authz request", body).Bool("result",
		opaResp.Result).Msg("authorization response received")

	return opaResp.Result, nil
}

func (a Authorizer) createAuthRequest(body OPARequestBody) (*http.Request,
	error) {

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
