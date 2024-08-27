package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EO-DataHub/eodhp-auth-agent/internal/authn"
	"github.com/EO-DataHub/eodhp-auth-agent/internal/authz"
	"github.com/stretchr/testify/assert"
)

type AuthenticatorMock struct {
	result bool
	token  string
	err    error
	called bool
}

func (a *AuthenticatorMock) IsAuthenticated(w http.ResponseWriter,
	r *http.Request) (bool, *authn.Claims, error) {

	a.called = true
	if a.err != nil {
		return false, nil, a.err
	}
	w.Header().Set("Authorization", a.token)
	claims := &authn.Claims{Username: "test"}
	return a.result, claims, nil
}

type AuthorizerMock struct {
	result bool
	err    error
	called bool
}

func (a *AuthorizerMock) IsAuthorized(r *http.Request,
	body authz.OPARequestBody) (bool, error) {

	a.called = true
	if a.err != nil {
		return false, a.err
	}
	return a.result, nil
}

func TestAuthHandler_AuthnAndAuthz_OK(t *testing.T) {
	// Create the mocks
	jwtToken, err := authn.CreateJWTToken(
		authn.Claims{Username: "test"}, "secret",
	)
	if err != nil {
		t.Fatal(err)
	}
	authenticators := make([]Authenticator, 2)
	authenticators[0] = &AuthenticatorMock{err: authn.ErrInvalidHost}
	authenticators[1] = &AuthenticatorMock{result: true, token: jwtToken}
	authorizer := &AuthorizerMock{result: true}

	// Create the handler
	handler := AuthHandler(authenticators, authorizer)

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, authenticators[0].(*AuthenticatorMock).called)
	assert.True(t, authenticators[1].(*AuthenticatorMock).called)
	assert.True(t, authorizer.called)
}

func TestAuthHandler_NoAuthnButAuthz_OK(t *testing.T) {
	// Create the mocks
	authenticators := make([]Authenticator, 2)
	authenticators[0] = &AuthenticatorMock{err: authn.ErrInvalidHost}
	authenticators[1] = &AuthenticatorMock{result: false}
	authorizer := &AuthorizerMock{result: true}

	// Create the handler
	handler := AuthHandler(authenticators, authorizer)

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, authenticators[0].(*AuthenticatorMock).called)
	assert.True(t, authenticators[1].(*AuthenticatorMock).called)
	assert.True(t, authorizer.called)
}

func TestAuthHandler_NoAuthnOrAuthz_Unauthorized(t *testing.T) {
	// Create the mocks
	authenticators := make([]Authenticator, 2)
	authenticators[0] = &AuthenticatorMock{err: authn.ErrInvalidHost}
	authenticators[1] = &AuthenticatorMock{result: false}
	authorizer := &AuthorizerMock{result: false}

	// Create the handler
	handler := AuthHandler(authenticators, authorizer)

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.True(t, authenticators[0].(*AuthenticatorMock).called)
	assert.True(t, authenticators[1].(*AuthenticatorMock).called)
	assert.True(t, authorizer.called)
}

func TestAuthHandler_AuthnButNoAuthz_Forbidden(t *testing.T) {
	// Create the mocks
	jwtToken, err := authn.CreateJWTToken(
		authn.Claims{Username: "test"}, "secret",
	)
	if err != nil {
		t.Fatal(err)
	}
	authenticators := make([]Authenticator, 2)
	authenticators[0] = &AuthenticatorMock{err: authn.ErrInvalidHost}
	authenticators[1] = &AuthenticatorMock{result: true, token: jwtToken}
	authorizer := &AuthorizerMock{result: false}

	// Create the handler
	handler := AuthHandler(authenticators, authorizer)

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.True(t, authenticators[0].(*AuthenticatorMock).called)
	assert.True(t, authenticators[1].(*AuthenticatorMock).called)
	assert.True(t, authorizer.called)
}

func TestAuthHandler_FirstAuthnAndAuthz_OK(t *testing.T) {
	// Create the mocks
	jwtToken, err := authn.CreateJWTToken(
		authn.Claims{Username: "test"}, "secret",
	)
	if err != nil {
		t.Fatal(err)
	}
	authenticators := make([]Authenticator, 2)
	authenticators[0] = &AuthenticatorMock{result: true, token: jwtToken}
	authenticators[1] = &AuthenticatorMock{err: authn.ErrInvalidHost}
	authorizer := &AuthorizerMock{result: true}

	// Create the handler
	handler := AuthHandler(authenticators, authorizer)

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, authenticators[0].(*AuthenticatorMock).called)
	assert.False(t, authenticators[1].(*AuthenticatorMock).called)
	assert.True(t, authorizer.called)
}
