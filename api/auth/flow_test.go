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
	err    error
	called bool
}

func (a *AuthenticatorMock) IsAuthenticated(w http.ResponseWriter,
	r *http.Request) (bool, *authn.Claims, error) {

	a.called = true
	if a.err != nil {
		return false, nil, a.err
	}
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

func TestProcessRequest_AuthnAndAuthz_OK(t *testing.T) {
	// Create the mocks
	authenticator := &AuthenticatorMock{result: true}
	authorizer := &AuthorizerMock{result: true}

	// Create the flow
	flow := AuthFlow{
		AuthFlowInputs: AuthFlowInputs{
			Name: "test",
		},
		authn: authenticator,
		authz: authorizer,
	}

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	isAuthenticated, isAuthorized := flow.ProcessRequest(w, r)

	// Check results
	assert.True(t, isAuthenticated)
	assert.True(t, isAuthorized)
	assert.True(t, authenticator.called)
	assert.True(t, authorizer.called)
}

func TestProcessRequest_NoAuthnAndAuthz_Unauthorized(t *testing.T) {
	// Create the mocks
	authenticator := &AuthenticatorMock{result: false}
	authorizer := &AuthorizerMock{result: true}

	// Create the flow
	flow := AuthFlow{
		AuthFlowInputs: AuthFlowInputs{
			Name: "test",
		},
		authn: authenticator,
		authz: authorizer,
	}

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	isAuthenticated, isAuthorized := flow.ProcessRequest(w, r)

	// Check results
	assert.False(t, isAuthenticated)
	assert.True(t, isAuthorized)
	assert.True(t, authenticator.called)
	assert.True(t, authorizer.called)
}

func TestProcessRequest_AuthnAndNoAuthz_Forbidden(t *testing.T) {
	// Create the mocks
	authenticator := &AuthenticatorMock{result: true}
	authorizer := &AuthorizerMock{result: false}

	// Create the flow
	flow := AuthFlow{
		AuthFlowInputs: AuthFlowInputs{
			Name: "test",
		},
		authn: authenticator,
		authz: authorizer,
	}

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	isAuthenticated, isAuthorized := flow.ProcessRequest(w, r)

	// Check results
	assert.True(t, isAuthenticated)
	assert.False(t, isAuthorized)
	assert.True(t, authenticator.called)
	assert.True(t, authorizer.called)
}

func TestProcessRequest_NoAuthnAndNoAuthz_Unauthorized(t *testing.T) {
	// Create the mocks
	authenticator := &AuthenticatorMock{result: false}
	authorizer := &AuthorizerMock{result: false}

	// Create the flow
	flow := AuthFlow{
		AuthFlowInputs: AuthFlowInputs{
			Name: "test",
		},
		authn: authenticator,
		authz: authorizer,
	}

	// Setup request and response
	r := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	// Call the handler
	isAuthenticated, isAuthorized := flow.ProcessRequest(w, r)

	// Check results
	assert.False(t, isAuthenticated)
	assert.False(t, isAuthorized)
	assert.True(t, authenticator.called)
	assert.True(t, authorizer.called)
}

func TestIsHostAllowed_AllowedSpecific_True(t *testing.T) {
	// Create a new authenticator
	a, err := NewAuthFlow(AuthFlowInputs{
		Domains: []string{"test.com", "*.test.com"},
	}, nil, nil)
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}

	isAllowed := a.IsHostAllowed("test.com")
	assert.True(t, isAllowed)
}

func TestIsHostAllowed_AllowedWildcard_True(t *testing.T) {
	// Create a new authenticator
	a, err := NewAuthFlow(AuthFlowInputs{
		Domains: []string{"*"},
	}, nil, nil)
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}

	isAllowed := a.IsHostAllowed("test.com")
	assert.True(t, isAllowed)
}

func TestIsHostAllowed_NotAllowed_False(t *testing.T) {
	// Create a new authenticator
	a, err := NewAuthFlow(AuthFlowInputs{
		Domains: []string{"test.com", "*.test.com"},
	}, nil, nil)
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}

	isAllowed := a.IsHostAllowed("example.com")
	assert.False(t, isAllowed)
}

func TestIsHostAllowed_HostAllowedPartialWildcard_True(t *testing.T) {
	// Create a new authenticator
	a, err := NewAuthFlow(AuthFlowInputs{
		Domains: []string{"test.com", "*.test.com"},
	}, nil, nil)
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}

	isAllowed := a.IsHostAllowed("sub.test.com")
	assert.True(t, isAllowed)
}
