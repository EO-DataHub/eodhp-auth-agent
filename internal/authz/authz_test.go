//go:build !production

package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsAuthorized_Authorized(t *testing.T) {
	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"result": true}`)); err != nil {
				t.Fatalf("Failed to create response: %v", err)
			}
		}))
	defer server.Close()

	// Create a new authorizer
	a := NewAuthorizer(AuthorizerInputs{
		OPAClientURL: server.URL,
	})

	// Create a new request with an API token
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	isAuthorized, err := a.IsAuthorized(req, OPARequestBody{
		Input: OPARequestBodyInput{
			Authenticated: true,
		},
	})
	if err != nil {
		t.Fatalf("Failed to check authorization")
	}

	if !isAuthorized {
		t.Fatalf("Expected request to be authenticated")
	}
}

func TestIsAuthorized_Unauthorized(t *testing.T) {
	// Create a new test HTTP server
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"result": false}`)); err != nil {
				t.Fatalf("Failed to create response: %v", err)
			}
		}))
	defer server.Close()

	// Create a new authorizer
	a := NewAuthorizer(AuthorizerInputs{
		OPAClientURL: server.URL,
	})

	// Create a new request with an API token
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	isAuthorized, err := a.IsAuthorized(req, OPARequestBody{
		Input: OPARequestBodyInput{
			Authenticated: true,
		},
	})
	if err != nil {
		t.Fatalf("Failed to check authorization")
	}

	if isAuthorized {
		t.Fatalf("Expected request to be unauthenticated")
	}
}
