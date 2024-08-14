package auth

import "net/http"

type Authorizer struct {
	// Not implemented yet
}

func NewAuthorizer() Authorizer {
	// Not implemented yet
	return Authorizer{}
}

func (a Authorizer) IsAuthorized(r *http.Request, claims Claims) bool {
	// Not implemented yet
	return true
}
