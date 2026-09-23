package authn

import (
	"fmt"
	"slices"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// allowedAudiences are the Keycloak client IDs platform tokens are issued for (the audience
// mappers on the eodh and eodh-workspaces clients, eodhp-argocd-deployment
// apps/keycloak/base/realms.yaml). This list is duplicated across the platform's services,
// so change them together.
var allowedAudiences = []string{"eodh", "eodh-workspaces"}

// Verifier checks a JWT's signature against Keycloak's published key before trusting any
// claim in it. Use this, not the unverified ParseClaims, for any endpoint that accepts a
// bearer token directly from the client: nothing upstream has checked that token, and a
// gateway sitting in front of a service's public routes does not cover traffic that
// reaches it directly from elsewhere on the cluster network.
type Verifier struct {
	keyFunc jwt.Keyfunc
}

// NewVerifier builds a Verifier backed by the JWKS at certsURL, e.g.
// https://<keycloak-host>/realms/<realm>/protocol/openid-connect/certs. It fetches and
// caches the key set, refreshing it in the background for the life of the process, so
// verifying a token does not cost a round trip to Keycloak each time.
//
// A failed first fetch (e.g. Keycloak unreachable at boot) does not surface as an error
// here: the underlying keyfunc library swallows it and retries in the background, leaving
// the Verifier holding no keys (so the token API returns 401) until a refresh succeeds.
// This is deliberately not wired into /healthz: the same pod serves nginx's auth_request
// for every request on the platform, so failing health on a Keycloak blip would take the
// whole platform down rather than just the token API.
func NewVerifier(certsURL string) (*Verifier, error) {
	kf, err := keyfunc.NewDefault([]string{certsURL})
	if err != nil {
		return nil, fmt.Errorf("building JWKS keyfunc for %q: %w", certsURL, err)
	}

	return &Verifier{keyFunc: kf.Keyfunc}, nil
}

// NewVerifierWithKeyFunc builds a Verifier from an already-constructed jwt.Keyfunc,
// letting tests (and anything else that already has one) supply a fixed key rather than
// talking to a real JWKS endpoint.
func NewVerifierWithKeyFunc(keyFunc jwt.Keyfunc) *Verifier {
	return &Verifier{keyFunc: keyFunc}
}

// ParseClaims verifies token's signature and audience against Keycloak, then populates
// claims. Every authorisation decision built on these claims (workspace ownership, user
// ID) depends on this actually being checked here.
func (v *Verifier) ParseClaims(token string, claims jwt.Claims) error {
	t, err := jwt.ParseWithClaims(token, claims, v.keyFunc,
		jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !t.Valid {
		return ErrInvalidJWT
	}

	aud, err := claims.GetAudience()
	if err != nil || !hasAllowedAudience(aud) {
		return ErrInvalidClaims
	}

	return nil
}

func hasAllowedAudience(aud jwt.ClaimStrings) bool {
	for _, a := range aud {
		if slices.Contains(allowedAudiences, a) {
			return true
		}
	}
	return false
}
