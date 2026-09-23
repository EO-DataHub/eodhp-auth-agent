package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This is the exact bug that shipped: ParseUnverified accepted a token's claims without
// ever checking its signature was genuine, so anyone could hand-craft a token with
// whatever workspace/user claims they liked and use it directly against the
// token-management API. These tests exist to make that regression loud if it ever comes
// back.

func generateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return key
}

func signToken(t *testing.T, key *rsa.PrivateKey, aud string, extra map[string]any) string {
	t.Helper()

	claims := jwt.MapClaims{
		"sub": "test-user",
		"aud": aud,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	require.NoError(t, err)

	return token
}

func fixedKeyVerifier(key *rsa.PrivateKey) *Verifier {
	return NewVerifierWithKeyFunc(func(*jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})
}

func TestVerifierParseClaims_GenuinelySignedToken_IsAccepted(t *testing.T) {
	key := generateKey(t)
	verifier := fixedKeyVerifier(key)

	token := signToken(t, key, "eodh", map[string]any{
		"username": "geodowd",
	})

	claims := Claims{}
	err := verifier.ParseClaims(token, &claims)

	require.NoError(t, err)
	assert.Equal(t, "test-user", claims["sub"])
	assert.Equal(t, "geodowd", claims["username"])
}

func TestVerifierParseClaims_ForgedSignature_IsRejected(t *testing.T) {
	key := generateKey(t)
	verifier := fixedKeyVerifier(key)

	// A well-formed JWT (real header/payload) but with a signature that was never
	// produced by the private key - exactly what ParseUnverified used to accept.
	genuine := signToken(t, key, "eodh", nil)
	forged := genuine[:len(genuine)-4] + "AAAA"

	claims := Claims{}
	err := verifier.ParseClaims(forged, &claims)

	assert.ErrorIs(t, err, ErrInvalidJWT)
}

func TestVerifierParseClaims_SignedByADifferentKey_IsRejected(t *testing.T) {
	verifier := fixedKeyVerifier(generateKey(t))
	otherKey := generateKey(t)

	token := signToken(t, otherKey, "eodh", nil)

	claims := Claims{}
	err := verifier.ParseClaims(token, &claims)

	assert.ErrorIs(t, err, ErrInvalidJWT)
}

func TestVerifierParseClaims_WrongAudience_IsRejected(t *testing.T) {
	key := generateKey(t)
	verifier := fixedKeyVerifier(key)

	token := signToken(t, key, "some-other-client", nil)

	claims := Claims{}
	err := verifier.ParseClaims(token, &claims)

	assert.ErrorIs(t, err, ErrInvalidClaims)
}
