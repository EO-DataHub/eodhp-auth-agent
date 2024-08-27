package authn

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalClaims_Valid(t *testing.T) {
	data := []byte(`{
		"exp": 1724746200,
		"iat": 1724745600,
		"preferred_username": "test",
		"realm_access": {
			"roles": [
				"test_role_1",
				"test_role_2"
			]
		}
	}`)
	c := Claims{}
	err := json.Unmarshal(data, &c)
	assert.NoError(t, err)
	assert.Equal(t, int64(1724746200), c.ExpiresAt)
	assert.Equal(t, int64(1724745600), c.IssuedAt)
	assert.Equal(t, "test", c.Username)
	assert.Equal(t, "test_role_1", c.RealmAccess.Roles[0])
	assert.Equal(t, "test_role_2", c.RealmAccess.Roles[1])
}

func TestParseClaims_Valid(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjQ3NDYyMDAsImlhdCI6MTcyNDc0NTYwMCwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdCIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ0ZXN0X3JvbGVfMSIsInRlc3Rfcm9sZV8yIl19fQ.hgEEeQ9R_VPkHBTP1Co3PQdwCuNqWzU-UtkYrceHlvs"
	claims, err := ParseClaims(token)
	assert.NoError(t, err)
	assert.Equal(t, int64(1724746200), claims.ExpiresAt)
	assert.Equal(t, int64(1724745600), claims.IssuedAt)
	assert.Equal(t, "test", claims.Username)
	assert.Equal(t, "test_role_1", claims.RealmAccess.Roles[0])
	assert.Equal(t, "test_role_2", claims.RealmAccess.Roles[1])
}
