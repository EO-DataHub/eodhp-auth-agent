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
		"username": "test"
	}`)
	claims := Claims{}
	err := json.Unmarshal(data, &claims)
	assert.NoError(t, err)
	assert.Equal(t, float64(1724746200), claims["exp"].(float64))
	assert.Equal(t, float64(1724745600), claims["iat"].(float64))
	assert.Equal(t, "test", claims["username"])
}

func TestParseClaims_Valid(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjQ3NDYyMDAsImlhdCI6MTcyNDc0NTYwMCwidXNlcm5hbWUiOiJ0ZXN0In0.Bo2W5yxwru0F4fd1-7Vt9U7ec9jwpCzSxqlJ9uhJMnA"
	claims := Claims{}
	err := ParseClaims(token, &claims)
	assert.NoError(t, err)
	assert.Equal(t, float64(1724746200), claims["exp"].(float64))
	assert.Equal(t, float64(1724745600), claims["iat"].(float64))
	assert.Equal(t, "test", claims["username"])
}
