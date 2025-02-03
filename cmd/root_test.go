package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	os.Setenv("API_SECRET", "secret")
	c, err := loadConfig("../example-config.yaml")

	assert.NoError(t, err)
	assert.Equal(t, 2, len(c.AuthStrategies))
	assert.Equal(t, "example authenticator", c.AuthStrategies[0].Name)
	assert.Equal(t, 2, len(c.AuthStrategies[0].Domains))
	assert.Equal(t, "example.com", c.AuthStrategies[0].Domains[0])
	assert.Equal(t, "*.example.com", c.AuthStrategies[0].Domains[1])
	assert.Equal(t, "https://example.com/auth", c.AuthStrategies[0].AuthenticationURL)
	assert.Equal(t, "http://localhost:8181/v1/data/example/allow",
		c.AuthStrategies[0].AuthorizationURL)
	assert.Equal(t, "test authenticator", c.AuthStrategies[1].Name)
	assert.Equal(t, 2, len(c.AuthStrategies[1].Domains))
	assert.Equal(t, "test.com", c.AuthStrategies[1].Domains[0])
	assert.Equal(t, "*.test.com", c.AuthStrategies[1].Domains[1])
	assert.Equal(t, "https://test.com/auth", c.AuthStrategies[1].AuthenticationURL)
	assert.Equal(t, "http://localhost:8181/v1/data/test/allow",
		c.AuthStrategies[1].AuthorizationURL)
	assert.Equal(t, "http://localhost:8080/auth", c.Keycloak.KeycloakURL)
	assert.Equal(t, "myrealm", c.Keycloak.Realm)
	assert.Equal(t, "myclient", c.Keycloak.ClientID)
	assert.Equal(t, "mysecret", c.Keycloak.ClientSecret)
	assert.Equal(t, "sqlite3", c.Database.Driver)
	assert.Equal(t, "./db.sqlite3", c.Database.Source)
	assert.Equal(t, "ABCD", c.APIToken.Prefix)
	assert.Equal(t, "secret", c.APIToken.Secret)
	assert.Equal(t, int16(5), c.APIToken.AccessTokenExpiryMargin)
}

func TestLoadEnvVars(t *testing.T) {
	os.Setenv("VAR1", "value1")
	os.Setenv("VAR2", "value2")

	envVars := loadEnvVars()

	assert.Equal(t, "value1", envVars["VAR1"])
	assert.Equal(t, "value2", envVars["VAR2"])
}
