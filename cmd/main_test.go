package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	c, err := loadConfig("../example_config.yaml")

	assert.NoError(t, err)
	assert.Equal(t, 2, len(c.Authenticators))
	assert.Equal(t, "example authenticator", c.Authenticators[0].Name)
	assert.Equal(t, "https://example.com/auth", c.Authenticators[0].AuthURL)
	assert.Equal(t, "GET", c.Authenticators[0].AuthMethod)
	assert.Equal(t, "cookie_1", c.Authenticators[0].CookieName)
	assert.Equal(t, 2, len(c.Authenticators[0].Domains))
	assert.Equal(t, "example.com", c.Authenticators[0].Domains[0])
	assert.Equal(t, "*.example.com", c.Authenticators[0].Domains[1])
	assert.Equal(t, "test authenticator", c.Authenticators[1].Name)
	assert.Equal(t, "https://test.com/auth", c.Authenticators[1].AuthURL)
	assert.Equal(t, "GET", c.Authenticators[1].AuthMethod)
	assert.Equal(t, "cookie_2", c.Authenticators[1].CookieName)
	assert.Equal(t, 2, len(c.Authenticators[1].Domains))
	assert.Equal(t, "test.com", c.Authenticators[1].Domains[0])
	assert.Equal(t, "*.test.com", c.Authenticators[1].Domains[1])
	assert.Equal(t, "http://localhost:8181/v1/data/authz/allow",
		c.Authorizer.OPAClientURL)
	assert.Equal(t, "http://localhost:8080/auth", c.Keycloak.KeycloakURL)
	assert.Equal(t, "myrealm", c.Keycloak.Realm)
	assert.Equal(t, "myclient", c.Keycloak.ClientID)
	assert.Equal(t, "mysecret", c.Keycloak.ClientSecret)
	assert.Equal(t, "sqlite3", c.Database.Driver)
	assert.Equal(t, "./db.sqlite3", c.Database.Source)
	assert.Equal(t, "ABCD", c.ApiTokenPrefix)
}
