# EO DataHub Auth Agent

An API gateway to the EO DataHub to manage authentication and authorization requests.

## Getting Started

### Prerequisites

- Go 1.16 or higher

### Installation

Clone the repository:

```sh
git clone https://github.com/yourusername/eo-datahub-auth-agent.git
cd eo-datahub-auth-agent
```

## Usage

### Running the Server

```sh
go run main.go runserver --help
```

### Init DB

Before using a database it is necessary to create the tables. The initdb command can be used for this.

```sh
go run main.go initdb --help
```

### Token CLI

A CLI is provided for admin management of tokens. This requires the Keycloak client to have permission to impersonate users, which can be a security risk if client credentials are ever leaked, so implement with caution.

```sh
go run main.go token --help
```

### Configuration

Configuration is controlled via a configuration file. The default config location is _/etc/auth-agent/config.yaml_. If another config path is to be user then it must be passed in on the command line using the `--config` flag.

An example config file is included in this repo as _./example-config.yaml_.

The config file is templated against environment variables when it is loaded. This allows for passing in secret values at runtime. An example is given in _example-config.yaml_ for the postgres database source and the API secret.

### Authenticating

When querying the _/auth_ endpoint, either directly or via something like Nginx auth_request, the following headers can be included:

- "Cookie" - Used to pass in any browser cookies used for authentication with Oauth2 Proxy authentication
- "Authorization" - Used to authenticate via Bearer token to Oauth2 Proxy. Can be Keycloak JWT access token or Auth Agent API token.
- "X-Original-Host" - Used to override the auth request host for OPA policy authorization. Optional.
- "X-Original-URI" - Used to override the auth request path used for OPA policy authorization. Optional, but should almost always be set for correct behaviour.

## Building for Production

```sh
go build -a -o dist/auth-agent main.go
```

## Deployment

```sh
docker build -t auth-agent .
docker run -v /absolute/path/to/config.yaml:/etc/auth-agent/config.yaml auth-agent
```

## Testing

Unit tests cover most of the key codebase. You can also run coverage tests and view results in html.

```sh
go test ./... -v  # run unit tests
go test -coverprofile=coverage.out ./...  # run unit tests and output coverage
go tool cover -html=coverage.out -o coverage.html  # generate html coverage report
```
