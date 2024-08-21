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

## Running the Server

```sh
go run cmd/main.go --config config.yaml
```

The server will start on port 8080.

To view command line options append `--help` to the run command.

### Configuration

Configuration is controlled via a configuration file. The path to this file must be passed in on the command line using the `--config` flag.

An example config file is included in this repo as _./example-config.yaml_.

## Building for Production

```sh
go build -a -o dist/auth-agent cmd/main.go
```

## Deployment

```sh
docker build -t auth-agent .
docker run -v /absolute/path/to/config.yaml:/app/config.yaml auth-agent --config /app/config.yaml
```

## Testing

Unit tests cover most of the key codebase. You can also run coverage tests and view results in html.

```sh
go test ./... -v  # run unit tests
go test -coverprofile=coverage.out ./...  # run unit tests and output coverage
go tool cover -html=coverage.out -o coverage.html  # generate html coverage report
```
