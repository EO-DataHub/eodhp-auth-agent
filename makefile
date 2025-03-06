# Default input parameters
go ?= go
docker ?= docker
image ?= public.ecr.aws/eodh/eodhp-auth-agent
version ?= 0.5.0-rc1

.SILENT:
MAKEFLAGS += --no-print-directory

.PHONY: test
test:
	$(go) test -coverprofile=coverage.out ./... && \
	$(go) tool cover -html=coverage.out -o coverage.html

.PHONY: container-build
container-build:
	$(docker) build -t $(image):$(version) .

.PHONY: container-push
container-push:
	$(docker) push $(image):$(version)

# Generate Swagger docs
.PHONY: docs
docs:
	swag init -g cmd/runserver.go

.PHONY: deploy
deploy: docs container-build container-push