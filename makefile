# Default input parameters
go ?= go
docker ?= docker
image ?= public.ecr.aws/n1b3o1k2/eodhp-auth-agent
version ?= 0.2.2

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