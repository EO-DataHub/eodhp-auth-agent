# Default input parameters
docker ?= docker
image ?= public.ecr.aws/n1b3o1k2/eodhp-auth-agent
version ?= 0.2.0

.SILENT:
MAKEFLAGS += --no-print-directory

.PHONY: build
docker-build:
	$(docker) build -t $(image):$(version) .

.PHONY: publish
docker-publish:
	$(docker) push $(image):$(version)