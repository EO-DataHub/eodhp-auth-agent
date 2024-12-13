# Default input parameters
docker ?= docker
image ?= public.ecr.aws/n1b3o1k2/eodhp-auth-agent
version ?= 0.2.1

.SILENT:
MAKEFLAGS += --no-print-directory

.PHONY: build
build:
	$(docker) build -t $(image):$(version) .

.PHONY: publish
publish:
	$(docker) push $(image):$(version)