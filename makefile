# Default input parameters
go ?= go
docker ?= docker
image ?= public.ecr.aws/eodh/eodhp-auth-agent
version ?= 0.5.0-debug1
path ?= migrations
port ?= 8080
loglevel ?= info

.SILENT:
MAKEFLAGS += --no-print-directory

.PHONY: build
build:
	$(go) build -o dist/auth-agent main.go

.PHONY: run
run:
	$(go) run main.go runserver --config=$(config) --port=$(port) \
		--log $(loglevel)

.PHONY: migrate
migrate:
	$(go) run main.go migrate --config=$(config)

.PHONY: test
test:
	$(go) test -coverprofile=coverage.out ./... && \
	$(go) tool cover -html=coverage.out -o coverage.html

.PHONY: docs
docs:
	swag init -g cmd/runserver.go

.PHONY: container-build
container-build:
	$(docker) build -t $(image):$(version) .

.PHONY: container-push
container-push:
	$(docker) push $(image):$(version)

.PHONY: container-run
container-run:
	$(docker) run  --rm \
		--mount type=bind,source=$(PWD)/$(config),target=/etc/auth-agent/config.yaml \
		$(image):$(version) runserver --port=$(port) --log $(loglevel) \
		--config=/etc/auth-agent/config.yaml 
		

.PHONY: deploy
deploy: docs container-build container-push