export GOEXPERIMENT=jsonv2

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo master)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

install:
	go install -ldflags "$(LDFLAGS)" .

build:
	go build -ldflags "$(LDFLAGS)" ./...

test:
	go test ./...

lint:
	golangci-lint run

all: build test lint

auth0-setup:
	./scripts/setup-auth0.sh
