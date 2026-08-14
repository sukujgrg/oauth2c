export GOEXPERIMENT=jsonv2

install:
	go install .

build:
	go build ./...

test:
	go test ./...

lint:
	golangci-lint run

all: build test lint

auth0-setup:
	./scripts/setup-auth0.sh
