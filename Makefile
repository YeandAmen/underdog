.PHONY: run build test check ui-test

run:
	go run ./cmd/identityshield serve

build:
	go build -trimpath -o bin/identityshield ./cmd/identityshield

test:
	go test -race ./...

check:
	go vet ./...
	npm run check:ui

ui-test:
	npm run test:ui
