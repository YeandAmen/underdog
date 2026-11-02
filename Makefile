.PHONY: run build test check ui-test terminal worker

run:
	go run ./cmd/underdog serve

build:
	go build -trimpath -o bin/underdog ./cmd/underdog

terminal:
	go run ./cmd/underdog terminal

worker:
	go run ./cmd/underdog worker

test:
	go test -race ./...

check:
	go vet ./...
	npm run check:ui

ui-test:
	npm run test:ui
