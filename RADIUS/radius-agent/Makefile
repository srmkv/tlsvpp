.PHONY: deps build run clean

deps:
	go mod tidy

build: deps
	go build -o radius-agent ./cmd/radius-agent

run: build
	./radius-agent

clean:
	rm -f radius-agent
