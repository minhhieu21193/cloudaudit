VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/minhhieu21193/cloudaudit/cmd.version=$(VERSION)

.PHONY: build test vet lint check demo clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/cloudaudit .

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run

check: vet test lint

# Regenerates the committed sample reports from built-in fake data (no AWS access).
demo: build
	./bin/cloudaudit scan --demo --format html --out examples/sample-report.html
	./bin/cloudaudit scan --demo --format md --out examples/sample-report.md

clean:
	rm -rf bin dist
