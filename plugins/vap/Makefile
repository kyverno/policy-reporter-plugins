VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o vap-plugin .

.PHONY: test
test:
	go test ./... -race -cover

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	gofmt -l .

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: ko-build
ko-build:
	KO_DOCKER_REPO=ko.local ko build . --bare --tags $(VERSION)

.PHONY: ko-publish
ko-publish:
	ko build . --bare --tags $(VERSION) --platform=linux/amd64,linux/arm64
