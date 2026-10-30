# Version shown by the program: the git tag (v0.0.1), a commit after a tag
# (v0.0.1-3-gabc1234) or just the commit, with -dirty for uncommitted changes.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)

.PHONY: build test clean

build:
	@echo "building iptables-tui $(VERSION)"
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o iptables-tui .
	@./iptables-tui -version

test:
	go test ./...

clean:
	rm -f iptables-tui
