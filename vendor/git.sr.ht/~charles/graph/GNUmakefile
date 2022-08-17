include ./opinionated.mk

test:
> go test -timeout 30s ./...
.PHONY: test

fmt:
> go fmt ./...
.PHONY: fmt

lint:
> golint ./...
> errcheck ./...
> ineffassign ./
.PHONY: lint

coverage:
> go test -timeout 30s -coverprofile /dev/null ./...
.PHONY: coverage

viewcoverage:
> go test -timeout 30s -coverprofile cover.out ./...
> go tool cover -html=cover.out
.PHONY: viewcoverage

benchmark:
> go test -bench=.
.PHONY: benchmark
