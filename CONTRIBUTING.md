# Contributing to MicroProxy

Thanks for contributing to MicroProxy.

## Local quality checks (same as CI)

Before opening a pull request, run the same checks that run in CI:

```bash
go test ./...
go vet ./...
go test -race ./...
go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck ./...
go test -covermode=atomic -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

## Coverage threshold

CI enforces an initial total coverage threshold of **60%**. Pull requests that drop below this value will fail the `go-ci` check.

## Required branch protection checks

Repository maintainers should configure branch protection for the default branch (`main`) to require the `go-ci` status check before merge.

Suggested branch protection settings:

- Require a pull request before merging.
- Require status checks to pass before merging.
- Required check: `go-ci`.
