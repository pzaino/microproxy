# syntax=docker/dockerfile:1.7

# Build stage (using golang:1.26.2-alpine-3.22)
FROM golang@sha256:7ef941168f213aa115df2e61364d67682129e99dc8188b734139dea862cc7d31 AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/microproxy ./cmd/microproxy

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

COPY --from=builder /out/microproxy /usr/local/bin/microproxy
COPY --from=builder /src/config.yaml /etc/microproxy/config.yaml

EXPOSE 8080 9090 9091 9092 9093 8081

ENTRYPOINT ["/usr/local/bin/microproxy"]
CMD ["-config", "/etc/microproxy/config.yaml", "-health-addr", ":9090"]
