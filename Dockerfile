# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o gql-firewall ./cmd/server/

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/gql-firewall .
COPY --from=builder /app/opa-policies/ ./opa-policies/
COPY config/params.json ./config/

EXPOSE 8081 8082

ENTRYPOINT ["/app/gql-firewall"]
