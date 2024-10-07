FROM golang:1.17 AS builder

WORKDIR /go/src/github.com/your-org/https-logger
COPY . .

RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o https-logger .

# Create final plugin image
FROM alpine:3.14

WORKDIR /plugins
COPY --from=builder /go/src/github.com/your-org/https-logger/https-logger /plugins/https-logger

CMD ["/plugins/https-logger"]
