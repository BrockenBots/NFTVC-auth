FROM golang:1.22.3-alpine AS builder

WORKDIR /app

COPY . .

ARG APP_PORT
ENV APP_PORT=8081

RUN go mod tidy

RUN go build -o main ./main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/pkg/config ./pkg/config
COPY --from=builder /app/certs ./certs/
COPY --from=builder /app .env

EXPOSE 8081

CMD ["./main"]