FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o articdbm-proxy .

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/articdbm-proxy .

ENV PROXY_PORT=8080 \
    METRICS_PORT=9090 \
    REDIS_ADDR=redis:6379 \
    MYSQL_ENABLED=true \
    MYSQL_PORT=3306 \
    POSTGRESQL_ENABLED=true \
    POSTGRESQL_PORT=5432 \
    MSSQL_ENABLED=true \
    MSSQL_PORT=1433 \
    MONGODB_ENABLED=true \
    MONGODB_PORT=27017 \
    REDIS_PROXY_ENABLED=true \
    REDIS_PROXY_PORT=6379 \
    SQL_INJECTION_DETECTION=true \
    MAX_CONNECTIONS=1000 \
    CONNECTION_TIMEOUT=30 \
    QUERY_TIMEOUT=60 \
    TLS_ENABLED=false \
    CLUSTER_MODE=false

EXPOSE 3306 5432 1433 27017 6379 8080 9090

CMD ["./articdbm-proxy"]