FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /identityshield ./cmd/identityshield

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && mkdir -p /app/data && chown -R 65532:65532 /app
WORKDIR /app
COPY --from=build /identityshield /usr/local/bin/identityshield
USER 65532:65532
ENV IDENTITYSHIELD_ADDR=0.0.0.0:8787 IDENTITYSHIELD_DATA_DIR=/app/data
EXPOSE 8787
ENTRYPOINT ["identityshield"]
CMD ["serve"]
