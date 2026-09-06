FROM golang:1.26.5-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/wl-regtest-server ./cmd/wl-regtest-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/wl-regtest-server /usr/local/bin/wl-regtest-server
ENV WL_DATA_DIR=/data
VOLUME /data
EXPOSE 10010
HEALTHCHECK --interval=5s --timeout=4s --start-period=10s CMD ["wl-regtest-server", "--healthcheck", "--listen=127.0.0.1:10010"]
ENTRYPOINT ["wl-regtest-server"]
