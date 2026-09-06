FROM golang:1.26.5-bookworm AS build
ARG LND_COMMIT=8ea98fd522683648144dd4f0f014fce80e311630
WORKDIR /src
RUN git init && git remote add origin https://github.com/lightningnetwork/lnd.git && \
    git fetch --depth=1 origin "$LND_COMMIT" && git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "$LND_COMMIT"
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath \
    -tags='signrpc walletrpc chainrpc invoicesrpc routerrpc' -o /out/lnd ./cmd/lnd && \
    CGO_ENABLED=0 go build -mod=readonly -trimpath \
    -tags='signrpc walletrpc chainrpc invoicesrpc routerrpc' -o /out/lncli ./cmd/lncli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/lnd /out/lncli /usr/local/bin/
ENTRYPOINT ["lnd"]
