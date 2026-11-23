# Builds derper from the tailscale module version pinned in go.mod.
# There is no usable published derper image (tailscale/derper and
# ghcr.io/tailscale/derper both refuse anonymous pulls), so compose builds it.
FROM golang:1.24 AS build
ARG TAILSCALE_VERSION=v1.84.3
RUN CGO_ENABLED=0 go install -trimpath -ldflags="-s -w" \
    tailscale.com/cmd/derper@${TAILSCALE_VERSION}

FROM alpine:3.20
RUN apk --no-cache add ca-certificates && \
    addgroup -S derper && adduser -S -G derper derper && \
    mkdir -p /var/lib/derper && chown derper:derper /var/lib/derper
COPY --from=build /go/bin/derper /usr/local/bin/derper
USER derper
EXPOSE 3340/tcp 3478/udp
ENTRYPOINT ["/usr/local/bin/derper"]
