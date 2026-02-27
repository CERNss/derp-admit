FROM --platform=$BUILDPLATFORM golang:1.25 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH:-amd64} \
    GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w" -o /out/derp-verifier ./cmd/derp_admit

FROM --platform=$TARGETPLATFORM gcr.io/distroless/static-debian12
COPY --from=build /out/derp-verifier /usr/local/bin/derp-verifier
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/derp-verifier"]
