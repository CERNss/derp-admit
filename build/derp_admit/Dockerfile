FROM golang:1.25 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/derp-verifier ./cmd/derp_admit

FROM gcr.io/distroless/base-debian12
COPY --from=build /out/derp-verifier /usr/local/bin/derp-verifier
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/derp-verifier"]
