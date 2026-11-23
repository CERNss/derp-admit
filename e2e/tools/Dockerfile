# e2etool: standard library only, so the build downloads no modules.
FROM golang:1.24.0 AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/e2etool .

FROM alpine:3.20
COPY --from=build /out/e2etool /usr/local/bin/e2etool
