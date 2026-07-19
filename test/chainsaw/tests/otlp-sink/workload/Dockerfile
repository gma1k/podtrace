# Minimal OTLP/HTTP sink that logs printable strings from trace bodies, for e2e.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -o /otlp-sink .

FROM gcr.io/distroless/static-debian12
COPY --from=build /otlp-sink /otlp-sink
ENTRYPOINT ["/otlp-sink"]
