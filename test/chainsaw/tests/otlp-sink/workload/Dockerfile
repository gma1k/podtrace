# Minimal OTLP/HTTP sink that logs printable strings from trace bodies, for e2e.
FROM golang:1.27.4-trixie@sha256:430985542100b871e108ccc00e8dcc5eef08ca14ee5825e98ebf563d8ffec4ee AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -o /otlp-sink .

FROM gcr.io/distroless/static-debian13:latest@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a
COPY --from=build /otlp-sink /otlp-sink
ENTRYPOINT ["/otlp-sink"]
