# Minimal OTLP/HTTP sink that logs printable strings from trace bodies, for e2e.
FROM golang:1.25@sha256:fe5d57d3b718e7a4986bae156c2d73f44973bfd313073aed08a4de6692bb6161 AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -o /otlp-sink .

FROM gcr.io/distroless/static-debian12@sha256:a9fcaedd4c9b59e12dd65d954f0b5044f19b0647a8a3712e77205df9e7b102cd
COPY --from=build /otlp-sink /otlp-sink
ENTRYPOINT ["/otlp-sink"]
