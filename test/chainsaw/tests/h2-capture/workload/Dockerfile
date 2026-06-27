# Non-stripped build so the Go crypto/tls uprobe resolves symbols without the
# gopclntab path (we're validating decode here, not stripped-binary support).
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /h2demo .

FROM gcr.io/distroless/static-debian12
COPY --from=build /h2demo /h2demo
ENTRYPOINT ["/h2demo"]
