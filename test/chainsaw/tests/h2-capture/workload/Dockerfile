# Non-stripped build so the Go crypto/tls uprobe resolves symbols without the
# gopclntab path (we're validating decode here, not stripped-binary support).
FROM golang:1.27.4-trixie@sha256:0f82c58710c405cc012da2fbd2b04bde9ced20392a89f66062822d711d7d6b4b AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /h2demo .

FROM gcr.io/distroless/static-debian13:latest@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a
COPY --from=build /h2demo /h2demo
ENTRYPOINT ["/h2demo"]
