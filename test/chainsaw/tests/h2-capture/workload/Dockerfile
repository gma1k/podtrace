# Non-stripped build so the Go crypto/tls uprobe resolves symbols without the
# gopclntab path (we're validating decode here, not stripped-binary support).
FROM golang:1.27.3-trixie@sha256:2336eda24930976591abea806d9b7d99eeae38238f19755c5deec02facdc1594 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /h2demo .

FROM gcr.io/distroless/static-debian13@sha256:448810357cc8e67b7208988abdba0f5ec3d3aebee0a5b13eb624979792cffc0f
COPY --from=build /h2demo /h2demo
ENTRYPOINT ["/h2demo"]
