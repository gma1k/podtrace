# An HTTP/3 server that serves through libnghttp3, for the server side of
# podtrace's nghttp3 probes: ngtcp2's GnuTLS example server, built against
# Debian's shared libnghttp3 so the uprobes find it mapped like any
# distribution-packaged server would have it. ngtcp2's own libraries are
# linked in statically; the source is pinned to the v1.11.0 tag's commit.
FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential autoconf automake libtool pkg-config \
      libnghttp3-dev libgnutls28-dev libev-dev \
    && rm -rf /var/lib/apt/lists/*
ARG NGTCP2_COMMIT=94932c9a43b95f148da082654b220ceb19d45c32
RUN git init /src && cd /src \
    && git fetch --depth 1 https://github.com/ngtcp2/ngtcp2 "${NGTCP2_COMMIT}" \
    && git checkout --quiet FETCH_HEAD \
    && git submodule update --init --depth 1 \
    && autoreconf -i \
    && ./configure --with-gnutls --disable-shared --enable-static \
    && make -j"$(nproc)"

FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
RUN apt-get update && apt-get install -y --no-install-recommends \
      libnghttp3-9 libgnutls30t64 libev4t64 gnutls-bin \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/examples/gtlsserver /usr/local/bin/gtlsserver
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
