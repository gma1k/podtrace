# USDT-instrumented workload. Built non-stripped so the .note.stapsdt notes and
# the .probes semaphore symbol survive for the agent's USDT scanner to discover.
FROM debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS build
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc systemtap-sdt-dev libc6-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY main.c ./
# No -s (keep symbols); the .note.stapsdt section is emitted regardless of -O.
RUN gcc -O2 -o /usdtdemo main.c && \
    readelf -n /usdtdemo | grep -A2 stapsdt

FROM debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
COPY --from=build /usdtdemo /usdtdemo
ENTRYPOINT ["/usdtdemo"]
