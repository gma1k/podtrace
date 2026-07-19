# USDT-instrumented workload. Built non-stripped so the .note.stapsdt notes and
# the .probes semaphore symbol survive for the agent's USDT scanner to discover.
FROM debian:12-slim AS build
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc systemtap-sdt-dev libc6-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY main.c ./
# No -s (keep symbols); the .note.stapsdt section is emitted regardless of -O.
RUN gcc -O2 -o /usdtdemo main.c && \
    readelf -n /usdtdemo | grep -A2 stapsdt

FROM debian:12-slim
COPY --from=build /usdtdemo /usdtdemo
ENTRYPOINT ["/usdtdemo"]
