#!/bin/sh
# Generate a throwaway certificate and serve /srv over HTTP/3 on UDP 4433.
# Datagrams are held to QUIC's 1200-byte minimum with path MTU discovery off:
# a kind cluster's overlay network drops the larger ones the server would
# otherwise probe with, which stalls every response after the handshake.
set -eu
mkdir -p /srv /tls
echo ok >/srv/index.html
certtool --generate-privkey --key-type=ecdsa --outfile /tls/key.pem 2>/dev/null
printf 'cn = h3server\ndns_name = h3server\nexpiration_days = 2\nsigning_key\nencryption_key\n' >/tls/cert.cfg
certtool --generate-self-signed --load-privkey /tls/key.pem --template /tls/cert.cfg --outfile /tls/cert.pem 2>/dev/null
exec gtlsserver --htdocs=/srv --quiet --no-pmtud --max-udp-payload-size=1200 0.0.0.0 4433 /tls/key.pem /tls/cert.pem
