// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_PROTOCOLS_H
#define PODTRACE_PROTOCOLS_H

/* === DEFAULT PROTOCOL PORTS === */
#define REDIS_DEFAULT_PORT      6379
#define MEMCACHED_DEFAULT_PORT  11211
#define KAFKA_DEFAULT_PORT      9092
#define GRPC_DEFAULT_PORT       50051

/* === FastCGI Record Types (RFC 3875 / FastCGI spec) === */
#define FCGI_VERSION_1       1
#define FCGI_BEGIN_REQUEST   1
#define FCGI_ABORT_REQUEST   2
#define FCGI_END_REQUEST     3
#define FCGI_PARAMS          4
#define FCGI_STDIN           5
#define FCGI_STDOUT          6
#define FCGI_STDERR          7

/* === HTTP/2 Frame Types (RFC 7540 §6) === */
#define HTTP2_DATA           0x0
#define HTTP2_HEADERS        0x1
#define HTTP2_PRIORITY       0x2
#define HTTP2_RST_STREAM     0x3
#define HTTP2_SETTINGS       0x4
#define HTTP2_GOAWAY         0x7

/* === HPACK Static Table Shortcuts (RFC 7541 Appendix B) === */
/* Indexed header representation: 0x80 | index */
#define HPACK_METHOD_GET     0x82   /* :method = GET  (index 2) */
#define HPACK_METHOD_POST    0x83   /* :method = POST (index 3) */
#define HPACK_PATH_SLASH     0x84   /* :path = /      (index 4) */

/* HTTP/2 client connection preface length */
#define HTTP2_PREFACE_LEN    24     /* "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" */

/* === FastCGI NV Pair Helpers === */
/* nameLen > 127 → 4-byte encoding with high bit set */
#define FCGI_NV_LEN_4BYTE    0x80

/* Minimum FastCGI record header size */
#define FCGI_HEADER_LEN      8

/* Max bytes to read from a PARAMS record for URI extraction */
#define FCGI_PARAMS_SCAN_LEN 200

#endif /* PODTRACE_PROTOCOLS_H */
