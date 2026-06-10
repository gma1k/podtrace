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

/* Max bytes to read from a PARAMS record for URI extraction.
 * Kept at 128 to bound the nested loop verifier instruction count on
 * strict 6.x kernels (verifier limit = 1M processed instructions). */
#define FCGI_PARAMS_SCAN_LEN 128

#ifdef PODTRACE_VMLINUX_FROM_BTF
/* Resolve the user-space data pointer behind a struct msghdr, handling both
 * iov_iter shapes: ITER_IOVEC (writev/sendmsg with an iovec array) and
 * ITER_UBUF (plain send()/write(), kernels >= 6.0, where the union member is
 * the buffer pointer itself, not a pointer to an iovec). Shared by the
 * FastCGI and gRPC inspectors — gRPC used to read msg_iter.__iov
 * unconditionally, which on >= 6.0 either missed plain send() entirely or
 * scanned a garbage pointer. */
static __always_inline void *msghdr_user_base(struct msghdr *msg, u64 *avail)
{
	if (!msg)
		return NULL;
	u8 it = BPF_CORE_READ(msg, msg_iter.iter_type);
	if (it == ITER_UBUF) {
		void *ubuf = (void *)BPF_CORE_READ(msg, msg_iter.ubuf);
		size_t count = BPF_CORE_READ(msg, msg_iter.count);
		size_t off = BPF_CORE_READ(msg, msg_iter.iov_offset);
		if (avail)
			*avail = count;
		if (!ubuf)
			return NULL;
		return (u8 *)ubuf + off;
	}
	if (it == ITER_IOVEC) {
		const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
		if (!iov)
			return NULL;
		struct iovec iov_entry;
		if (bpf_probe_read_kernel(&iov_entry, sizeof(iov_entry), iov) != 0)
			return NULL;
		if (avail)
			*avail = iov_entry.iov_len;
		return iov_entry.iov_base;
	}
	return NULL;
}

static __always_inline int read_msghdr_data(struct msghdr *msg, void *buf, u32 buf_size)
{
	if (!buf || buf_size == 0)
		return -1;
	u64 avail = 0;
	void *base = msghdr_user_base(msg, &avail);
	if (!base || avail < buf_size)
		return -1;
	return bpf_probe_read_user(buf, buf_size, base);
}
#endif /* PODTRACE_VMLINUX_FROM_BTF */

#endif /* PODTRACE_PROTOCOLS_H */
