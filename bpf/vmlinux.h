/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal vmlinux.h fallback for environments without bpftool.
 * At build time the Makefile regenerates this from the running kernel's BTF
 * (bpftool btf dump file /sys/kernel/btf/vmlinux format c) when available.
 *
 * All primitive types (u8/u16/u32/u64, __u*, etc.) and all kernel structs
 * used by podtrace are defined locally in common.h, so this stub only needs
 * to forward-declare struct file (used as an opaque pointer in filesystem.c).
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

/* Forward declaration — accessed only via raw bpf_probe_read_kernel offsets,
 * never via BPF CO-RE field reads. */
struct file;

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
