/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal vmlinux.h fallback for environments without bpftool.
 * At build time the Makefile regenerates a kernel-specific header into
 * bpf/.generated/vmlinux.h when kernel BTF is available.
 *
 * All primitive types (u8/u16/u32/u64, __u*, etc.) and kernel structs used by
 * podtrace are defined locally in common.h, so this fallback only needs to
 * forward-declare struct file (used as an opaque pointer in filesystem.c).
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

struct file;

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
