// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_FILESYSTEM_H
#define PODTRACE_FILESYSTEM_H

#include "common.h"
#include "maps.h"

/*
 * get_path_str_from_file — extract the filename from a kernel struct file *.
 *
 * When built with full kernel BTF (PODTRACE_VMLINUX_FROM_BTF), uses BPF CO-RE
 * to read file->f_path.dentry->d_name.name — gives at minimum the basename.
 * Full path traversal is not verifier-safe from kprobe context without BTF.
 *
 * Without BTF (minimal vmlinux.h fallback): returns 0 / empty string.
 */
static inline int get_path_str_from_file(struct file *file, char *out_buf, u32 buf_size)
{
    if (!file || !out_buf || buf_size < 2) {
        if (out_buf && buf_size > 0) out_buf[0] = '\0';
        return 0;
    }

#ifdef PODTRACE_VMLINUX_FROM_BTF
    const unsigned char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (!name) {
        out_buf[0] = '\0';
        return 0;
    }
    int ret = bpf_probe_read_kernel_str(out_buf, buf_size, name);
    return ret > 1 ? 1 : 0;
#else
    out_buf[0] = '\0';
    return 0;
#endif
}

#endif

