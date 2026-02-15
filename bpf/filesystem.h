// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_FILESYSTEM_H
#define PODTRACE_FILESYSTEM_H

#include "common.h"
#include "maps.h"

#define PT_FILE_OFFSET_F_PATH  8
#define PT_PATH_OFFSET_DENTRY  8

static inline int get_path_str_from_file(void *file, char *out_buf, u32 buf_size)
{
    if (file == NULL || out_buf == NULL || buf_size < 2)
        return 0;

    u64 dentry_ptr = 0;
    bpf_probe_read_kernel(&dentry_ptr, sizeof(dentry_ptr),
                         (void *)file + PT_FILE_OFFSET_F_PATH + PT_PATH_OFFSET_DENTRY);
    if (dentry_ptr == 0)
        return 0;

    out_buf[0] = '\0';
    return 0;
}

#endif

