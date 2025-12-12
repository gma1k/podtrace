#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

/* Basic type definitions */
typedef signed char __s8;
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

enum {
	false = 0,
	true = 1,
};

typedef long int __kernel_long_t;
typedef long unsigned int __kernel_ulong_t;
typedef int __kernel_pid_t;
typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_long_t __kernel_ssize_t;
typedef long long int __kernel_loff_t;
typedef long long int __kernel_time64_t;
typedef __kernel_long_t __kernel_clock_t;
typedef int __kernel_timer_t;
typedef int __kernel_clockid_t;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;
typedef unsigned int __poll_t;
typedef u32 __kernel_dev_t;
typedef __kernel_dev_t dev_t;
typedef short unsigned int umode_t;
typedef __kernel_pid_t pid_t;
typedef __kernel_clockid_t clockid_t;
typedef _Bool bool;
typedef __kernel_uid32_t uid_t;
typedef __kernel_gid32_t gid_t;
typedef long unsigned int uintptr_t;
typedef __kernel_loff_t loff_t;
typedef __kernel_size_t size_t;
typedef __kernel_ssize_t ssize_t;

/* Minimal kernel structures needed for compilation */
/* NOTE: This is a placeholder. For full CO-RE support, generate vmlinux.h from BTF:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
 */

struct list_head {
	struct list_head *next, *prev;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_bl_node {
	struct hlist_bl_node *next, **pprev;
};

struct hlist_bl_head {
	struct hlist_bl_head *first;
};

struct qstr {
	union {
		struct {
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

/* Forward declarations */
struct vfsmount;
struct inode;
struct dentry;
struct file_operations;
struct dentry_operations;
struct super_block;
struct cred;
struct pid;
struct mutex;
struct spinlock;
struct atomic_long_t;
struct file_ra_state;
struct fown_struct;
struct callback_head;
struct llist_node;
struct lockref;
struct wait_queue_head;
struct seqcount_spinlock_t;

/* Minimal definitions for structures */
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct file {
	union {
		struct llist_node *f_llist;
		struct callback_head *f_rcuhead;
		unsigned int f_iocb_flags;
	};
	struct path f_path;
	struct inode *f_inode;
	const struct file_operations *f_op;
	void *f_lock;
	void *f_count;
	unsigned int f_flags;
	unsigned int f_mode;
	void *f_pos_lock;
	loff_t f_pos;
	struct fown_struct *f_owner;
	const struct cred *f_cred;
	struct file_ra_state *f_ra;
	u64 f_version;
	void *f_security;
	void *private_data;
};

struct dentry {
	unsigned int d_flags;
	void *d_seq;
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	unsigned char d_iname[32];
	void *d_lockref;
	const struct dentry_operations *d_op;
	struct super_block *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		struct wait_queue_head *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union {
		struct hlist_node d_alias;
		struct hlist_node d_u;
	};
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
