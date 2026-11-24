/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SYSCALL_TRACE_H
#define _UAPI_LINUX_SYSCALL_TRACE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define SCT_EVENT_MAGIC 0x53544345 /* STCE */
#define SCT_EVENT_VERSION 2

/* Records describe AArch64 syscalls only; compat syscalls are skipped. */
#define SCT_EVENT_F_CAPTURE_FAULT (1U << 0)
#define SCT_EVENT_F_OUTPUT_LENGTH_UNAVAILABLE (1U << 1)
#define SCT_BLOB_F_FAULT (1U << 0)

#define SCT_FLAG_ENABLED	(1U << 0)
#define SCT_FLAG_TRACE_ENTER	(1U << 1)
#define SCT_FLAG_TRACE_EXIT	(1U << 2)
#define SCT_FLAG_CAPTURE_STACK	(1U << 3)

#define SCT_RETFILTER_ANY 0U
#define SCT_RETFILTER_OK  (1U << 0)  /* keep events with ret >= 0 */
#define SCT_RETFILTER_ERR (1U << 1)  /* keep events with ret <  0 */

#define SCT_FILTER_ANY_U32 ((__u32)~0U)
#define SCT_FILTER_ANY_S32 ((__s32)-1)
#define SCT_MAX_NR_FILTERS 32U
#define SCT_MAX_CAPTURE_RULES 32U

enum sct_event_type {
	SCT_EV_ENTER = 1,
	SCT_EV_EXIT = 2,
	SCT_EV_LOST = 3,
};

enum sct_blob_kind {
	SCT_BLOB_USER_STACK = 1,
	SCT_BLOB_USER_STRING = 2,
	SCT_BLOB_USER_BYTES = 3,
	SCT_BLOB_SOCKADDR = 4,
};

struct sct_config {
	__u32 flags;
	__u32 stack_bytes;
	__u32 target_tgid;	/* SCT_FILTER_ANY_U32 for all, owner tgid is skipped */
	__u32 target_uid;	/* SCT_FILTER_ANY_U32 for all */
	__s32 syscall_nr;	/* SCT_FILTER_ANY_S32 for all */
	__u32 ret_filter;	/* SCT_RETFILTER_* mask, applied to EXIT events */
};

/*
 * Generic capture rule: for syscall @nr, capture argument @arg_index using
 * blob @kind (see enum sct_blob_kind), up to @max_len bytes.
 * Argument rules apply to ENTER and override built-in capture for that arg.
 * max_len == 0 selects the kind's limit for arguments, and disables a stack
 * rule. Duplicate (nr, arg_index) or stack rules for one nr are invalid.
 *
 * A rule with kind == SCT_BLOB_USER_STACK captures the user stack window
 * (from user_sp, @max_len bytes) for that syscall instead of an argument.
 */
struct sct_capture_rule {
	__s32 nr;
	__u16 arg_index;
	__u16 kind;
	__u32 max_len;
};

struct sct_capture_rules {
	__u32 count;		/* 0 disables rule-based capture */
	__u32 reserved;
	struct sct_capture_rule rules[SCT_MAX_CAPTURE_RULES];
};

struct sct_nr_filter {
	__u32 count;		/* 0 disables list filtering */
	__u32 reserved;
	__s32 nr[SCT_MAX_NR_FILTERS];
};

struct sct_event_header {
	__u32 magic;
	__u16 version;
	__u16 type;
	__u32 size;
	__u32 flags;

	__u64 seq;
	__u64 ts_ns;

	__u32 cpu;
	__u32 pid;
	__u32 tid;
	__u32 uid;

	char comm[16];

	__s32 nr;
	__s64 ret;
	__u64 args[6];

	__u64 user_pc;
	__u64 user_sp;
	__u64 user_fp;
	__u64 user_lr;

	__u32 blob_count;
	__u32 blob_off;
	__u32 lost_before;	/* events dropped before this one */
};

struct sct_blob {
	__u16 kind;
	__u16 flags;
	__u16 arg_index;
	__u16 reserved;
	__u64 user_addr;
	__u32 data_off;
	__u32 data_len;
};

#define SCT_IOC_MAGIC 'S'
#define SCT_IOC_SET_CONFIG _IOW(SCT_IOC_MAGIC, 1, struct sct_config)
#define SCT_IOC_GET_CONFIG _IOR(SCT_IOC_MAGIC, 2, struct sct_config)
#define SCT_IOC_START _IO(SCT_IOC_MAGIC, 3)
#define SCT_IOC_STOP _IO(SCT_IOC_MAGIC, 4)
#define SCT_IOC_SET_NR_FILTER _IOW(SCT_IOC_MAGIC, 5, struct sct_nr_filter)
#define SCT_IOC_SET_CAPTURE_RULES _IOW(SCT_IOC_MAGIC, 6, struct sct_capture_rules)

#endif /* _UAPI_LINUX_SYSCALL_TRACE_H */
