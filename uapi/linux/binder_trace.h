/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_BINDER_TRACE_H
#define _UAPI_LINUX_BINDER_TRACE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define BT_ABI_VERSION 3U
#define BT_IOC_MAGIC 'B'
#define BT_DRIVER_FEATURE_MAGIC 0x4254524143453031ULL
#define BT_DRIVER_FEATURE_NAME "binder-trace"

#define BT_FEATURE_EVENT_STREAM (1U << 1)
#define BT_FEATURE_KTOOLS_FD (1U << 2)
#define BT_FEATURE_TRANSACTION (1U << 3)
#define BT_FEATURE_TRANSACTION_RESULT (1U << 4)

/* SUBMITTED means accepted by Binder, not that the service has replied. */
#define BT_OUTCOME_UNKNOWN 0U
#define BT_OUTCOME_SUBMITTED 1U
#define BT_OUTCOME_FAILED 2U

#define BT_EVENT_KIND_BINDER_TRANSACTION 1U
#define BT_MAX_INLINE_DATA 256U

#define BT_CAPTURE_POINT_TRANSACTION (1U << 2)

struct bt_abi_version {
	__u32 version;
	__u32 reserved;
};

struct bt_driver_feature {
	__u64 magic;
	__u32 abi_version;
	__u32 feature_flags;
	char name[16];
};

struct bt_capture_config {
	__u32 enabled;
	__u32 point_mask; /* BT_CAPTURE_POINT_TRANSACTION */
	__s32 tgid;
	__s32 pid;
	__u32 uid;
	__u32 uid_enabled;
	__u32 ioctl_cmd; /* Must be zero. */
	__u32 ioctl_cmd_enabled; /* Must be zero. */
	__u64 min_size;
	__u64 max_size;
};

struct bt_capture_stats {
	__u64 ioctl_hits; /* Always zero. */
	__u64 copy_to_user_hits; /* Always zero. */
	__u64 transaction_hits;
	__u64 captured;
	__u64 filtered;
};

struct bt_binder_event {
	__u64 sequence;
	__u64 timestamp_ns;
	__u32 kind;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 reply;
	__u32 lost_before;
	__u32 transaction_debug_id;
	__u32 reply_to_debug_id;
	__u64 transaction;
	__u64 proc;
	__u64 thread;
	__u64 extra_buffers_size;
	__u32 code;
	__u32 flags;
	__u64 data_size;
	__u64 offsets_size;
	__u32 target_handle;
	__u32 sender_pid; /* Binder proc TGID in the initial PID namespace. */
	__u32 sender_euid; /* Kernel sender credential, initial user namespace. */
	__u32 data_len;
	__u8 data_truncated;
	__u8 outcome; /* BT_OUTCOME_*; former reserved space. */
	__u8 reserved[2];
	__s32 error; /* Failure errno; may be zero even for FAILED. */
	__u8 data[BT_MAX_INLINE_DATA];
};

#define BT_IOC_GET_ABI_VERSION _IOR(BT_IOC_MAGIC, 0x00, struct bt_abi_version)
#define BT_IOC_SET_CONFIG _IOW(BT_IOC_MAGIC, 0x01, struct bt_capture_config)
#define BT_IOC_GET_CONFIG _IOR(BT_IOC_MAGIC, 0x02, struct bt_capture_config)
#define BT_IOC_GET_STATS _IOR(BT_IOC_MAGIC, 0x03, struct bt_capture_stats)
#define BT_IOC_CLEAR_STATS _IO(BT_IOC_MAGIC, 0x04)
#define BT_IOC_GET_FEATURE _IOR(BT_IOC_MAGIC, 0x05, struct bt_driver_feature)

#define BT_IOC_MAX_NR 0x05

#endif /* _UAPI_LINUX_BINDER_TRACE_H */
