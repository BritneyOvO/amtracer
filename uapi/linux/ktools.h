/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_KTOOLS_H
#define _UAPI_LINUX_KTOOLS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define KT_ABI_VERSION 1U
#define KT_OPEN_CONTROL 1U

#define KT_FEATURE_RWMEM (1U << 0)
#define KT_FEATURE_VTOUCH (1U << 1)
#define KT_FEATURE_SYSCALL_TRACE (1U << 2)
#define KT_FEATURE_BINDER_TRACE (1U << 3)
#define KT_FEATURE_UXN (1U << 4)

/* v1 sizes and ioctl numbers are fixed. Unspecified flags/reserved are zero. */
struct kt_info {
	__u32 abi_version;
	__u32 features;
	__u32 max_io_bytes;
	__u32 max_touch_slots;
};

struct kt_target_open {
	__u32 size;
	__u32 flags;
	__s32 pid; /* 0: current; positive: PID in the caller's namespace */
	__u32 reserved;
};

struct kt_touch_open {
	__u32 size;
	__u32 flags;
	__u32 slots; /* 1..16 */
	__u32 reserved;
};

/* Mutually exclusive READ/WRITE modes in kt_mem_io.flags. */
#define KT_MEM_MODE_PROCESS_VM	0U
#define KT_MEM_MODE_PGTABLE	1U
#define KT_MEM_MODE_AT		2U
#define KT_MEM_MODE_DEVICE	3U
#define KT_MEM_MODE_MAX		KT_MEM_MODE_DEVICE

struct kt_mem_io {
	__u32 size;
	__u32 flags;
	__aligned_u64 address;
	__aligned_u64 buffer;
	__aligned_u64 length;
	__aligned_u64 transferred;
};

struct kt_mem_translate {
	__u32 size;
	__u32 flags;
	__aligned_u64 address;
	__aligned_u64 physical_address;
};

/* Address cursor: start at skip=0; on success skip becomes the last VMA end.
 * Without this flag, skip remains an input record count (legacy pagination).
 */
#define KT_VMA_ENUM_BY_ADDR (1U << 0)

/* Records are struct rwmem_vma from linux/rwmem.h. Not a stable snapshot. */
struct kt_vma_enum {
	__u32 size;
	__u32 flags;
	__aligned_u64 skip;
	__aligned_u64 buffer;
	__aligned_u64 buffer_bytes;
	__aligned_u64 count;
};

struct kt_touch_point {
	__u32 size;
	__u32 flags;
	__u32 slot;
	__s32 x;
	__s32 y;
	__u32 reserved;
};

struct kt_touch_info {
	__u32 slots;
	__s32 min_x;
	__s32 max_x;
	__s32 min_y;
	__s32 max_y;
	__u32 reserved;
};

struct kt_trace_stats {
	__aligned_u64 sequence;
	__aligned_u64 lost;
	__u32 queued;
	__u32 reserved;
};

#define KT_IOC_GET_INFO _IOR('K', 0x00, struct kt_info)
/* OPEN commands return an O_CLOEXEC fd; trace fds also start O_NONBLOCK. */
#define KT_IOC_OPEN_MEM _IOW('K', 0x01, struct kt_target_open)
#define KT_IOC_OPEN_TOUCH _IOW('K', 0x02, struct kt_touch_open)
#define KT_IOC_OPEN_SYSCALL_TRACE _IO('K', 0x03)
#define KT_IOC_OPEN_BINDER_TRACE _IO('K', 0x04)

#define KT_IOC_MEM_READ _IOWR('K', 0x10, struct kt_mem_io)
#define KT_IOC_MEM_WRITE _IOWR('K', 0x11, struct kt_mem_io)
#define KT_IOC_MEM_TRANSLATE _IOWR('K', 0x12, struct kt_mem_translate)
#define KT_IOC_MEM_ENUM_VMAS _IOWR('K', 0x13, struct kt_vma_enum)

#define KT_IOC_TOUCH_DOWN _IOW('K', 0x20, struct kt_touch_point)
#define KT_IOC_TOUCH_MOVE _IOW('K', 0x21, struct kt_touch_point)
#define KT_IOC_TOUCH_UP _IOW('K', 0x22, struct kt_touch_point)
#define KT_IOC_TOUCH_GET_INFO _IOR('K', 0x23, struct kt_touch_info)

/* Trace configuration/record formats remain in their existing UAPI headers. */
#define KT_IOC_TRACE_GET_STATS _IOR('K', 0x30, struct kt_trace_stats)

#endif /* _UAPI_LINUX_KTOOLS_H */
