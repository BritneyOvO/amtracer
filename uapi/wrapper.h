#include <linux/ktools.h>
#include <linux/prctl.h>
#include <linux/syscall_trace.h>
#include <linux/binder_trace.h>

/* bindgen evaluates enum values; sizeof-based ioctl macros are not constants
 * in bindgen's macro parser. Keep their values derived from the original UAPI. */
enum {
    AMT_KT_IOC_GET_INFO = KT_IOC_GET_INFO,
    AMT_KT_IOC_OPEN_SYSCALL_TRACE = KT_IOC_OPEN_SYSCALL_TRACE,
    AMT_KT_IOC_OPEN_BINDER_TRACE = KT_IOC_OPEN_BINDER_TRACE,
    AMT_KT_IOC_TRACE_GET_STATS = KT_IOC_TRACE_GET_STATS,
    AMT_SCT_IOC_SET_CONFIG = SCT_IOC_SET_CONFIG,
    AMT_SCT_IOC_START = SCT_IOC_START,
    AMT_SCT_IOC_STOP = SCT_IOC_STOP,
    AMT_SCT_IOC_SET_NR_FILTER = SCT_IOC_SET_NR_FILTER,
    AMT_BT_IOC_GET_FEATURE = BT_IOC_GET_FEATURE,
    AMT_BT_IOC_SET_CONFIG = BT_IOC_SET_CONFIG,
};
