/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace ABI for the UXN/exception-based uxn probe framework.
 *
 * Based on the design described in:
 *   https://blog.xinrao.moe/article/3552c64d-9f79-8080-84da-ca2d720a3b89
 *
 * Flow: mark target code page PTE.UXN → EL0 I-abort → kernel rewrites
 * pt_regs->pc to a per-page recompilation (recomp) VMA.
 */
#ifndef _UAPI_LINUX_UXN_PROBE_H
#define _UAPI_LINUX_UXN_PROBE_H

#include <linux/types.h>

/* Breakpoint / site modes. */
#define UXN_BP_MODE_DBI		1
#define UXN_BP_MODE_INSTRUMENT	2
#define UXN_BP_MODE_INLINE_PROBE	3
#define UXN_BP_MODE_BRK		4

/*
 * BRK: entry_out is one kernel-owned BRK, followed by the relocated original
 * instruction at body_out. handler must be zero; user_data is an opaque cookie.
 * The kernel validates the site and resumes at this generation's body_out.
 * No userspace handler or SIGTRAP is invoked. Uprobe consumers require the
 * explicit per-site UXN_BP_FLAG_UPROBE opt-in below.
 * NO_PREFIX suppresses the BRK, as it suppresses other modes' prefixes.
 */

/*
 * Userspace handler contracts (WuWa-style control flow):
 *
 *   prefix pushes a frame, sets LR = recomp restore (not the UXN page),
 *   BR handler. handler RET lands in the restore half and falls into the
 *   rewritten body. One instruction abort per call. ctx.pc (INSTRUMENT)
 *   is still the original site.
 *
 * DBI:
 *   void handler(void);
 *   — no args; preserve/restore any regs you clobber (prefix only saves LR,X17)
 *
 * INSTRUMENT:
 *   void handler(struct uxn_instr_ctx *ctx);  // x1 may carry user_data
 *   — x0 = &ctx on the probe stack frame
 *   — x1 = user_data from REGISTER (Nebula extension; may be ignored)
 *   — handler may read/write ctx fields; restored before body runs
 *   — do not free the frame or change SP relative to the prefix epilogue
 */
struct uxn_instr_ctx {
	__u64 x[31];	/* x0..x30 at entry to the site */
	__u64 sp;	/* SP at entry (before prefix frame) */
	__u64 pc;	/* original site PC (page_base + offset) */
	__u64 nzcv;	/* v4: NZCV low32, FPSR high32; FPCR privately preserved */
	__u64 q[64];	/* q0..q31 as 32×(lo,hi) u64 pairs, 512 bytes */
	/* total 784 (0x310) bytes, 16-aligned */
};

/* Deprecated, ignored: recomp must stay within the supported branch range. */
#define UXN_BP_FLAG_NO_NEARBY	(1u << 0)
/* Do not install entry prefix; only recomp for page continuity. */
#define UXN_BP_FLAG_NO_PREFIX	(1u << 1)
/* Keep original page readable; only UXN is forced (default). */
#define UXN_BP_FLAG_UXN_ONLY	(1u << 2)
/*
 * Defer the UXN flip out of REGISTER: build the recomp + export body_out /
 * entry_out but do NOT arm the site. The page stays fully executable until a
 * separate UXN_PROBE_CMD_ACTIVATE flips UXN. Two-phase install lets
 * userspace point "call original" at body_out *before* the probe can fire,
 * eliminating the install-window race where a call re-enters the trampoline
 * via the provisional original pointer (infinite recursion -> SIGSEGV).
 */
#define UXN_BP_FLAG_DEFER_UXN	(1u << 3)
/*
 * BRK site only: allow standard uprobe consumers to use this recomp prefix.
 * REGISTER and ACTIVATE the file-backed page before attaching the consumers.
 * NO_PREFIX is incompatible. Detach consumers before replacing/unregistering
 * the UXN generation. Other pages retain the standard software breakpoint.
 */
#define UXN_BP_FLAG_UPROBE	(1u << 4)
/*
 * REGISTER is always a full-page upsert: sites[] is the complete desired set
 * for that page. Re-REGISTER with a different handler/mode/user_data at the
 * same offset replaces the previous site (Nebula hot-replace). There is no
 * separate "already installed" reject in the kernel — userspace decides
 * whether to merge or replace before building sites[].
 *
 * v4: published recomp generations are immutable and retained until mm exit.
 * REGISTER requires DEFER_UXN and a matching expected generation token.
 * Writable/shared source mappings and conflicting writes/mprotect/mremap/
 * destructive madvise are refused; transparent hot rebuild is unsupported.
 * Handlers, callback descriptors and saved original trampolines must also
 * remain valid until mm exit because an old generation may still call them.
 */

/* Max instruction sites registered per original 4K page. */
#define UXN_PROBE_MAX_SITES		32
/* Max concurrent tracked pages system-wide. */
#define UXN_PROBE_MAX_PAGES		4096

/*
 * One probe site inside a page.
 * @offset: byte offset from page base (must be 4-byte aligned, < PAGE_SIZE).
 * @mode:   UXN_BP_MODE_*.
 * @flags:  UXN_BP_FLAG_*.
 * @handler: user VA of replacement/probe entry (0 = none); must be 0 for BRK.
 * @user_data: opaque cookie returned via STAT / debug.
 */
struct uxn_probe_site {
	__u32 offset;
	__u32 mode;
	__u32 flags;
	__u32 reserved;
	__u64 handler;
	__u64 user_data;
	/* Filled by kernel on successful REGISTER: */
	__u64 entry_out;	/* recomp VA of site prefix (branch target for EL0) */
	__u64 body_out;		/* recomp VA of rewritten body (call as "original") */
};

/*
 * Register (or update) a page under uxn control.
 * @pid: target process (0 = current).
 * @page_addr: any address in the target code page (will be page-aligned).
 * @nr_sites: number of valid entries in sites[].
 * @flags: page-level flags (OR of UXN_BP_FLAG_*).
 * @recomp_out: kernel fills mapped recomp page user VA on success.
 */
struct uxn_probe_reg {
	__u32 pid;
	__u32 nr_sites;
	__u32 flags;
	__u32 generation; /* v4: expected old token (0=create); output new token */
	__u64 page_addr;
	__u64 recomp_out;
	struct uxn_probe_site sites[UXN_PROBE_MAX_SITES];
};

/* Unregister by page (pid + page_addr). */
struct uxn_probe_unreg {
	__u32 pid;
	__u32 generation; /* Required v4 REGISTER token; stale => ESTALE */
	__u64 page_addr;
};

/* Query one page. */
struct uxn_probe_stat {
	__u32 pid;
	__u32 nr_sites;
	__u32 flags;
	__u32 active;		/* 1 if UXN applied */
	__u64 page_addr;
	__u64 recomp_addr;
	__u64 hit_count;
	struct uxn_probe_site sites[UXN_PROBE_MAX_SITES];
	__u32 generation; /* v4: compare with REGISTER output */
	__u32 reserved;
};

/* Global counters. */
struct uxn_probe_info {
	__u32 version;		/* UXN_PROBE_ABI_VERSION */
	__u32 page_count;
	__u64 abort_hits;
	__u64 abort_misses;
	__u64 far_redirects;	/* reserved legacy counter, always zero */
	__u64 recomp_allocs;
	__u64 hot_rebuilds;	/* reserved legacy counter, always zero */
	__u64 write_traps;	/* reserved legacy counter, always zero */
	__u64 vma_events;	/* source unmap / mm exit events */
};

#define UXN_PROBE_ABI_VERSION	4

/* Legacy redirect marker, kept for source/ABI compatibility; not emitted. */
#define UXN_PROBE_FAR_MAGIC		0x53544846u /* 'STHF' */
/*
 * DBI/INSTRUMENT prefix frame marker (16-bit, fits MOVZ).
 * Prefix: STP XZR, Xmag, [SP,#-16]! -> [SP+0]=0, [SP+8]=magic.
 * The handler returns to the recomp restore entry, which pops this frame.
 */
#define UXN_PROBE_RET_MAGIC		0x5354u /* 'ST' */

/*
 * Transport (v0.4+): prctl magic option — no /dev, no custom AF socket.
 *
 *   prctl(PR_UXN_PROBE, UXN_PROBE_CMD_*, (unsigned long)arg, 0, 0);
 *
 * PR_UXN_PROBE is defined in linux/prctl.h as 0x5354484b ('STHK').
 * arg is a userspace pointer to the matching command struct below; the
 * numbers match the former miscdevice ABI so data structs stay identical.
 */
#define UXN_PROBE_CMD_REGISTER	1
#define UXN_PROBE_CMD_UNREGISTER	2
#define UXN_PROBE_CMD_STAT		3
#define UXN_PROBE_CMD_INFO		4
#define UXN_PROBE_CMD_CLEAR_PID	5
/*
 * Two-phase install: REGISTER with UXN_BP_FLAG_DEFER_UXN arms nothing;
 * UXN_PROBE_CMD_ACTIVATE flips UXN on an already-registered page so the
 * site starts firing. Data is struct uxn_probe_unreg (pid + page_addr).
 */
#define UXN_PROBE_CMD_ACTIVATE	6

#endif /* _UAPI_LINUX_UXN_PROBE_H */
