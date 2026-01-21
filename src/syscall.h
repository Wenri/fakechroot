/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2024 Bingchen Gong

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
*/

/*
 * syscall.h - Unified syscall wrapper and SIGSYS handler support
 *
 * This file provides:
 * 1. Extern declaration for syscall wrapper's nextfunc (shared across files)
 * 2. Unified macro system for generating syscall redirect code
 *
 * Two contexts use these macros:
 * - syscall() wrapper (syscall.c): Uses va_arg, performs path expansion
 * - SIGSYS handler (sigaction.c): Uses ucontext registers, no path expansion
 *
 * The deduplication is achieved through:
 * - Boost.PP for iteration over the redirect table (REDIRECT_SEQ)
 * - Context-specific CTX_ARG and CTX_CALL macros defined per-file
 * - Context types (syscall_args_t, sigsys_ctx_t) for type safety
 *
 * Patterns supported:
 * - SYS_GEN_AT: AT syscalls that drop last arg (faccessat2 -> faccessat)
 * - SYS_GEN_PATH0/1/2: Non-AT syscalls redirected to AT versions
 * - SYS_GEN_R0/3/4_2: Non-path syscalls with different arg counts
 * - SYS_GEN_SYMLINK/LINK: Special multi-path syscalls
 */

#ifndef FAKECHROOT_SYSCALL_H
#define FAKECHROOT_SYSCALL_H

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/tuple/elem.hpp>
#include <boost/preprocessor/cat.hpp>
#include <sys/ucontext.h>

/*
 * ============================================================================
 * Syscall wrapper prototype declaration
 *
 * This allows other files (sigaction.c) to call through the syscall wrapper
 * using nextcall(syscall), ensuring consistent interception behavior.
 * Requires libfakechroot.h to be included first for wrapper_proto macro.
 * ============================================================================
 */
wrapper_proto(syscall, long, (long, ...));

/*
 * ============================================================================
 * SIGSYS Register Access (for signal handler context)
 *
 * These macros extract syscall arguments from the ucontext registers when
 * handling SIGSYS signals from Android's seccomp filter.
 * ============================================================================
 */
#ifdef __aarch64__
#define SIGSYS_REG(ctx, n) ((long)(ctx)->uc_mcontext.regs[n])
#define SIGSYS_SET_RETURN(ctx, val) ((ctx)->uc_mcontext.regs[0] = (val))
#endif

#ifdef __x86_64__
#include <sys/ucontext.h>
/* x86_64 syscall argument registers: rdi, rsi, rdx, r10, r8, r9 */
#define SIGSYS_REG(ctx, n) ((long)(ctx)->uc_mcontext.gregs[ \
    (n) == 0 ? REG_RDI : \
    (n) == 1 ? REG_RSI : \
    (n) == 2 ? REG_RDX : \
    (n) == 3 ? REG_R10 : \
    (n) == 4 ? REG_R8 : REG_R9])
#define SIGSYS_SET_RETURN(ctx, val) ((ctx)->uc_mcontext.gregs[REG_RAX] = (val))
#endif

/*
 * ============================================================================
 * Context types for _Generic dispatch
 *
 * These types allow the same generator macros to work in both contexts:
 * - syscall_args_t: Pre-extracted va_args in syscall() wrapper
 * - sigsys_ctx_t: Pointer to ucontext in SIGSYS handler
 * ============================================================================
 */

/* Syscall wrapper context - holds pre-extracted va_args */
typedef struct {
    long a[6];
} syscall_args_t;

/* SIGSYS handler context - pointer to ucontext */
typedef ucontext_t * sigsys_ctx_t;

/*
 * ============================================================================
 * Context-specific argument accessors
 *
 * CTX_ARG must be defined by each source file before using SYS_GEN_* macros:
 * - syscall.c: #define CTX_ARG(ctx, n) (ctx).a[n]
 * - sigaction.c: #define CTX_ARG(ctx, n) SIGSYS_REG(ctx, n)
 *
 * Similarly, CTX_CALL must be defined per-file:
 * - syscall.c: #define CTX_CALL(ctx, ...) nextcall(syscall)(__VA_ARGS__)
 * - sigaction.c: #define CTX_CALL(ctx, ...) syscall(__VA_ARGS__)
 *
 * Note: _Generic cannot be used here because both branches must be
 * syntactically valid, but (ctx).a[n] is invalid when ctx is a pointer.
 * ============================================================================
 */

/*
 * ============================================================================
 * Unified Generator Macros using CTX_ARG
 *
 * These macros generate case statements for the switch. They take:
 * - from: Source syscall name (without SYS_ prefix)
 * - to: Target syscall name (without SYS_ prefix)
 * - extra: Extra argument(s) to append
 * - ctx_expr: Context expression (syscall_args_t or sigsys_ctx_t)
 * - DONE: Macro to handle result (return or goto)
 *
 * Note: DONE must be context-specific because control flow differs:
 * - syscall.c: va_end(ap); return val;
 * - sigaction.c: ret = val; goto set_return;
 *
 * Important: We use typeof() to ensure ctx_expr is evaluated only once,
 * avoiding issues with side effects (e.g., va_arg in SYSCALL_SETUP).
 * ============================================================================
 */

/*
 * All macros take 6 parameters: (from, to, e1, e2, ctx_expr, DONE)
 * This allows uniform dispatch from REDIRECT_SEQ entries.
 * Macros that don't need e2 (or both) simply ignore them.
 */

/* AT syscall: syscall(dirfd, path, mode) -> target(dirfd, path, mode, e1) */
#define SYS_GEN_AT(from, to, e1, e2, ctx_expr, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        typeof(ctx_expr) _ctx = ctx_expr; \
        long result = CTX_CALL(_ctx, BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), CTX_ARG(_ctx, 1), CTX_ARG(_ctx, 2), e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* Path with 0 args: syscall(path) -> target(AT_FDCWD, path, e1) */
#define SYS_GEN_PATH0(from, to, e1, e2, ctx_expr, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        typeof(ctx_expr) _ctx = ctx_expr; \
        long result = CTX_CALL(_ctx, BOOST_PP_CAT(SYS_, to), AT_FDCWD, CTX_ARG(_ctx, 0), e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* Path with 1 arg: syscall(path, a2) -> target(AT_FDCWD, path, a2, e1) */
#define SYS_GEN_PATH1(from, to, e1, e2, ctx_expr, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        typeof(ctx_expr) _ctx = ctx_expr; \
        long result = CTX_CALL(_ctx, BOOST_PP_CAT(SYS_, to), AT_FDCWD, CTX_ARG(_ctx, 0), CTX_ARG(_ctx, 1), e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* Path with 2 args: syscall(path, a2, a3) -> target(AT_FDCWD, path, a2, a3, e1) */
#define SYS_GEN_PATH2(from, to, e1, e2, ctx_expr, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        typeof(ctx_expr) _ctx = ctx_expr; \
        long result = CTX_CALL(_ctx, BOOST_PP_CAT(SYS_, to), AT_FDCWD, CTX_ARG(_ctx, 0), CTX_ARG(_ctx, 1), CTX_ARG(_ctx, 2), e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* 0 args: syscall() -> target(e1) */
#define SYS_GEN_R0(from, to, e1, e2, ctx_expr, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        typeof(ctx_expr) _ctx = ctx_expr; \
        (void)_ctx; /* unused but needed for consistency */ \
        long result = CTX_CALL(_ctx, BOOST_PP_CAT(SYS_, to), e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* 3 args: syscall(a1, a2, a3) -> target(a1, a2, a3, e1) */
#define SYS_GEN_R3(from, to, e1, e2, ctx_expr, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        typeof(ctx_expr) _ctx = ctx_expr; \
        long result = CTX_CALL(_ctx, BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), CTX_ARG(_ctx, 1), CTX_ARG(_ctx, 2), e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* 4 args + 2 extras: syscall(a1, a2, a3, a4) -> target(a1, a2, a3, a4, e1, e2) */
#define SYS_GEN_R4_2(from, to, e1, e2, ctx_expr, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        typeof(ctx_expr) _ctx = ctx_expr; \
        long result = CTX_CALL(_ctx, BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), CTX_ARG(_ctx, 1), CTX_ARG(_ctx, 2), CTX_ARG(_ctx, 3), e1, e2); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* symlink(target, linkpath) -> symlinkat(target, AT_FDCWD, linkpath) */
#define SYS_GEN_SYMLINK(from, to, e1, e2, ctx_expr, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        typeof(ctx_expr) _ctx = ctx_expr; \
        long result = CTX_CALL(_ctx, BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), AT_FDCWD, CTX_ARG(_ctx, 1)); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* link(oldpath, newpath) -> linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0) */
#define SYS_GEN_LINK(from, to, e1, e2, ctx_expr, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        typeof(ctx_expr) _ctx = ctx_expr; \
        long result = CTX_CALL(_ctx, BOOST_PP_CAT(SYS_, to), AT_FDCWD, CTX_ARG(_ctx, 0), AT_FDCWD, CTX_ARG(_ctx, 1), 0); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/*
 * ============================================================================
 * Redirect Table as Boost.PP Sequence
 *
 * Each entry is a 5-tuple: (PATTERN, from, to, extra1, extra2)
 * - PATTERN: Generator macro suffix (AT, PATH0, PATH1, PATH2, R0, R3, R4_2, SYMLINK, LINK)
 * - from: Source syscall name (without SYS_ prefix)
 * - to: Target syscall name (without SYS_ prefix)
 * - extra1: First extra argument (use 0 or _ as placeholder)
 * - extra2: Second extra argument (use 0 or _ as placeholder, only R4_2 uses both)
 *
 * All entries have 5 elements for uniform dispatch. Unused extras are ignored.
 * Note: Entries are conditionally included based on SYS_* availability.
 * ============================================================================
 */

/* Newer syscalls that have older fallbacks */
#ifdef SYS_faccessat2
#define REDIRECT_ENTRY_faccessat2 ((AT, faccessat2, faccessat, 0, _))
#else
#define REDIRECT_ENTRY_faccessat2
#endif

#ifdef SYS_fchmodat2
#define REDIRECT_ENTRY_fchmodat2 ((AT, fchmodat2, fchmodat, 0, _))
#else
#define REDIRECT_ENTRY_fchmodat2
#endif

/* Legacy syscalls redirected to *at versions (x86 only) */
#ifdef SYS_chmod
#define REDIRECT_ENTRY_chmod ((PATH1, chmod, fchmodat, 0, _))
#else
#define REDIRECT_ENTRY_chmod
#endif

#ifdef SYS_chown
#define REDIRECT_ENTRY_chown ((PATH2, chown, fchownat, 0, _))
#else
#define REDIRECT_ENTRY_chown
#endif

#ifdef SYS_chown32
#define REDIRECT_ENTRY_chown32 ((PATH2, chown32, fchownat, 0, _))
#else
#define REDIRECT_ENTRY_chown32
#endif

#ifdef SYS_rmdir
#define REDIRECT_ENTRY_rmdir ((PATH0, rmdir, unlinkat, AT_REMOVEDIR, _))
#else
#define REDIRECT_ENTRY_rmdir
#endif

/* Socket syscalls (may be legacy on some archs) */
#ifdef SYS_accept
#define REDIRECT_ENTRY_accept ((R3, accept, accept4, 0, _))
#else
#define REDIRECT_ENTRY_accept
#endif

#ifdef SYS_recv
#define REDIRECT_ENTRY_recv ((R4_2, recv, recvfrom, 0, 0))
#else
#define REDIRECT_ENTRY_recv
#endif

#ifdef SYS_send
#define REDIRECT_ENTRY_send ((R4_2, send, sendto, 0, 0))
#else
#define REDIRECT_ENTRY_send
#endif

/* Process syscalls */
#ifdef SYS_getpgrp
#define REDIRECT_ENTRY_getpgrp ((R0, getpgrp, getpgid, 0, _))
#else
#define REDIRECT_ENTRY_getpgrp
#endif

/* Filesystem syscalls */
#ifdef SYS_symlink
#define REDIRECT_ENTRY_symlink ((SYMLINK, symlink, symlinkat, _, _))
#else
#define REDIRECT_ENTRY_symlink
#endif

#ifdef SYS_link
#define REDIRECT_ENTRY_link ((LINK, link, linkat, _, _))
#else
#define REDIRECT_ENTRY_link
#endif

/* Combined redirect sequence - expands to all defined entries */
#define REDIRECT_SEQ \
    REDIRECT_ENTRY_faccessat2 \
    REDIRECT_ENTRY_fchmodat2 \
    REDIRECT_ENTRY_chmod \
    REDIRECT_ENTRY_chown \
    REDIRECT_ENTRY_chown32 \
    REDIRECT_ENTRY_rmdir \
    REDIRECT_ENTRY_accept \
    REDIRECT_ENTRY_recv \
    REDIRECT_ENTRY_send \
    REDIRECT_ENTRY_getpgrp \
    REDIRECT_ENTRY_symlink \
    REDIRECT_ENTRY_link

/*
 * ============================================================================
 * AT Pass-through syscalls: expand path and call same syscall
 * Pattern: syscall(dirfd, pathname, ...) with path expansion
 * (These are NOT redirects - they call the same syscall with expanded path)
 * ============================================================================
 */

/* AT syscall with 1 extra arg after pathname */
#define AT_PASSTHROUGH_1(sysnum) \
    case sysnum: { \
        int dirfd = va_arg(ap, int); \
        const char *pathname = va_arg(ap, const char *); \
        long a3 = va_arg(ap, long); \
        va_end(ap); \
        debug("syscall(" #sysnum ", %d, \"%s\", %ld)", dirfd, pathname, a3); \
        pathname = expand_chroot_path_at(dirfd, pathname, fakechroot_buf); \
        return nextcall(syscall)(number, dirfd, pathname, a3); \
    }

/* AT syscall with 2 extra args after pathname */
#define AT_PASSTHROUGH_2(sysnum) \
    case sysnum: { \
        int dirfd = va_arg(ap, int); \
        const char *pathname = va_arg(ap, const char *); \
        long a3 = va_arg(ap, long); \
        long a4 = va_arg(ap, long); \
        va_end(ap); \
        debug("syscall(" #sysnum ", %d, \"%s\", ...)", dirfd, pathname); \
        pathname = expand_chroot_path_at(dirfd, pathname, fakechroot_buf); \
        return nextcall(syscall)(number, dirfd, pathname, a3, a4); \
    }

/* AT syscall with 3 extra args after pathname */
#define AT_PASSTHROUGH_3(sysnum) \
    case sysnum: { \
        int dirfd = va_arg(ap, int); \
        const char *pathname = va_arg(ap, const char *); \
        long a3 = va_arg(ap, long); \
        long a4 = va_arg(ap, long); \
        long a5 = va_arg(ap, long); \
        va_end(ap); \
        debug("syscall(" #sysnum ", %d, \"%s\", ...)", dirfd, pathname); \
        pathname = expand_chroot_path_at(dirfd, pathname, fakechroot_buf); \
        return nextcall(syscall)(number, dirfd, pathname, a3, a4, a5); \
    }

#endif /* FAKECHROOT_SYSCALL_H */
