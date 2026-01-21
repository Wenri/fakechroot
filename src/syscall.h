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
 * - Context-specific CTX_ARG and CTX_EXPAND_PATH* macros defined per-file
 * - Context types for type safety (syscall_args_t here, sigsys_ctx_t in sigaction.h)
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
 * Context-specific macros (must be defined by each source file)
 *
 * CTX_SETUP - Context initialization (declares the _ctx variable):
 * - syscall.c: long _ctx[6] = { va_arg(ap, long), ... }
 * - sigaction.c: sigsys_ctx_t _ctx = ctx
 *
 * CTX_ARG - Argument accessor:
 * - syscall.c: #define CTX_ARG(ctx, n) (ctx)[n]
 * - sigaction.c: #define CTX_ARG(ctx, n) SIGSYS_REG(ctx, n)
 *
 * CTX_EXPAND_PATH - Path expansion for chroot (arg index):
 * - syscall.c: expand_chroot_path(path, alloca(FAKECHROOT_PATH_MAX))
 * - sigaction.c: (const char *)CTX_ARG(ctx, n)  [no-op in signal handler]
 *
 * CTX_EXPAND_PATH_AT - Path expansion for AT syscalls (dirfd index, path index):
 * - syscall.c: expand_chroot_path_at(dirfd, path, alloca(FAKECHROOT_PATH_MAX))
 * - sigaction.c: (const char *)CTX_ARG(ctx, n)  [no-op in signal handler]
 *
 * Note: CTX_SETUP is a declaration macro (not expression) because C doesn't
 * allow array assignment, but brace initialization works: long arr[6] = {...};
 * ============================================================================
 */

/*
 * ============================================================================
 * Unified Generator Macros using CTX_ARG
 *
 * These macros generate case statements for the switch. They take:
 * - from: Source syscall name (without SYS_ prefix)
 * - to: Target syscall name (without SYS_ prefix)
 * - e1, e2: Extra argument(s) to append (unused ones ignored)
 * - DONE: Macro to handle result (return or goto)
 *
 * Each macro calls CTX_SETUP(_ctx) to initialize the context variable.
 * CTX_SETUP must be defined by the including file as a declaration macro.
 *
 * Note: DONE must be context-specific because control flow differs:
 * - syscall.c: va_end(ap); return val;
 * - sigaction.c: ret = val; goto set_return;
 * ============================================================================
 */

/*
 * All macros take 5 parameters: (from, to, e1, e2, DONE)
 * This allows uniform dispatch from REDIRECT_SEQ entries.
 * Macros that don't need e2 (or both) simply ignore them.
 */

/* AT syscall: syscall(dirfd, path, mode) -> target(dirfd, path, mode, e1) */
#define SYS_GEN_AT(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH_AT(_ctx, 0, 1); \
        long result = nextcall(syscall)( BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), _path, CTX_ARG(_ctx, 2), e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* Path with 0 args: syscall(path) -> target(AT_FDCWD, path, e1) */
#define SYS_GEN_PATH0(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH(_ctx, 0); \
        long result = nextcall(syscall)( BOOST_PP_CAT(SYS_, to), AT_FDCWD, _path, e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* Path with 1 arg: syscall(path, a2) -> target(AT_FDCWD, path, a2, e1) */
#define SYS_GEN_PATH1(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH(_ctx, 0); \
        long result = nextcall(syscall)( BOOST_PP_CAT(SYS_, to), AT_FDCWD, _path, CTX_ARG(_ctx, 1), e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* Path with 2 args: syscall(path, a2, a3) -> target(AT_FDCWD, path, a2, a3, e1) */
#define SYS_GEN_PATH2(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH(_ctx, 0); \
        long result = nextcall(syscall)( BOOST_PP_CAT(SYS_, to), AT_FDCWD, _path, CTX_ARG(_ctx, 1), CTX_ARG(_ctx, 2), e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* 0 args: syscall() -> target(e1) */
#define SYS_GEN_R0(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        (void)_ctx; /* unused but needed for consistency */ \
        long result = nextcall(syscall)( BOOST_PP_CAT(SYS_, to), e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* 3 args: syscall(a1, a2, a3) -> target(a1, a2, a3, e1) */
#define SYS_GEN_R3(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        long result = nextcall(syscall)( BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), CTX_ARG(_ctx, 1), CTX_ARG(_ctx, 2), e1); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* 4 args + 2 extras: syscall(a1, a2, a3, a4) -> target(a1, a2, a3, a4, e1, e2) */
#define SYS_GEN_R4_2(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        long result = nextcall(syscall)( BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), CTX_ARG(_ctx, 1), CTX_ARG(_ctx, 2), CTX_ARG(_ctx, 3), e1, e2); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* symlink(target, linkpath) -> symlinkat(target, AT_FDCWD, linkpath)
 * Note: Only linkpath (arg 1) is expanded - target (arg 0) is stored as-is */
#define SYS_GEN_SYMLINK(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_newpath = CTX_EXPAND_PATH(_ctx, 1); \
        long result = nextcall(syscall)( BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), AT_FDCWD, _newpath); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* link(oldpath, newpath) -> linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0) */
#define SYS_GEN_LINK(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_oldpath = CTX_EXPAND_PATH(_ctx, 0); \
        const char *_newpath = CTX_EXPAND_PATH(_ctx, 1); \
        long result = nextcall(syscall)( BOOST_PP_CAT(SYS_, to), AT_FDCWD, _oldpath, AT_FDCWD, _newpath, 0); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* AT syscall with 1 extra arg: syscall(dirfd, path, a3) -> to(dirfd, path_expanded, a3) */
#define SYS_GEN_AT1(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH_AT(_ctx, 0, 1); \
        long result = nextcall(syscall)(BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), _path, CTX_ARG(_ctx, 2)); \
        debug("syscall: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* AT syscall with 2 extra args: syscall(dirfd, path, a3, a4) -> to(dirfd, path_expanded, a3, a4) */
#define SYS_GEN_AT2(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH_AT(_ctx, 0, 1); \
        long result = nextcall(syscall)(BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), _path, CTX_ARG(_ctx, 2), CTX_ARG(_ctx, 3)); \
        debug("syscall: " #from " -> " #to " = %ld", result); \
        DONE(result); \
    }

/* AT syscall with 3 extra args: syscall(dirfd, path, a3, a4, a5) -> to(dirfd, path_expanded, a3, a4, a5) */
#define SYS_GEN_AT3(from, to, e1, e2, DONE) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH_AT(_ctx, 0, 1); \
        long result = nextcall(syscall)(BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), _path, CTX_ARG(_ctx, 2), CTX_ARG(_ctx, 3), CTX_ARG(_ctx, 4)); \
        debug("syscall: " #from " -> " #to " = %ld", result); \
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
 * Passthrough Table as Boost.PP Sequence
 *
 * These syscalls call the SAME syscall with path expansion (not redirect).
 * Pattern: (AT1/AT2/AT3, syscall, syscall, _, _) - note from=to for passthrough
 * ============================================================================
 */

#ifdef SYS_unlinkat
#define PASSTHROUGH_ENTRY_unlinkat ((AT1, unlinkat, unlinkat, _, _))
#else
#define PASSTHROUGH_ENTRY_unlinkat
#endif

#ifdef SYS_mkdirat
#define PASSTHROUGH_ENTRY_mkdirat ((AT1, mkdirat, mkdirat, _, _))
#else
#define PASSTHROUGH_ENTRY_mkdirat
#endif

#ifdef SYS_faccessat
#define PASSTHROUGH_ENTRY_faccessat ((AT2, faccessat, faccessat, _, _))
#else
#define PASSTHROUGH_ENTRY_faccessat
#endif

#ifdef SYS_openat
#define PASSTHROUGH_ENTRY_openat ((AT2, openat, openat, _, _))
#else
#define PASSTHROUGH_ENTRY_openat
#endif

#ifdef SYS_newfstatat
#define PASSTHROUGH_ENTRY_newfstatat ((AT2, newfstatat, newfstatat, _, _))
#else
#define PASSTHROUGH_ENTRY_newfstatat
#endif

#ifdef SYS_readlinkat
#define PASSTHROUGH_ENTRY_readlinkat ((AT2, readlinkat, readlinkat, _, _))
#else
#define PASSTHROUGH_ENTRY_readlinkat
#endif

#ifdef SYS_statx
#define PASSTHROUGH_ENTRY_statx ((AT3, statx, statx, _, _))
#else
#define PASSTHROUGH_ENTRY_statx
#endif

#define PASSTHROUGH_SEQ \
    PASSTHROUGH_ENTRY_unlinkat \
    PASSTHROUGH_ENTRY_mkdirat \
    PASSTHROUGH_ENTRY_faccessat \
    PASSTHROUGH_ENTRY_openat \
    PASSTHROUGH_ENTRY_newfstatat \
    PASSTHROUGH_ENTRY_readlinkat \
    PASSTHROUGH_ENTRY_statx

#endif /* FAKECHROOT_SYSCALL_H */
