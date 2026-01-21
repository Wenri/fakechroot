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
 * - Context types: long[6] array in syscall.c, ucontext_t* in sigaction.c
 *
 * Patterns supported (8 macros in 5 groups):
 * - Group 1: FORWARD (no path handling)
 * - Group 2: PATH0, PATH0_DIRECT (path at arg 0)
 * - Group 3: AT1, AT2 (AT-style with dirfd)
 * - Group 4: PATH1 (path at arg 1, no dirfd)
 * - Group 5: LINK2, AT1_AT3 (two paths)
 */

#ifndef FAKECHROOT_SYSCALL_H
#define FAKECHROOT_SYSCALL_H

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/tuple/elem.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/arithmetic/add.hpp>
#include <boost/preprocessor/control/expr_if.hpp>
#include <boost/preprocessor/punctuation/comma_if.hpp>
#include <boost/preprocessor/logical/not.hpp>

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
 * - sigaction.c: ucontext_t *_ctx = ctx
 *
 * CTX_ARG - Argument accessor:
 * - syscall.c: #define CTX_ARG(ctx, n) (ctx)[n]
 * - sigaction.c: #define CTX_ARG(ctx, n) sigsys_get_arg(ctx, n)
 *
 * CTX_EXPAND_PATH - Path expansion for chroot (arg index):
 * - syscall.c: expand_chroot_path(path, alloca(FAKECHROOT_PATH_MAX))
 * - sigaction.c: (const char *)CTX_ARG(ctx, n)  [no-op in signal handler]
 *
 * CTX_EXPAND_PATH_AT - Path expansion for AT syscalls (dirfd index, path index):
 * - syscall.c: expand_chroot_path_at(dirfd, path, alloca(FAKECHROOT_PATH_MAX))
 * - sigaction.c: (const char *)CTX_ARG(ctx, n)  [no-op in signal handler]
 *
 * CTX_DONE - Result handling (return or goto):
 * - syscall.c: va_end(ap); return val;
 * - sigaction.c: ret = val; goto set_return;
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
 * - p1, p2: Pattern-specific parameters (see table below)
 *
 * Each macro uses context-specific macros that must be defined by the
 * including file: CTX_SETUP, CTX_ARG, CTX_EXPAND_PATH*, CTX_DONE
 * ============================================================================
 */

/*
 * All macros take 4 parameters: (from, to, p1, p2)
 * This allows uniform dispatch from REDIRECT_SEQ entries.
 *
 * ============================================================================
 * Macro Comparison Table (8 macros in 5 groups)
 * ============================================================================
 * | Macro       | Input Args                           | Path Expansion     | Output Format                         | p1      | p2        |
 * |-------------|--------------------------------------|--------------------|---------------------------------------|---------|-----------|
 * | FORWARD     | args...                              | none               | to(args..., 0...)                     | nargs   | nzeros    |
 * |-------------|--------------------------------------|--------------------|---------------------------------------|---------|-----------|
 * | PATH0       | path, ...                            | arg 0              | to(AT_FDCWD, path, ..., extra)        | nargs   | extra     |
 * | PATH0_DIRECT| path, ...                            | arg 0              | to(path, ...)                         | nargs   | _         |
 * |-------------|--------------------------------------|--------------------|---------------------------------------|---------|-----------|
 * | AT1         | dirfd, path, ...                     | arg 1 (AT)         | to(dirfd, path, ..., 0...)            | nargs   | nzeros    |
 * | AT2         | arg0, dirfd, path                    | arg 2 (AT)         | to(arg0, dirfd, path)                 | _       | _         |
 * |-------------|--------------------------------------|--------------------|---------------------------------------|---------|-----------|
 * | PATH1       | arg0, path, ...                      | arg 1              | to(arg0, [AT_FDCWD,] path, ...)       | nargs   | fdcwd     |
 * |-------------|--------------------------------------|--------------------|---------------------------------------|---------|-----------|
 * | LINK2       | path0, path1                         | args 0,1           | to(AT_FDCWD, path0, AT_FDCWD, path1, 0)| _      | _         |
 * | AT1_AT3     | dirfd0, path1, dirfd2, path3[, ...]  | args 1,3 (AT)      | to(dirfd0, path1, dirfd2, path3, ...) | nargs   | _         |
 * ============================================================================
 */

/* Helper: emit ", CTX_ARG(_ctx, n+x)" for BOOST_PP_REPEAT (x = starting arg index) */
#define SYS_GEN_EMIT_ARG_FROMX(z, n, x) , CTX_ARG(_ctx, BOOST_PP_ADD(n, x))

/* Helper: emit ", x" for BOOST_PP_REPEAT (trailing constant value) */
#define SYS_GEN_EMIT_X(z, n, x) , x

/* Dispatch macro for BOOST_PP_SEQ_FOR_EACH */
#define SYS_GEN_DISPATCH(r, n, elem) \
    BOOST_PP_CAT(SYS_GEN_, BOOST_PP_TUPLE_ELEM(0, elem))( \
        BOOST_PP_TUPLE_ELEM(1, elem), \
        BOOST_PP_TUPLE_ELEM(2, elem), \
        BOOST_PP_TUPLE_ELEM(3, elem), \
        BOOST_PP_TUPLE_ELEM(4, elem))

/* ============================================================================
 * Group 1: No path handling
 * ============================================================================ */

/* FORWARD: syscall(args...) -> target(args..., 0...)
 * p1: nargs, p2: nzeros */
#define SYS_GEN_FORWARD(from, to, p1, p2) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        BOOST_PP_EXPR_IF(BOOST_PP_NOT(p1), (void)_ctx;) \
        long result = nextcall(syscall)(BOOST_PP_CAT(SYS_, to) \
            BOOST_PP_REPEAT(p1, SYS_GEN_EMIT_ARG_FROMX, 0) \
            BOOST_PP_REPEAT(p2, SYS_GEN_EMIT_X, 0)); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        CTX_DONE(result); \
    }

/* ============================================================================
 * Group 2: Single path at position 0
 * ============================================================================ */

/* PATH0: syscall(path, ...) -> target(AT_FDCWD, path, ..., extra)
 * p1: nargs, p2: extra value to append */
#define SYS_GEN_PATH0(from, to, p1, p2) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH(_ctx, 0); \
        long result = nextcall(syscall)(BOOST_PP_CAT(SYS_, to), AT_FDCWD, _path \
            BOOST_PP_REPEAT(p1, SYS_GEN_EMIT_ARG_FROMX, 1), p2); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        CTX_DONE(result); \
    }

/* PATH0_DIRECT: syscall(path, ...) -> same(expanded_path, ...)
 * Direct passthrough without AT_FDCWD prepend
 * p1: nargs, p2: unused */
#define SYS_GEN_PATH0_DIRECT(from, to, p1, p2) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH(_ctx, 0); \
        long result = nextcall(syscall)(BOOST_PP_CAT(SYS_, to), _path \
            BOOST_PP_REPEAT(p1, SYS_GEN_EMIT_ARG_FROMX, 1)); \
        debug("syscall: " #from " = %ld", result); \
        CTX_DONE(result); \
    }

/* ============================================================================
 * Group 3: Single path with dirfd (AT-style)
 * ============================================================================ */

/* AT1: syscall(dirfd, path, ...) -> to(dirfd, expanded_path, ..., 0...)
 * dirfd@0, path@1
 * p1: nargs, p2: nzeros */
#define SYS_GEN_AT1(from, to, p1, p2) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH_AT(_ctx, 0, 1); \
        long result = nextcall(syscall)(BOOST_PP_CAT(SYS_, to), CTX_ARG(_ctx, 0), _path \
            BOOST_PP_REPEAT(p1, SYS_GEN_EMIT_ARG_FROMX, 2) \
            BOOST_PP_REPEAT(p2, SYS_GEN_EMIT_X, 0)); \
        debug("syscall: " #from " -> " #to " = %ld", result); \
        CTX_DONE(result); \
    }

/* AT2: syscall(arg0, dirfd, path) -> to(arg0, dirfd, expanded_path)
 * dirfd@1, path@2 (e.g., symlinkat: target, dirfd, linkpath)
 * p1, p2: unused */
#define SYS_GEN_AT2(from, to, p1, p2) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH_AT(_ctx, 1, 2); \
        long result = nextcall(syscall)(BOOST_PP_CAT(SYS_, to), \
            CTX_ARG(_ctx, 0), CTX_ARG(_ctx, 1), _path); \
        debug("syscall: " #from " = %ld", result); \
        CTX_DONE(result); \
    }

/* ============================================================================
 * Group 4: Single path at position 1, no dirfd
 * ============================================================================ */

/* PATH1: syscall(arg0, path, ...) -> to(arg0, [AT_FDCWD,] path, ...)
 * p1: nargs, p2: fdcwd (1=insert AT_FDCWD after arg0) */
#define SYS_GEN_PATH1(from, to, p1, p2) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path = CTX_EXPAND_PATH(_ctx, 1); \
        long result = nextcall(syscall)(BOOST_PP_CAT(SYS_, to), \
            CTX_ARG(_ctx, 0) BOOST_PP_COMMA_IF(p2) BOOST_PP_EXPR_IF(p2, AT_FDCWD), _path \
            BOOST_PP_REPEAT(p1, SYS_GEN_EMIT_ARG_FROMX, 2)); \
        debug("syscall: " #from " = %ld", result); \
        CTX_DONE(result); \
    }

/* ============================================================================
 * Group 5: Two paths
 * ============================================================================ */

/* LINK2: syscall(path0, path1) -> to(AT_FDCWD, path0, AT_FDCWD, path1, 0)
 * p1, p2: unused */
#define SYS_GEN_LINK2(from, to, p1, p2) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_oldpath = CTX_EXPAND_PATH(_ctx, 0); \
        const char *_newpath = CTX_EXPAND_PATH(_ctx, 1); \
        long result = nextcall(syscall)(BOOST_PP_CAT(SYS_, to), AT_FDCWD, _oldpath, AT_FDCWD, _newpath, 0); \
        debug("redirect: " #from " -> " #to " = %ld", result); \
        CTX_DONE(result); \
    }

/* AT1_AT3: syscall(dirfd0, path1, dirfd2, path3[, ...]) -> to(...)
 * Two (dirfd, path) pairs at positions (0,1) and (2,3)
 * p1: nargs (trailing args after path3), p2: unused */
#define SYS_GEN_AT1_AT3(from, to, p1, p2) \
    case BOOST_PP_CAT(SYS_, from): { \
        CTX_SETUP(_ctx); \
        const char *_path1 = CTX_EXPAND_PATH_AT(_ctx, 0, 1); \
        const char *_path3 = CTX_EXPAND_PATH_AT(_ctx, 2, 3); \
        long result = nextcall(syscall)(BOOST_PP_CAT(SYS_, to), \
            CTX_ARG(_ctx, 0), _path1, CTX_ARG(_ctx, 2), _path3 \
            BOOST_PP_REPEAT(p1, SYS_GEN_EMIT_ARG_FROMX, 4)); \
        debug("syscall: " #from " = %ld", result); \
        CTX_DONE(result); \
    }

/*
 * ============================================================================
 * Redirect Table as Boost.PP Sequence
 *
 * Each entry is a 4-tuple: (PATTERN, from, to, p1, p2)
 * - PATTERN: Generator macro suffix (FORWARD, PATH0, AT1, PATH1, LINK2, etc.)
 * - from: Source syscall name (without SYS_ prefix)
 * - to: Target syscall name (without SYS_ prefix)
 * - p1, p2: Pattern-specific parameters (see table above)
 *
 * Entries are conditionally included based on SYS_* availability.
 * ============================================================================
 */

/* Newer syscalls that have older fallbacks
 * Format: (AT1, from, to, nargs, nzeros) */
#ifdef SYS_faccessat2
#define REDIRECT_ENTRY_faccessat2 ((AT1, faccessat2, faccessat, 1, 1))
#else
#define REDIRECT_ENTRY_faccessat2
#endif

#ifdef SYS_fchmodat2
#define REDIRECT_ENTRY_fchmodat2 ((AT1, fchmodat2, fchmodat, 1, 1))
#else
#define REDIRECT_ENTRY_fchmodat2
#endif

/* Legacy syscalls redirected to *at versions (x86 only)
 * Format: (PATH0, from, to, nargs, extra) */
#ifdef SYS_chmod
#define REDIRECT_ENTRY_chmod ((PATH0, chmod, fchmodat, 1, 0))
#else
#define REDIRECT_ENTRY_chmod
#endif

#ifdef SYS_chown
#define REDIRECT_ENTRY_chown ((PATH0, chown, fchownat, 2, 0))
#else
#define REDIRECT_ENTRY_chown
#endif

#ifdef SYS_chown32
#define REDIRECT_ENTRY_chown32 ((PATH0, chown32, fchownat, 2, 0))
#else
#define REDIRECT_ENTRY_chown32
#endif

#ifdef SYS_rmdir
#define REDIRECT_ENTRY_rmdir ((PATH0, rmdir, unlinkat, 0, AT_REMOVEDIR))
#else
#define REDIRECT_ENTRY_rmdir
#endif

/* Socket syscalls (may be legacy on some archs)
 * Format: (FORWARD, from, to, nargs, num_zeros) */
#ifdef SYS_accept
#define REDIRECT_ENTRY_accept ((FORWARD, accept, accept4, 3, 1))
#else
#define REDIRECT_ENTRY_accept
#endif

#ifdef SYS_recv
#define REDIRECT_ENTRY_recv ((FORWARD, recv, recvfrom, 4, 2))
#else
#define REDIRECT_ENTRY_recv
#endif

#ifdef SYS_send
#define REDIRECT_ENTRY_send ((FORWARD, send, sendto, 4, 2))
#else
#define REDIRECT_ENTRY_send
#endif

/* Process syscalls
 * Format: (FORWARD, from, to, nargs, num_zeros) */
#ifdef SYS_getpgrp
#define REDIRECT_ENTRY_getpgrp ((FORWARD, getpgrp, getpgid, 0, 1))
#else
#define REDIRECT_ENTRY_getpgrp
#endif

/* Filesystem syscalls
 * Format: (PATH1/LINK2, from, to, p1, p2) */
#ifdef SYS_symlink
#define REDIRECT_ENTRY_symlink ((PATH1, symlink, symlinkat, 0, 1))
#else
#define REDIRECT_ENTRY_symlink
#endif

#ifdef SYS_link
#define REDIRECT_ENTRY_link ((LINK2, link, linkat, _, _))
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
 * Format: (AT1, syscall, syscall, nargs, 0) - no trailing zeros
 * ============================================================================
 */

#ifdef SYS_unlinkat
#define PASSTHROUGH_ENTRY_unlinkat ((AT1, unlinkat, unlinkat, 1, 0))
#else
#define PASSTHROUGH_ENTRY_unlinkat
#endif

#ifdef SYS_mkdirat
#define PASSTHROUGH_ENTRY_mkdirat ((AT1, mkdirat, mkdirat, 1, 0))
#else
#define PASSTHROUGH_ENTRY_mkdirat
#endif

#ifdef SYS_faccessat
#define PASSTHROUGH_ENTRY_faccessat ((AT1, faccessat, faccessat, 2, 0))
#else
#define PASSTHROUGH_ENTRY_faccessat
#endif

#ifdef SYS_openat
#define PASSTHROUGH_ENTRY_openat ((AT1, openat, openat, 2, 0))
#else
#define PASSTHROUGH_ENTRY_openat
#endif

#ifdef SYS_newfstatat
#define PASSTHROUGH_ENTRY_newfstatat ((AT1, newfstatat, newfstatat, 2, 0))
#else
#define PASSTHROUGH_ENTRY_newfstatat
#endif

#ifdef SYS_readlinkat
#define PASSTHROUGH_ENTRY_readlinkat ((AT1, readlinkat, readlinkat, 2, 0))
#else
#define PASSTHROUGH_ENTRY_readlinkat
#endif

#ifdef SYS_statx
#define PASSTHROUGH_ENTRY_statx ((AT1, statx, statx, 3, 0))
#else
#define PASSTHROUGH_ENTRY_statx
#endif

/* Group 1: Additional AT syscalls (use existing AT pattern) */
#ifdef SYS_fchmodat
#define PASSTHROUGH_ENTRY_fchmodat ((AT1, fchmodat, fchmodat, 2, 0))
#else
#define PASSTHROUGH_ENTRY_fchmodat
#endif

#ifdef SYS_fchownat
#define PASSTHROUGH_ENTRY_fchownat ((AT1, fchownat, fchownat, 3, 0))
#else
#define PASSTHROUGH_ENTRY_fchownat
#endif

#ifdef SYS_mknodat
#define PASSTHROUGH_ENTRY_mknodat ((AT1, mknodat, mknodat, 2, 0))
#else
#define PASSTHROUGH_ENTRY_mknodat
#endif

#ifdef SYS_utimensat
#define PASSTHROUGH_ENTRY_utimensat ((AT1, utimensat, utimensat, 2, 0))
#else
#define PASSTHROUGH_ENTRY_utimensat
#endif

/* Group 2: Two-path AT syscalls */
#ifdef SYS_linkat
#define PASSTHROUGH_ENTRY_linkat ((AT1_AT3, linkat, linkat, 1, _))
#else
#define PASSTHROUGH_ENTRY_linkat
#endif

#ifdef SYS_renameat
#define PASSTHROUGH_ENTRY_renameat ((AT1_AT3, renameat, renameat, 0, _))
#else
#define PASSTHROUGH_ENTRY_renameat
#endif

#ifdef SYS_renameat2
#define PASSTHROUGH_ENTRY_renameat2 ((AT1_AT3, renameat2, renameat2, 1, _))
#else
#define PASSTHROUGH_ENTRY_renameat2
#endif

#ifdef SYS_symlinkat
#define PASSTHROUGH_ENTRY_symlinkat ((AT2, symlinkat, symlinkat, _, _))
#else
#define PASSTHROUGH_ENTRY_symlinkat
#endif

/* Group 3: Non-AT path syscalls */
#ifdef SYS_chdir
#define PASSTHROUGH_ENTRY_chdir ((PATH0_DIRECT, chdir, chdir, 0, _))
#else
#define PASSTHROUGH_ENTRY_chdir
#endif

#ifdef SYS_chroot
#define PASSTHROUGH_ENTRY_chroot ((PATH0_DIRECT, chroot, chroot, 0, _))
#else
#define PASSTHROUGH_ENTRY_chroot
#endif

#ifdef SYS_truncate
#define PASSTHROUGH_ENTRY_truncate ((PATH0_DIRECT, truncate, truncate, 1, _))
#else
#define PASSTHROUGH_ENTRY_truncate
#endif

#ifdef SYS_statfs
#define PASSTHROUGH_ENTRY_statfs ((PATH0_DIRECT, statfs, statfs, 1, _))
#else
#define PASSTHROUGH_ENTRY_statfs
#endif

/* Group 4: Extended attribute syscalls */
#ifdef SYS_getxattr
#define PASSTHROUGH_ENTRY_getxattr ((PATH0_DIRECT, getxattr, getxattr, 3, _))
#else
#define PASSTHROUGH_ENTRY_getxattr
#endif

#ifdef SYS_lgetxattr
#define PASSTHROUGH_ENTRY_lgetxattr ((PATH0_DIRECT, lgetxattr, lgetxattr, 3, _))
#else
#define PASSTHROUGH_ENTRY_lgetxattr
#endif

#ifdef SYS_setxattr
#define PASSTHROUGH_ENTRY_setxattr ((PATH0_DIRECT, setxattr, setxattr, 4, _))
#else
#define PASSTHROUGH_ENTRY_setxattr
#endif

#ifdef SYS_lsetxattr
#define PASSTHROUGH_ENTRY_lsetxattr ((PATH0_DIRECT, lsetxattr, lsetxattr, 4, _))
#else
#define PASSTHROUGH_ENTRY_lsetxattr
#endif

#ifdef SYS_listxattr
#define PASSTHROUGH_ENTRY_listxattr ((PATH0_DIRECT, listxattr, listxattr, 2, _))
#else
#define PASSTHROUGH_ENTRY_listxattr
#endif

#ifdef SYS_llistxattr
#define PASSTHROUGH_ENTRY_llistxattr ((PATH0_DIRECT, llistxattr, llistxattr, 2, _))
#else
#define PASSTHROUGH_ENTRY_llistxattr
#endif

#ifdef SYS_removexattr
#define PASSTHROUGH_ENTRY_removexattr ((PATH0_DIRECT, removexattr, removexattr, 1, _))
#else
#define PASSTHROUGH_ENTRY_removexattr
#endif

#ifdef SYS_lremovexattr
#define PASSTHROUGH_ENTRY_lremovexattr ((PATH0_DIRECT, lremovexattr, lremovexattr, 1, _))
#else
#define PASSTHROUGH_ENTRY_lremovexattr
#endif

/* Group 5: Misc syscalls */
#ifdef SYS_inotify_add_watch
#define PASSTHROUGH_ENTRY_inotify_add_watch ((PATH1, inotify_add_watch, inotify_add_watch, 1, 0))
#else
#define PASSTHROUGH_ENTRY_inotify_add_watch
#endif

#define PASSTHROUGH_SEQ \
    PASSTHROUGH_ENTRY_unlinkat \
    PASSTHROUGH_ENTRY_mkdirat \
    PASSTHROUGH_ENTRY_faccessat \
    PASSTHROUGH_ENTRY_openat \
    PASSTHROUGH_ENTRY_newfstatat \
    PASSTHROUGH_ENTRY_readlinkat \
    PASSTHROUGH_ENTRY_statx \
    /* Group 1: Additional AT syscalls */ \
    PASSTHROUGH_ENTRY_fchmodat \
    PASSTHROUGH_ENTRY_fchownat \
    PASSTHROUGH_ENTRY_mknodat \
    PASSTHROUGH_ENTRY_utimensat \
    /* Group 2: Two-path AT syscalls */ \
    PASSTHROUGH_ENTRY_linkat \
    PASSTHROUGH_ENTRY_renameat \
    PASSTHROUGH_ENTRY_renameat2 \
    PASSTHROUGH_ENTRY_symlinkat \
    /* Group 3: Non-AT path syscalls */ \
    PASSTHROUGH_ENTRY_chdir \
    PASSTHROUGH_ENTRY_chroot \
    PASSTHROUGH_ENTRY_truncate \
    PASSTHROUGH_ENTRY_statfs \
    /* Group 4: Extended attribute syscalls */ \
    PASSTHROUGH_ENTRY_getxattr \
    PASSTHROUGH_ENTRY_lgetxattr \
    PASSTHROUGH_ENTRY_setxattr \
    PASSTHROUGH_ENTRY_lsetxattr \
    PASSTHROUGH_ENTRY_listxattr \
    PASSTHROUGH_ENTRY_llistxattr \
    PASSTHROUGH_ENTRY_removexattr \
    PASSTHROUGH_ENTRY_lremovexattr \
    /* Group 5: Misc */ \
    PASSTHROUGH_ENTRY_inotify_add_watch

#endif /* FAKECHROOT_SYSCALL_H */
