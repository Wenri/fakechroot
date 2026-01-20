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
 * syscall_macros.h - Macros for syscall wrapper generation
 *
 * These macros reduce boilerplate in syscall.c by providing templates for
 * common syscall wrapper patterns:
 *
 * 1. AT_PASSTHROUGH_N: AT syscalls that pass through with path expansion
 *    (dirfd, pathname, N extra args)
 *
 * 2. AT_REDIRECT_N: AT syscalls that redirect to another syscall
 *    (dirfd, pathname, args -> target_syscall with different args)
 *
 * 3. PATH_REDIRECT_N: Non-AT syscalls with path that redirect to AT version
 *    (pathname -> AT_FDCWD + pathname)
 *
 * 4. REDIRECT_N: Non-path syscalls that redirect to another syscall
 *
 * All arguments after pathname are extracted as `long` which is safe because:
 * - This matches glibc's syscall() implementation
 * - The kernel expects register-sized arguments
 * - Unused high bits are ignored
 */

#ifndef SYSCALL_MACROS_H
#define SYSCALL_MACROS_H

/*
 * ============================================================================
 * AT Pass-through syscalls: expand path and call same syscall
 * Pattern: syscall(dirfd, pathname, ...) with path expansion
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
        expand_chroot_path_at(dirfd, pathname); \
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
        expand_chroot_path_at(dirfd, pathname); \
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
        expand_chroot_path_at(dirfd, pathname); \
        return nextcall(syscall)(number, dirfd, pathname, a3, a4, a5); \
    }

/*
 * ============================================================================
 * AT Redirect syscalls: expand path and redirect to different syscall
 * Pattern: syscall(dirfd, pathname, ...) -> target(dirfd, pathname, ...)
 * ============================================================================
 */

/* AT redirect with 1 arg: syscall(dirfd, path, a3) -> target(dirfd, path, a3, extra) */
#define AT_REDIRECT_1(sysnum, target, extra) \
    case sysnum: { \
        int dirfd = va_arg(ap, int); \
        const char *pathname = va_arg(ap, const char *); \
        long a3 = va_arg(ap, long); \
        va_end(ap); \
        debug("syscall(" #sysnum ", %d, \"%s\", %ld) -> " #target, dirfd, pathname, a3); \
        expand_chroot_path_at(dirfd, pathname); \
        return nextcall(syscall)(target, dirfd, pathname, a3, extra); \
    }

/*
 * ============================================================================
 * PATH Redirect syscalls: non-AT syscall redirects to AT version
 * Pattern: syscall(pathname, ...) -> target(AT_FDCWD, pathname, ...)
 * ============================================================================
 */

/* Path redirect with 1 arg: syscall(path, a2) -> target(AT_FDCWD, path, a2, extra) */
#define PATH_REDIRECT_1(sysnum, target, extra) \
    case sysnum: { \
        const char *pathname = va_arg(ap, const char *); \
        long a2 = va_arg(ap, long); \
        va_end(ap); \
        debug("syscall(" #sysnum ", \"%s\", %ld) -> " #target, pathname, a2); \
        expand_chroot_path(pathname); \
        return nextcall(syscall)(target, AT_FDCWD, pathname, a2, extra); \
    }

/* Path redirect with 2 args: syscall(path, a2, a3) -> target(AT_FDCWD, path, a2, a3, extra) */
#define PATH_REDIRECT_2(sysnum, target, extra) \
    case sysnum: { \
        const char *pathname = va_arg(ap, const char *); \
        long a2 = va_arg(ap, long); \
        long a3 = va_arg(ap, long); \
        va_end(ap); \
        debug("syscall(" #sysnum ", \"%s\", ...) -> " #target, pathname); \
        expand_chroot_path(pathname); \
        return nextcall(syscall)(target, AT_FDCWD, pathname, a2, a3, extra); \
    }

/* Path redirect with 0 args: syscall(path) -> target(AT_FDCWD, path, extra) */
#define PATH_REDIRECT_0(sysnum, target, extra) \
    case sysnum: { \
        const char *pathname = va_arg(ap, const char *); \
        va_end(ap); \
        debug("syscall(" #sysnum ", \"%s\") -> " #target, pathname); \
        expand_chroot_path(pathname); \
        return nextcall(syscall)(target, AT_FDCWD, pathname, extra); \
    }

/*
 * ============================================================================
 * Non-path redirect syscalls: redirect to different syscall
 * Pattern: syscall(args...) -> target(args..., extra)
 * ============================================================================
 */

/* Redirect with 3 args: syscall(a1, a2, a3) -> target(a1, a2, a3, extra) */
#define REDIRECT_3(sysnum, target, extra) \
    case sysnum: { \
        long a1 = va_arg(ap, long); \
        long a2 = va_arg(ap, long); \
        long a3 = va_arg(ap, long); \
        va_end(ap); \
        debug("syscall(" #sysnum ", ...) -> " #target); \
        return nextcall(syscall)(target, a1, a2, a3, extra); \
    }

/* Redirect with 4 args: syscall(a1, a2, a3, a4) -> target(a1, a2, a3, a4, extra1, extra2) */
#define REDIRECT_4_2(sysnum, target, extra1, extra2) \
    case sysnum: { \
        long a1 = va_arg(ap, long); \
        long a2 = va_arg(ap, long); \
        long a3 = va_arg(ap, long); \
        long a4 = va_arg(ap, long); \
        va_end(ap); \
        debug("syscall(" #sysnum ", ...) -> " #target); \
        return nextcall(syscall)(target, a1, a2, a3, a4, extra1, extra2); \
    }

/* Redirect with 0 args: syscall() -> target(extra) */
#define REDIRECT_0(sysnum, target, extra) \
    case sysnum: { \
        va_end(ap); \
        debug("syscall(" #sysnum ") -> " #target "(" #extra ")"); \
        return nextcall(syscall)(target, extra); \
    }

/*
 * ============================================================================
 * Special cases for symlink/link (multiple paths)
 * ============================================================================
 */

/* symlink(target, linkpath) -> symlinkat(target, AT_FDCWD, linkpath) */
#define SYMLINK_REDIRECT(sysnum, target) \
    case sysnum: { \
        const char *oldpath = va_arg(ap, const char *); \
        const char *newpath = va_arg(ap, const char *); \
        va_end(ap); \
        debug("syscall(" #sysnum ", \"%s\", \"%s\") -> " #target, oldpath, newpath); \
        expand_chroot_path(newpath); \
        return nextcall(syscall)(target, oldpath, AT_FDCWD, newpath); \
    }

/* link(oldpath, newpath) -> linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0) */
#define LINK_REDIRECT(sysnum, target) \
    case sysnum: { \
        const char *oldpath = va_arg(ap, const char *); \
        const char *newpath = va_arg(ap, const char *); \
        va_end(ap); \
        debug("syscall(" #sysnum ", \"%s\", \"%s\") -> " #target, oldpath, newpath); \
        expand_chroot_path(oldpath); \
        expand_chroot_path(newpath); \
        return nextcall(syscall)(target, AT_FDCWD, oldpath, AT_FDCWD, newpath, 0); \
    }

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
 * Redirect Table - Single source of truth for all syscall redirects
 *
 * This X-macro table defines all syscall redirects in one place.
 * It is expanded differently in syscall.c (va_arg + path expansion) and
 * sigaction.c (register access for SIGSYS handler).
 *
 * X-macro patterns:
 *   AT_REDIRECT_X(from, to, extra)      - AT syscall drops last arg, adds extra
 *   PATH_REDIRECT_0_X(from, to, extra)  - path → AT_FDCWD + path + extra
 *   PATH_REDIRECT_1_X(from, to, extra)  - path + 1 arg → AT_FDCWD + path + arg + extra
 *   PATH_REDIRECT_2_X(from, to, extra)  - path + 2 args → AT_FDCWD + path + args + extra
 *   REDIRECT_0_X(from, to, extra)       - no args → extra
 *   REDIRECT_3_X(from, to, extra)       - 3 args → 3 args + extra
 *   REDIRECT_4_2_X(from, to, e1, e2)    - 4 args → 4 args + 2 extras
 *   SYMLINK_REDIRECT_X(from, to)        - target + path → target + AT_FDCWD + path
 *   LINK_REDIRECT_X(from, to)           - old + new → AT_FDCWD + old + AT_FDCWD + new + 0
 *
 * Note: Each entry is wrapped in #ifdef because some syscalls don't exist on
 * all architectures (e.g., chmod, chown, rmdir are x86-only legacy syscalls;
 * aarch64 only has the *at versions).
 * ============================================================================
 */

/* Newer syscalls that have older fallbacks */
#ifdef SYS_faccessat2
#define REDIRECT_faccessat2 AT_REDIRECT_X(faccessat2, faccessat, 0)
#else
#define REDIRECT_faccessat2
#endif

#ifdef SYS_fchmodat2
#define REDIRECT_fchmodat2 AT_REDIRECT_X(fchmodat2, fchmodat, 0)
#else
#define REDIRECT_fchmodat2
#endif

/* Legacy syscalls redirected to *at versions (x86 only) */
#ifdef SYS_chmod
#define REDIRECT_chmod PATH_REDIRECT_1_X(chmod, fchmodat, 0)
#else
#define REDIRECT_chmod
#endif

#ifdef SYS_chown
#define REDIRECT_chown PATH_REDIRECT_2_X(chown, fchownat, 0)
#else
#define REDIRECT_chown
#endif

#ifdef SYS_chown32
#define REDIRECT_chown32 PATH_REDIRECT_2_X(chown32, fchownat, 0)
#else
#define REDIRECT_chown32
#endif

#ifdef SYS_rmdir
#define REDIRECT_rmdir PATH_REDIRECT_0_X(rmdir, unlinkat, AT_REMOVEDIR)
#else
#define REDIRECT_rmdir
#endif

/* Socket syscalls (may be legacy on some archs) */
#ifdef SYS_accept
#define REDIRECT_accept REDIRECT_3_X(accept, accept4, 0)
#else
#define REDIRECT_accept
#endif

#ifdef SYS_recv
#define REDIRECT_recv REDIRECT_4_2_X(recv, recvfrom, 0, 0)
#else
#define REDIRECT_recv
#endif

#ifdef SYS_send
#define REDIRECT_send REDIRECT_4_2_X(send, sendto, 0, 0)
#else
#define REDIRECT_send
#endif

/* Process syscalls */
#ifdef SYS_getpgrp
#define REDIRECT_getpgrp REDIRECT_0_X(getpgrp, getpgid, 0)
#else
#define REDIRECT_getpgrp
#endif

/* Filesystem syscalls */
#ifdef SYS_symlink
#define REDIRECT_symlink SYMLINK_REDIRECT_X(symlink, symlinkat)
#else
#define REDIRECT_symlink
#endif

#ifdef SYS_link
#define REDIRECT_link LINK_REDIRECT_X(link, linkat)
#else
#define REDIRECT_link
#endif

/* Combined redirect table - expands to all defined redirects */
#define REDIRECT_TABLE \
    REDIRECT_faccessat2 \
    REDIRECT_fchmodat2 \
    REDIRECT_chmod \
    REDIRECT_chown \
    REDIRECT_chown32 \
    REDIRECT_rmdir \
    REDIRECT_accept \
    REDIRECT_recv \
    REDIRECT_send \
    REDIRECT_getpgrp \
    REDIRECT_symlink \
    REDIRECT_link

#endif /* SYSCALL_MACROS_H */
