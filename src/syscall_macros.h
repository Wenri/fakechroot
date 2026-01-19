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

#endif /* SYSCALL_MACROS_H */
