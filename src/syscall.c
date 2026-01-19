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
 * syscall() wrapper for direct syscall interception.
 *
 * This intercepts calls to syscall() and translates paths for path-related
 * syscalls. This handles cases where libraries (like libuv) bypass glibc
 * wrappers and call syscall() directly.
 *
 * Note: Extracting 6 va_arg unconditionally is the standard pattern used by
 * glibc's own syscall() implementation. The kernel expects 6 register
 * arguments (x0-x5 on aarch64) and ignores unused ones.
 */

#include <config.h>

#ifdef HAVE_SYS_SYSCALL_H

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>        /* AT_FDCWD, AT_REMOVEDIR */
#include <sys/socket.h>   /* socket types */
#include "libfakechroot.h"
#include "android_syscalls.h"

/* Declare the saved handler from sigaction.c */
extern struct sigaction saved_sigsys_handler;


wrapper(syscall, long, (long number, ...))
{
    char fakechroot_abspath[FAKECHROOT_PATH_MAX];
    char fakechroot_buf[FAKECHROOT_PATH_MAX];
    va_list ap;
    va_start(ap, number);

    switch (number) {
#ifdef SYS_statx
    case SYS_statx: {
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        unsigned int mask = va_arg(ap, unsigned int);
        void *statxbuf = va_arg(ap, void *);
        va_end(ap);
        debug("syscall(SYS_statx, %d, \"%s\", %d, %u, %p)", dirfd, pathname, flags, mask, statxbuf);
        expand_chroot_path_at(dirfd, pathname);
        return nextcall(syscall)(number, dirfd, pathname, flags, mask, statxbuf);
    }
#endif

#ifdef SYS_openat
    case SYS_openat: {
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        int mode = va_arg(ap, int);
        va_end(ap);
        debug("syscall(SYS_openat, %d, \"%s\", %d, %o)", dirfd, pathname, flags, mode);
        expand_chroot_path_at(dirfd, pathname);
        return nextcall(syscall)(number, dirfd, pathname, flags, mode);
    }
#endif

#ifdef SYS_faccessat
    case SYS_faccessat: {
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        int mode = va_arg(ap, int);
        int flags = va_arg(ap, int);
        va_end(ap);
        debug("syscall(SYS_faccessat, %d, \"%s\", %d, %d)", dirfd, pathname, mode, flags);
        expand_chroot_path_at(dirfd, pathname);
        return nextcall(syscall)(number, dirfd, pathname, mode, flags);
    }
#endif

#ifdef SYS_newfstatat
    case SYS_newfstatat: {
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        void *statbuf = va_arg(ap, void *);
        int flags = va_arg(ap, int);
        va_end(ap);
        debug("syscall(SYS_newfstatat, %d, \"%s\", %p, %d)", dirfd, pathname, statbuf, flags);
        expand_chroot_path_at(dirfd, pathname);
        return nextcall(syscall)(number, dirfd, pathname, statbuf, flags);
    }
#endif

#ifdef SYS_readlinkat
    case SYS_readlinkat: {
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        char *buf = va_arg(ap, char *);
        size_t bufsiz = va_arg(ap, size_t);
        va_end(ap);
        debug("syscall(SYS_readlinkat, %d, \"%s\", %p, %zu)", dirfd, pathname, buf, bufsiz);
        expand_chroot_path_at(dirfd, pathname);
        return nextcall(syscall)(number, dirfd, pathname, buf, bufsiz);
    }
#endif

#ifdef SYS_unlinkat
    case SYS_unlinkat: {
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        int flags = va_arg(ap, int);
        va_end(ap);
        debug("syscall(SYS_unlinkat, %d, \"%s\", %d)", dirfd, pathname, flags);
        expand_chroot_path_at(dirfd, pathname);
        return nextcall(syscall)(number, dirfd, pathname, flags);
    }
#endif

#ifdef SYS_mkdirat
    case SYS_mkdirat: {
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        int mode = va_arg(ap, int);
        va_end(ap);
        debug("syscall(SYS_mkdirat, %d, \"%s\", %o)", dirfd, pathname, mode);
        expand_chroot_path_at(dirfd, pathname);
        return nextcall(syscall)(number, dirfd, pathname, mode);
    }
#endif

    /* ================================================================
     * Android seccomp bypass - redirect blocked syscalls to alternatives
     * Based on glibc's fakesyscall.json from Termux patches
     * ================================================================ */

    /* --- Category 1: Redirect to replacement syscalls --- */

#ifdef SYS_faccessat2
    case SYS_faccessat2: {
        /* faccessat2(dirfd, path, mode, flags) -> faccessat(dirfd, path, mode, 0) */
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        int mode = va_arg(ap, int);
        va_end(ap);
        debug("syscall(SYS_faccessat2, %d, \"%s\", %d) -> faccessat", dirfd, pathname, mode);
        expand_chroot_path_at(dirfd, pathname);
        return nextcall(syscall)(SYS_faccessat, dirfd, pathname, mode, 0);
    }
#endif

#ifdef SYS_chmod
    case SYS_chmod: {
        /* chmod(path, mode) -> fchmodat(AT_FDCWD, path, mode, 0) */
        const char *pathname = va_arg(ap, const char *);
        mode_t mode = va_arg(ap, mode_t);
        va_end(ap);
        debug("syscall(SYS_chmod, \"%s\", %o) -> fchmodat", pathname, mode);
        expand_chroot_path(pathname);
        return nextcall(syscall)(SYS_fchmodat, AT_FDCWD, pathname, mode, 0);
    }
#endif

#ifdef SYS_fchmodat2
    case SYS_fchmodat2: {
        /* fchmodat2(dirfd, path, mode, flags) -> fchmodat(dirfd, path, mode, 0) */
        int dirfd = va_arg(ap, int);
        const char *pathname = va_arg(ap, const char *);
        mode_t mode = va_arg(ap, mode_t);
        va_end(ap);
        debug("syscall(SYS_fchmodat2, %d, \"%s\", %o) -> fchmodat", dirfd, pathname, mode);
        expand_chroot_path_at(dirfd, pathname);
        return nextcall(syscall)(SYS_fchmodat, dirfd, pathname, mode, 0);
    }
#endif

#ifdef SYS_chown
    case SYS_chown: {
        /* chown(path, uid, gid) -> fchownat(AT_FDCWD, path, uid, gid, 0) */
        const char *pathname = va_arg(ap, const char *);
        uid_t owner = va_arg(ap, uid_t);
        gid_t group = va_arg(ap, gid_t);
        va_end(ap);
        debug("syscall(SYS_chown, \"%s\", %d, %d) -> fchownat", pathname, owner, group);
        expand_chroot_path(pathname);
        return nextcall(syscall)(SYS_fchownat, AT_FDCWD, pathname, owner, group, 0);
    }
#endif

#ifdef SYS_chown32
    case SYS_chown32: {
        const char *pathname = va_arg(ap, const char *);
        uid_t owner = va_arg(ap, uid_t);
        gid_t group = va_arg(ap, gid_t);
        va_end(ap);
        debug("syscall(SYS_chown32) -> fchownat");
        expand_chroot_path(pathname);
        return nextcall(syscall)(SYS_fchownat, AT_FDCWD, pathname, owner, group, 0);
    }
#endif

#ifdef SYS_accept
    case SYS_accept: {
        /* accept(sockfd, addr, addrlen) -> accept4(sockfd, addr, addrlen, 0) */
        int sockfd = va_arg(ap, int);
        void *addr = va_arg(ap, void *);
        void *addrlen = va_arg(ap, void *);
        va_end(ap);
        debug("syscall(SYS_accept) -> accept4");
        return nextcall(syscall)(SYS_accept4, sockfd, addr, addrlen, 0);
    }
#endif

#ifdef SYS_recv
    case SYS_recv: {
        /* recv(fd, buf, len, flags) -> recvfrom(fd, buf, len, flags, NULL, NULL) */
        int sockfd = va_arg(ap, int);
        void *buf = va_arg(ap, void *);
        size_t len = va_arg(ap, size_t);
        int flags = va_arg(ap, int);
        va_end(ap);
        debug("syscall(SYS_recv) -> recvfrom");
        return nextcall(syscall)(SYS_recvfrom, sockfd, buf, len, flags, NULL, NULL);
    }
#endif

#ifdef SYS_send
    case SYS_send: {
        /* send(fd, buf, len, flags) -> sendto(fd, buf, len, flags, NULL, 0) */
        int sockfd = va_arg(ap, int);
        const void *buf = va_arg(ap, const void *);
        size_t len = va_arg(ap, size_t);
        int flags = va_arg(ap, int);
        va_end(ap);
        debug("syscall(SYS_send) -> sendto");
        return nextcall(syscall)(SYS_sendto, sockfd, buf, len, flags, NULL, 0);
    }
#endif

#ifdef SYS_symlink
    case SYS_symlink: {
        /* symlink(target, linkpath) -> symlinkat(target, AT_FDCWD, linkpath) */
        const char *target = va_arg(ap, const char *);
        const char *linkpath = va_arg(ap, const char *);
        va_end(ap);
        debug("syscall(SYS_symlink) -> symlinkat");
        expand_chroot_path(linkpath);
        return nextcall(syscall)(SYS_symlinkat, target, AT_FDCWD, linkpath);
    }
#endif

#ifdef SYS_link
    case SYS_link: {
        /* link(oldpath, newpath) -> linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0) */
        const char *oldpath = va_arg(ap, const char *);
        const char *newpath = va_arg(ap, const char *);
        va_end(ap);
        debug("syscall(SYS_link) -> linkat");
        expand_chroot_path(oldpath);
        expand_chroot_path(newpath);
        return nextcall(syscall)(SYS_linkat, AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
    }
#endif

#ifdef SYS_rmdir
    case SYS_rmdir: {
        /* rmdir(path) -> unlinkat(AT_FDCWD, path, AT_REMOVEDIR) */
        const char *pathname = va_arg(ap, const char *);
        va_end(ap);
        debug("syscall(SYS_rmdir) -> unlinkat");
        expand_chroot_path(pathname);
        return nextcall(syscall)(SYS_unlinkat, AT_FDCWD, pathname, AT_REMOVEDIR);
    }
#endif

#ifdef SYS_getpgrp
    case SYS_getpgrp: {
        /* getpgrp() -> getpgid(0) */
        va_end(ap);
        debug("syscall(SYS_getpgrp) -> getpgid(0)");
        return nextcall(syscall)(SYS_getpgid, 0);
    }
#endif

    /* --- Category 2 & 3: Use shared functions from android_syscalls.h --- */
    /* Category 2 (uid/gid no-ops) and Category 3 (blocked syscalls) are now */
    /* handled in the default case using is_noop_syscall()/is_blocked_syscall() */

#ifdef SYS_rt_sigaction
    /*
     * Intercept rt_sigaction syscall to protect our SIGSYS handler.
     *
     * Python's subprocess module and other programs reset signal handlers
     * to SIG_DFL before exec() using raw syscall() instead of sigaction().
     * This bypasses our sigaction() wrapper.
     *
     * When SIGSYS is reset to SIG_DFL and a seccomp-blocked syscall is made,
     * the process dies instead of using our handler that returns ENOSYS.
     *
     * Solution: Intercept attempts to reset SIGSYS and keep our handler.
     */
    case SYS_rt_sigaction: {
        int signum = va_arg(ap, int);
        struct sigaction *act = va_arg(ap, struct sigaction *);
        struct sigaction *oldact = va_arg(ap, struct sigaction *);
        size_t sigsetsize = va_arg(ap, size_t);
        va_end(ap);

        /* Only intercept SIGSYS */
        if (signum != SIGSYS) {
            return nextcall(syscall)(number, signum, act, oldact, sigsetsize);
        }

        debug("syscall(SYS_rt_sigaction, SIGSYS, %p, %p, %zu)", act, oldact, sigsetsize);

        /* Return the saved handler if requested */
        if (oldact != NULL) {
            memcpy(oldact, &saved_sigsys_handler, sizeof(struct sigaction));
        }

        /* If just querying (act == NULL), we're done */
        if (act == NULL) {
            return 0;
        }

        /* Someone is trying to change SIGSYS handler */
        /* Save their handler for chaining but don't actually install it */
        debug("syscall: blocking SIGSYS handler change to %p", act->sa_handler);
        memcpy(&saved_sigsys_handler, act, sizeof(struct sigaction));

        /* Return success without actually changing the handler */
        return 0;
    }
#endif

    default: {
        /* Category 2: uid/gid syscalls return 0 (no-op on Android) */
        if (is_noop_syscall(number)) {
            va_end(ap);
            debug("syscall(%ld) -> 0 (uid/gid no-op)", number);
            return 0;
        }

        /* Category 3: blocked syscalls return ENOSYS */
        if (is_blocked_syscall(number)) {
            va_end(ap);
            debug("syscall(%ld) -> ENOSYS (blocked)", number);
            errno = ENOSYS;
            return -1;
        }

        /* Pass through all other syscalls with up to 6 args.
         * This matches glibc's syscall() implementation which also
         * extracts exactly 6 va_arg unconditionally. */
        long a1 = va_arg(ap, long);
        long a2 = va_arg(ap, long);
        long a3 = va_arg(ap, long);
        long a4 = va_arg(ap, long);
        long a5 = va_arg(ap, long);
        long a6 = va_arg(ap, long);
        va_end(ap);
        return nextcall(syscall)(number, a1, a2, a3, a4, a5, a6);
    }
    }
}

#else
typedef int empty_translation_unit;
#endif
