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
#include "libfakechroot.h"

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

#ifdef SYS_close_range
    /*
     * Intercept close_range syscall - blocked by Android seccomp.
     * Return ENOSYS so callers fall back to closing FDs one by one.
     */
    case SYS_close_range: {
        unsigned int first = va_arg(ap, unsigned int);
        unsigned int last = va_arg(ap, unsigned int);
        unsigned int flags = va_arg(ap, unsigned int);
        va_end(ap);
        debug("syscall(SYS_close_range, %u, %u, %u) -> ENOSYS", first, last, flags);
        errno = ENOSYS;
        return -1;
    }
#endif

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
