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
#include <fcntl.h>        /* AT_FDCWD, AT_REMOVEDIR, O_RDONLY */
#include <unistd.h>       /* read, close */
#include <sys/prctl.h>    /* prctl, PR_SET_NAME */
#include <sys/socket.h>   /* socket types */
#include "libfakechroot.h"
#include "android_syscalls.h"
#include "syscall_macros.h"
#include "readlink.h"
#include "open.h"

/* Declare the saved handler from sigaction.c */
extern struct sigaction saved_sigsys_handler;


wrapper(syscall, long, (long number, ...))
{
    char fakechroot_abspath[FAKECHROOT_PATH_MAX];
    char fakechroot_buf[FAKECHROOT_PATH_MAX];
    va_list ap;
    va_start(ap, number);

    switch (number) {

    /* ================================================================
     * Pass-through AT syscalls with path expansion
     * These use macros from syscall_macros.h to reduce boilerplate
     * ================================================================ */

#ifdef SYS_unlinkat
    AT_PASSTHROUGH_1(SYS_unlinkat)
#endif
#ifdef SYS_mkdirat
    AT_PASSTHROUGH_1(SYS_mkdirat)
#endif
#ifdef SYS_faccessat
    AT_PASSTHROUGH_2(SYS_faccessat)
#endif
#ifdef SYS_openat
    AT_PASSTHROUGH_2(SYS_openat)
#endif
#ifdef SYS_newfstatat
    AT_PASSTHROUGH_2(SYS_newfstatat)
#endif
#ifdef SYS_readlinkat
    AT_PASSTHROUGH_2(SYS_readlinkat)
#endif
#ifdef SYS_statx
    AT_PASSTHROUGH_3(SYS_statx)
#endif

    /* ================================================================
     * Android seccomp bypass - redirect blocked syscalls to alternatives
     * Uses REDIRECT_TABLE from syscall_macros.h (single source of truth)
     * ================================================================ */

    /* Define X-macros to expand REDIRECT_TABLE with va_arg + path expansion */
#define AT_REDIRECT_X(from, to, extra) \
    AT_REDIRECT_1(SYS_##from, SYS_##to, extra)
#define PATH_REDIRECT_0_X(from, to, extra) \
    PATH_REDIRECT_0(SYS_##from, SYS_##to, extra)
#define PATH_REDIRECT_1_X(from, to, extra) \
    PATH_REDIRECT_1(SYS_##from, SYS_##to, extra)
#define PATH_REDIRECT_2_X(from, to, extra) \
    PATH_REDIRECT_2(SYS_##from, SYS_##to, extra)
#define REDIRECT_0_X(from, to, extra) \
    REDIRECT_0(SYS_##from, SYS_##to, extra)
#define REDIRECT_3_X(from, to, extra) \
    REDIRECT_3(SYS_##from, SYS_##to, extra)
#define REDIRECT_4_2_X(from, to, e1, e2) \
    REDIRECT_4_2(SYS_##from, SYS_##to, e1, e2)
#define SYMLINK_REDIRECT_X(from, to) \
    SYMLINK_REDIRECT(SYS_##from, SYS_##to)
#define LINK_REDIRECT_X(from, to) \
    LINK_REDIRECT(SYS_##from, SYS_##to)

    /* Expand REDIRECT_TABLE - generates all redirect case statements */
    REDIRECT_TABLE

#undef AT_REDIRECT_X
#undef PATH_REDIRECT_0_X
#undef PATH_REDIRECT_1_X
#undef PATH_REDIRECT_2_X
#undef REDIRECT_0_X
#undef REDIRECT_3_X
#undef REDIRECT_4_2_X
#undef SYMLINK_REDIRECT_X
#undef LINK_REDIRECT_X

    /* --- Category 2 & 3: Use shared functions from android_syscalls.h --- */
    /* Category 2 (uid/gid no-ops) and Category 3 (blocked syscalls) are now */
    /* handled in the default case using is_noop_syscall()/is_blocked_syscall() */

#ifdef SYS_rt_sigaction
    /*
     * Intercept rt_sigaction syscall to protect our SIGSYS handler.
     * Uses shared helper from android_syscalls.h (same logic as sigaction wrapper).
     */
    case SYS_rt_sigaction: {
        int signum = va_arg(ap, int);
        struct sigaction *act = va_arg(ap, struct sigaction *);
        struct sigaction *oldact = va_arg(ap, struct sigaction *);
        size_t sigsetsize = va_arg(ap, size_t);
        va_end(ap);

        /* Only intercept SIGSYS - pass through all other signals */
        if (signum != SIGSYS) {
            return nextcall(syscall)(number, signum, act, oldact, sigsetsize);
        }

        debug("syscall(SYS_rt_sigaction, SIGSYS, %p, %p, %zu)", act, oldact, sigsetsize);
        return handle_sigsys_sigaction(act, oldact, &saved_sigsys_handler);
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


/*
 * Set process name from /proc/self/cmdline for correct ps/top display.
 * When running under ld.so, kernel sets comm to "ld-linux-aarch64.so.1".
 * We read the original argv[0] from cmdline and use prctl to fix it.
 *
 * The execve wrapper puts the original filename in argv[0] specifically
 * so we can read it here and set the process name correctly.
 *
 * Only runs if /proc/self/exe shows we're launched via ld.so.
 * Runs automatically as a CONSTRUCTOR when the library is loaded.
 */
static void fakechroot_set_process_name(void) CONSTRUCTOR;
static void fakechroot_set_process_name(void)
{
    char buf[4096];
    int fd;
    ssize_t n;
    const char *name;

    /* Check if we're actually running under ld.so */
    n = nextcall(readlink)("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0)
        return;
    buf[n] = '\0';

    /* Only proceed if exe is ld-linux (the dynamic linker) */
    if (strstr(buf, "ld-linux") == NULL)
        return;

    /* Reuse buffer for cmdline */
    fd = nextcall(open)("/proc/self/cmdline", O_RDONLY);
    if (fd < 0)
        return;

    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0)
        return;

    buf[n] = '\0';

    /* First null-terminated string is original argv[0] */
    name = strrchr(buf, '/');
    name = name ? name + 1 : buf;

    /* PR_SET_NAME truncates to 15 chars, which is fine */
    prctl(PR_SET_NAME, name, 0, 0, 0);

    debug("fakechroot_set_process_name: set comm to \"%s\"", name);
}

#else
typedef int empty_translation_unit;
#endif
