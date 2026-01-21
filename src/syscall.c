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
#include <alloca.h>       /* alloca for stack-based path buffers */
#include "libfakechroot.h"
#include "android_syscalls.h"
#include "syscall.h"
#include "readlink.h"
#include "open.h"


wrapper(syscall, long, (long number, ...))
{
    /* Quick early returns for noop/blocked syscalls - no va_args needed */
    if (is_noop_syscall(number)) {
        debug("syscall(%ld) -> 0 (uid/gid no-op)", number);
        return 0;
    }

    if (is_blocked_syscall(number)) {
        debug("syscall(%ld) -> ENOSYS (blocked)", number);
        __set_errno(ENOSYS);
        return -1;
    }

    va_list ap;
    va_start(ap, number);

    switch (number) {

    /* ================================================================
     * Syscall interception using unified SYS_GEN_* macros
     *
     * Two categories:
     * - PASSTHROUGH_SEQ: AT syscalls that expand path and call same syscall
     * - REDIRECT_SEQ: Syscalls redirected to alternative syscalls
     *
     * Path-related syscalls perform path expansion via CTX_EXPAND_PATH* macros.
     * ================================================================ */

    /* Context setup: extract all va_args into array */
#define CTX_SETUP(name) long name[6] = { \
        va_arg(ap, long), va_arg(ap, long), va_arg(ap, long), \
        va_arg(ap, long), va_arg(ap, long), va_arg(ap, long) }

    /* Context-specific argument accessor for array */
#define CTX_ARG(ctx, n) (ctx)[n]

    /* Path expansion using alloca() for stack-based buffer allocation.
     * Each expansion gets its own buffer, so link() works without special handling. */
#define CTX_EXPAND_PATH(ctx, arg_n) \
    expand_chroot_path((const char *)CTX_ARG(ctx, arg_n), alloca(FAKECHROOT_PATH_MAX))

#define CTX_EXPAND_PATH_AT(ctx, dirfd_n, path_n) \
    expand_chroot_path_at((int)CTX_ARG(ctx, dirfd_n), \
                          (const char *)CTX_ARG(ctx, path_n), alloca(FAKECHROOT_PATH_MAX))

    /* Done: cleanup and return */
#define CTX_DONE(val) do { va_end(ap); return val; } while(0)

    /* Expand PASSTHROUGH_SEQ - generates passthrough case statements */
    BOOST_PP_SEQ_FOR_EACH(SYS_GEN_DISPATCH, 5, PASSTHROUGH_SEQ)

    /* Expand REDIRECT_SEQ - generates redirect case statements */
    BOOST_PP_SEQ_FOR_EACH(SYS_GEN_DISPATCH, 5, REDIRECT_SEQ)

#undef CTX_DONE
#undef CTX_EXPAND_PATH_AT
#undef CTX_EXPAND_PATH
#undef CTX_ARG
#undef CTX_SETUP

#ifdef SYS_rt_sigaction
    /*
     * Intercept rt_sigaction syscall to protect our SIGSYS handler.
     * Uses shared helper from android_syscalls.h (same logic as sigaction wrapper).
     */
    case SYS_rt_sigaction: {
        const int signum = va_arg(ap, int);
        struct sigaction *const act = va_arg(ap, struct sigaction *);
        struct sigaction *const oldact = va_arg(ap, struct sigaction *);
        const size_t sigsetsize = va_arg(ap, size_t);
        va_end(ap);

        /* Only intercept SIGSYS - pass through all other signals */
        if (signum != SIGSYS) {
            return nextcall(syscall)(number, signum, act, oldact, sigsetsize);
        }

        debug("syscall(SYS_rt_sigaction, SIGSYS, %p, %p, %zu)", act, oldact, sigsetsize);
        return handle_sigsys_sigaction(act, oldact);
    }
#endif

    default: {
        /* Pass through all other syscalls with up to 6 args.
         * This matches glibc's syscall() implementation which also
         * extracts exactly 6 va_arg unconditionally.
         * Note: noop/blocked syscalls already handled at function start. */
        const long a1 = va_arg(ap, long);
        const long a2 = va_arg(ap, long);
        const long a3 = va_arg(ap, long);
        const long a4 = va_arg(ap, long);
        const long a5 = va_arg(ap, long);
        const long a6 = va_arg(ap, long);
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
    const int fd = nextcall(open)("/proc/self/cmdline", O_RDONLY);
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
