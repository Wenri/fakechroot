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


#include <config.h>

#ifdef __linux__

#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>       /* syscall() */
#include <sys/ucontext.h>
#include <sys/syscall.h>
#include <fcntl.h>        /* AT_FDCWD, AT_REMOVEDIR */
#include "libfakechroot.h"
#include "android_syscalls.h"
#include "syscall_macros.h"

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

/*
 * Android seccomp blocked syscalls - tested on kernel 5.10.43 aarch64
 *
 * Android's seccomp uses SECCOMP_RET_TRAP (sends SIGSYS) as the default
 * action for most blocked syscalls (~200+). Only a small set of syscalls
 * return ENOSYS directly via SECCOMP_RET_ERRNO.
 *
 * Programs that bypass glibc (Go, Rust with direct syscalls) hit the kernel
 * seccomp filter directly and receive SIGSYS. Our handler catches these and
 * returns ENOSYS so programs can use fallback implementations.
 *
 * Full list of SIGSYS-blocked syscalls by category:
 *
 *   Filesystem (18, 40, 51, 58):
 *     lookup_dcookie, mount, chroot, vhangup
 *
 *   IPC - POSIX MQ (180-185):
 *     mq_open, mq_unlink, mq_timedsend, mq_timedreceive, mq_notify, mq_getsetattr
 *
 *   IPC - SysV Semaphores (190-193):
 *     semget, semctl, semtimedop, semop
 *
 *   IPC - SysV Messages (186-189):
 *     msgget, msgctl, msgrcv, msgsnd
 *
 *   IPC - SysV Shared Memory (194-197):
 *     shmget, shmctl, shmat, shmdt
 *
 *   Process/Thread (99-100, 116, 272, 293, 435):
 *     set_robust_list, get_robust_list, ptrace, kcmp, rseq, clone3
 *
 *   Memory - NUMA (235-239):
 *     mbind, get_mempolicy, set_mempolicy, migrate_pages, move_pages
 *
 *   Memory - Protection Keys (288-290):
 *     pkey_mprotect, pkey_alloc, pkey_free
 *
 *   Security - Keyring (217-219):
 *     add_key, request_key, keyctl
 *
 *   Security - Sandboxing (280, 444-446):
 *     bpf, landlock_create_ruleset, landlock_add_rule, landlock_restrict_self
 *
 *   File Notification (262-263):
 *     fanotify_init, fanotify_mark
 *
 *   File Handles (264-265):
 *     name_to_handle_at, open_by_handle_at
 *
 *   Async I/O (292, 425-427):
 *     io_pgetevents, io_uring_setup, io_uring_enter, io_uring_register
 *
 *   Modules (245-246, 273):
 *     init_module, delete_module, finit_module
 *
 *   Newer syscalls (294-459, most blocked):
 *     Including: openat2(437), faccessat2(439), close_range(436),
 *     epoll_pwait2(441), mount_setattr(442), futex_waitv(449),
 *     process_madvise(447), process_mrelease(448), pidfd_*(420-423), etc.
 *
 * Note: We only check specific syscalls here rather than returning ENOSYS
 * for all SIGSYS signals, to avoid interfering with legitimate SIGSYS uses.
 *
 * Syscall handling is split across two files:
 * - android_syscalls.h: is_noop_syscall() and is_blocked_syscall()
 * - syscall_macros.h: REDIRECT_TABLE for Category 1 syscall redirects
 *   (e.g., faccessat2 -> faccessat), expanded via handle_sigsys_redirect()
 */

/* Saved SIGSYS handler from other code (e.g., Go runtime) */
/* Initialized when we install our handler, so always valid */
/* Not static - accessed from syscall.c to intercept raw syscall() */
struct sigaction saved_sigsys_handler;

/*
 * Handle redirect syscalls by calling target syscall directly.
 * Uses REDIRECT_TABLE from syscall_macros.h (single source of truth).
 * Returns 1 if handled (and sets return value), 0 if not a redirect syscall.
 *
 * Note: Unlike the syscall() wrapper in syscall.c, we cannot do path expansion
 * here because we're in a signal handler context. However, this is acceptable:
 * - Raw syscalls that bypass glibc typically use absolute paths
 * - The main benefit is avoiding the ENOSYS retry overhead
 */
static int handle_sigsys_redirect(ucontext_t *ctx, int syscall_nr)
{
    long ret;

    switch (syscall_nr) {

/* Define X-macros to expand REDIRECT_TABLE with register access */
#define AT_REDIRECT_X(from, to, extra) \
    case SYS_##from: \
        ret = syscall(SYS_##to, SIGSYS_REG(ctx, 0), SIGSYS_REG(ctx, 1), SIGSYS_REG(ctx, 2)); \
        debug("sigsys: " #from " -> " #to " = %ld", ret); \
        goto set_return;

#define PATH_REDIRECT_0_X(from, to, extra) \
    case SYS_##from: \
        ret = syscall(SYS_##to, AT_FDCWD, SIGSYS_REG(ctx, 0), extra); \
        debug("sigsys: " #from " -> " #to " = %ld", ret); \
        goto set_return;

#define PATH_REDIRECT_1_X(from, to, extra) \
    case SYS_##from: \
        ret = syscall(SYS_##to, AT_FDCWD, SIGSYS_REG(ctx, 0), SIGSYS_REG(ctx, 1), extra); \
        debug("sigsys: " #from " -> " #to " = %ld", ret); \
        goto set_return;

#define PATH_REDIRECT_2_X(from, to, extra) \
    case SYS_##from: \
        ret = syscall(SYS_##to, AT_FDCWD, SIGSYS_REG(ctx, 0), SIGSYS_REG(ctx, 1), SIGSYS_REG(ctx, 2), extra); \
        debug("sigsys: " #from " -> " #to " = %ld", ret); \
        goto set_return;

#define REDIRECT_0_X(from, to, extra) \
    case SYS_##from: \
        ret = syscall(SYS_##to, extra); \
        debug("sigsys: " #from " -> " #to " = %ld", ret); \
        goto set_return;

#define REDIRECT_3_X(from, to, extra) \
    case SYS_##from: \
        ret = syscall(SYS_##to, SIGSYS_REG(ctx, 0), SIGSYS_REG(ctx, 1), SIGSYS_REG(ctx, 2), extra); \
        debug("sigsys: " #from " -> " #to " = %ld", ret); \
        goto set_return;

#define REDIRECT_4_2_X(from, to, e1, e2) \
    case SYS_##from: \
        ret = syscall(SYS_##to, SIGSYS_REG(ctx, 0), SIGSYS_REG(ctx, 1), SIGSYS_REG(ctx, 2), SIGSYS_REG(ctx, 3), e1, e2); \
        debug("sigsys: " #from " -> " #to " = %ld", ret); \
        goto set_return;

#define SYMLINK_REDIRECT_X(from, to) \
    case SYS_##from: \
        ret = syscall(SYS_##to, SIGSYS_REG(ctx, 0), AT_FDCWD, SIGSYS_REG(ctx, 1)); \
        debug("sigsys: " #from " -> " #to " = %ld", ret); \
        goto set_return;

#define LINK_REDIRECT_X(from, to) \
    case SYS_##from: \
        ret = syscall(SYS_##to, AT_FDCWD, SIGSYS_REG(ctx, 0), AT_FDCWD, SIGSYS_REG(ctx, 1), 0); \
        debug("sigsys: " #from " -> " #to " = %ld", ret); \
        goto set_return;

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

    default:
        return 0;  /* Not handled */
    }

set_return:
    SIGSYS_SET_RETURN(ctx, ret);
    return 1;  /* Handled */
}

/*
 * SIGSYS handler for Android seccomp bypass.
 * When Android's seccomp blocks syscalls, it sends SIGSYS.
 * We intercept this and return appropriate values:
 * - Redirected result for redirect syscalls (e.g., faccessat2 -> faccessat)
 * - 0 for uid/gid syscalls (no-op on Android)
 * - ENOSYS for other blocked syscalls (triggers program fallback)
 */
static void fakechroot_sigsys_handler(int sig, siginfo_t *info, void *ucontext)
{
    if (info->si_code != SYS_SECCOMP) {
        goto chain_handler;
    }

    ucontext_t *ctx = (ucontext_t *)ucontext;
    int syscall_nr = info->si_syscall;

    /* Quick checks first - avoid switch statement overhead */

    /* Category 2: uid/gid syscalls return 0 (success, no-op) */
    if (is_noop_syscall(syscall_nr)) {
        SIGSYS_SET_RETURN(ctx, 0);
        debug("sigsys: syscall %d -> 0 (noop)", syscall_nr);
        return;
    }

    /* Category 3: blocked syscalls return ENOSYS */
    if (is_blocked_syscall(syscall_nr)) {
        SIGSYS_SET_RETURN(ctx, -ENOSYS);
        debug("sigsys: syscall %d -> ENOSYS", syscall_nr);
        return;
    }

    /* Category 1: Redirect syscalls - call target syscall directly */
    if (handle_sigsys_redirect(ctx, syscall_nr)) {
        return;
    }

chain_handler:

    /* Chain to saved handler (e.g., Go's handler) for other SIGSYS signals */
    if (saved_sigsys_handler.sa_flags & SA_SIGINFO) {
        if (saved_sigsys_handler.sa_sigaction != NULL) {
            debug("sigsys: chaining to saved SA_SIGINFO handler");
            saved_sigsys_handler.sa_sigaction(sig, info, ucontext);
        }
    } else {
        if (saved_sigsys_handler.sa_handler != NULL &&
            saved_sigsys_handler.sa_handler != SIG_IGN &&
            saved_sigsys_handler.sa_handler != SIG_DFL) {
            debug("sigsys: chaining to saved handler");
            saved_sigsys_handler.sa_handler(sig);
        }
    }
}

wrapper(sigaction, int, (int signum, const struct sigaction *act, struct sigaction *oldact))
{
    debug("sigaction(%d, %p, %p)", signum, act, oldact);

    /* Only intercept SIGSYS - pass through all other signals */
    if (signum != SIGSYS) {
        return nextcall(sigaction)(signum, act, oldact);
    }

    /* Use shared helper for SIGSYS protection logic */
    debug("sigaction: intercepting SIGSYS handler change");
    return handle_sigsys_sigaction(act, oldact, &saved_sigsys_handler);
}

/*
 * Install our SIGSYS handler using nextcall to bypass our own wrapper.
 * Runs automatically as a CONSTRUCTOR when the library is loaded.
 */
static void fakechroot_install_sigsys_handler(void) CONSTRUCTOR;
static void fakechroot_install_sigsys_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fakechroot_sigsys_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (nextcall(sigaction)(SIGSYS, &sa, &saved_sigsys_handler) == 0) {
        debug("sigsys: handler installed for seccomp bypass");
    }
}

#endif /* __linux__ */
