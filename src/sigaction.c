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
#include <sys/ucontext.h>
#include <sys/syscall.h>
#include "libfakechroot.h"

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
 */
static int is_blocked_syscall(int syscall_nr)
{
    switch (syscall_nr) {
    /* Filesystem */
    case SYS_mount:
    case SYS_chroot:
    /* IPC - POSIX MQ */
    case SYS_mq_open:
    /* IPC - SysV Semaphores */
    case SYS_semget:
    case SYS_semctl:
    case SYS_semop:
    case SYS_semtimedop:
    /* IPC - SysV Messages */
    case SYS_msgctl:
    case SYS_msgget:
    case SYS_msgrcv:
    case SYS_msgsnd:
    /* Process/Thread */
    case SYS_set_robust_list:
    case SYS_get_robust_list:
    case SYS_ptrace:
    case SYS_kcmp:
    case SYS_rseq:
    case SYS_clone3:
    /* Memory - NUMA */
    case SYS_mbind:
    case SYS_get_mempolicy:
    case SYS_set_mempolicy:
    /* Memory - Protection Keys */
    case SYS_pkey_mprotect:
    case SYS_pkey_alloc:
    case SYS_pkey_free:
    /* Security - Keyring */
    case SYS_add_key:
    case SYS_request_key:
    case SYS_keyctl:
    /* Security - Sandboxing */
    case SYS_bpf:
    case SYS_landlock_create_ruleset:
    case SYS_landlock_add_rule:
    case SYS_landlock_restrict_self:
    /* File Notification */
    case SYS_fanotify_init:
    case SYS_fanotify_mark:
    /* File Handles */
    case SYS_name_to_handle_at:
    case SYS_open_by_handle_at:
    /* Async I/O */
    case SYS_io_pgetevents:
    case SYS_io_uring_setup:
    case SYS_io_uring_enter:
    case SYS_io_uring_register:
    /* Modules */
    case SYS_init_module:
    case SYS_delete_module:
    case SYS_finit_module:
    /* Newer syscalls - commonly used by Go/Rust */
    case SYS_openat2:
    case SYS_faccessat2:
    case SYS_close_range:
    case SYS_epoll_pwait2:
    case SYS_mount_setattr:
    case SYS_futex_waitv:
    case SYS_process_madvise:
    case SYS_process_mrelease:
    case SYS_pidfd_send_signal:
        return 1;
    default:
        return 0;
    }
}

/* Saved SIGSYS handler from other code (e.g., Go runtime) */
/* Initialized when we install our handler, so always valid */
/* Not static - accessed from syscall.c to intercept raw syscall() */
struct sigaction saved_sigsys_handler;

/*
 * SIGSYS handler for Android seccomp bypass.
 * When Android's seccomp blocks syscalls like faccessat2, it sends SIGSYS.
 * We intercept this and return ENOSYS so Go (and other runtimes) can fallback.
 */
static void fakechroot_sigsys_handler(int sig, siginfo_t *info, void *ucontext)
{
    /* Handle seccomp-blocked syscalls by returning ENOSYS */
    if (info->si_code == SYS_SECCOMP && is_blocked_syscall(info->si_syscall)) {
        ucontext_t *ctx = (ucontext_t *)ucontext;
#ifdef __aarch64__
        /* On aarch64, x0 holds the return value */
        ctx->uc_mcontext.regs[0] = -ENOSYS;
#endif
#ifdef __x86_64__
        /* On x86_64, rax holds the return value */
        ctx->uc_mcontext.gregs[REG_RAX] = -ENOSYS;
#endif
        debug("sigsys: blocked syscall %d, returning ENOSYS", info->si_syscall);
        return;
    }

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

    /* Only intercept SIGSYS */
    if (signum != SIGSYS) {
        return nextcall(sigaction)(signum, act, oldact);
    }

    /*
     * Make our handler fully transparent to callers.
     * Return the saved handler (what they think is installed), not our actual handler.
     */

    /* Return the previously saved handler if requested */
    if (oldact != NULL) {
        memcpy(oldact, &saved_sigsys_handler, sizeof(struct sigaction));
    }

    /* If just querying (act == NULL), we're done */
    if (act == NULL) {
        return 0;
    }

    /* Someone (e.g., Go) is trying to install a SIGSYS handler */
    debug("sigaction: intercepting SIGSYS handler installation");

    /* Save their handler for chaining */
    memcpy(&saved_sigsys_handler, act, sizeof(struct sigaction));

    /* Don't actually install their handler - keep ours installed */
    /* Return success to make them think it worked */
    return 0;
}

/*
 * Install our SIGSYS handler using nextcall to bypass our own wrapper.
 * Called from fakechroot_init() in libfakechroot.c.
 */
LOCAL void fakechroot_install_sigsys_handler(void)
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
