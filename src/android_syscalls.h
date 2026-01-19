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
 * android_syscalls.h - Shared Android syscall definitions
 *
 * Defines syscall categories for Android seccomp bypass:
 * - Category 2: uid/gid syscalls that return 0 (no-op)
 * - Category 3: Blocked syscalls that return ENOSYS
 * - Category 1 fallback: Redirect syscalls for SIGSYS handler
 *
 * Used by both syscall.c (wrapper) and sigaction.c (SIGSYS handler).
 */

#ifndef ANDROID_SYSCALLS_H
#define ANDROID_SYSCALLS_H

#include <sys/syscall.h>
#include <signal.h>
#include <string.h>

/*
 * ============================================================================
 * SIGSYS Handler Protection
 * ============================================================================
 *
 * Helper for protecting our SIGSYS handler from being replaced.
 * Used by both sigaction() wrapper and syscall(SYS_rt_sigaction) wrapper.
 *
 * Our SIGSYS handler intercepts seccomp-blocked syscalls and returns ENOSYS.
 * Programs (like Go runtime, Python subprocess) may try to replace it with
 * SIG_DFL, which would cause crashes instead of graceful ENOSYS fallback.
 *
 * Solution: Intercept sigaction calls for SIGSYS, save the requested handler
 * for chaining, but don't actually install it - keep our handler active.
 */

/*
 * Handle SIGSYS sigaction request.
 * Returns 0 on success (always succeeds for SIGSYS).
 *
 * Parameters:
 *   act          - New handler to install (or NULL to query)
 *   oldact       - Where to store previous handler (or NULL)
 *   saved_handler - Pointer to saved handler storage (for chaining)
 */
static inline int handle_sigsys_sigaction(
    const struct sigaction *act,
    struct sigaction *oldact,
    struct sigaction *saved_handler)
{
    /* Return the previously saved handler if requested */
    if (oldact != NULL) {
        memcpy(oldact, saved_handler, sizeof(struct sigaction));
    }

    /* If just querying (act == NULL), we're done */
    if (act == NULL) {
        return 0;
    }

    /* Save their handler for chaining but don't actually install it */
    memcpy(saved_handler, act, sizeof(struct sigaction));

    /* Return success - caller thinks their handler is installed */
    return 0;
}

/*
 * Check if syscall should return 0 (no-op) - uid/gid changes on Android.
 * These syscalls can't actually change user/group, so we silently succeed.
 * (Category 2 in syscall.c wrapper)
 */
static inline int is_noop_syscall(int syscall_nr)
{
    switch (syscall_nr) {
#ifdef SYS_setuid
    case SYS_setuid:
#endif
#ifdef SYS_setuid32
    case SYS_setuid32:
#endif
#ifdef SYS_setgid
    case SYS_setgid:
#endif
#ifdef SYS_setgid32
    case SYS_setgid32:
#endif
#ifdef SYS_setreuid
    case SYS_setreuid:
#endif
#ifdef SYS_setreuid32
    case SYS_setreuid32:
#endif
#ifdef SYS_setregid
    case SYS_setregid:
#endif
#ifdef SYS_setregid32
    case SYS_setregid32:
#endif
#ifdef SYS_setresuid
    case SYS_setresuid:
#endif
#ifdef SYS_setresuid32
    case SYS_setresuid32:
#endif
#ifdef SYS_setresgid
    case SYS_setresgid:
#endif
#ifdef SYS_setresgid32
    case SYS_setresgid32:
#endif
#ifdef SYS_setfsuid
    case SYS_setfsuid:
#endif
#ifdef SYS_setfsuid32
    case SYS_setfsuid32:
#endif
#ifdef SYS_setfsgid
    case SYS_setfsgid:
#endif
#ifdef SYS_setfsgid32
    case SYS_setfsgid32:
#endif
        return 1;
    default:
        return 0;
    }
}

/*
 * Check if syscall should return ENOSYS - blocked by Android seccomp.
 * (Category 3 in syscall.c wrapper)
 *
 * Note: This does NOT include Category 1 syscalls (redirects like
 * faccessat2 → faccessat). Those are handled separately in syscall.c
 * with redirect logic. The SIGSYS handler uses is_redirect_syscall()
 * for those.
 */
static inline int is_blocked_syscall(int syscall_nr)
{
    switch (syscall_nr) {
    /* Filesystem */
#ifdef SYS_mount
    case SYS_mount:
#endif
#ifdef SYS_chroot
    case SYS_chroot:
#endif
    /* IPC - POSIX MQ */
#ifdef SYS_mq_open
    case SYS_mq_open:
#endif
    /* IPC - SysV Semaphores */
#ifdef SYS_semget
    case SYS_semget:
#endif
#ifdef SYS_semctl
    case SYS_semctl:
#endif
#ifdef SYS_semop
    case SYS_semop:
#endif
#ifdef SYS_semtimedop
    case SYS_semtimedop:
#endif
    /* IPC - SysV Messages */
#ifdef SYS_msgctl
    case SYS_msgctl:
#endif
#ifdef SYS_msgget
    case SYS_msgget:
#endif
#ifdef SYS_msgrcv
    case SYS_msgrcv:
#endif
#ifdef SYS_msgsnd
    case SYS_msgsnd:
#endif
    /* IPC - SysV Shared Memory */
#ifdef SYS_shmget
    case SYS_shmget:
#endif
#ifdef SYS_shmctl
    case SYS_shmctl:
#endif
#ifdef SYS_shmat
    case SYS_shmat:
#endif
#ifdef SYS_shmdt
    case SYS_shmdt:
#endif
    /* Process/Thread */
#ifdef SYS_set_robust_list
    case SYS_set_robust_list:
#endif
#ifdef SYS_get_robust_list
    case SYS_get_robust_list:
#endif
#ifdef SYS_ptrace
    case SYS_ptrace:
#endif
#ifdef SYS_kcmp
    case SYS_kcmp:
#endif
#ifdef SYS_rseq
    case SYS_rseq:
#endif
#ifdef SYS_clone3
    case SYS_clone3:
#endif
    /* Memory - NUMA */
#ifdef SYS_mbind
    case SYS_mbind:
#endif
#ifdef SYS_get_mempolicy
    case SYS_get_mempolicy:
#endif
#ifdef SYS_set_mempolicy
    case SYS_set_mempolicy:
#endif
    /* Memory - Protection Keys */
#ifdef SYS_pkey_mprotect
    case SYS_pkey_mprotect:
#endif
#ifdef SYS_pkey_alloc
    case SYS_pkey_alloc:
#endif
#ifdef SYS_pkey_free
    case SYS_pkey_free:
#endif
    /* Security - Keyring */
#ifdef SYS_add_key
    case SYS_add_key:
#endif
#ifdef SYS_request_key
    case SYS_request_key:
#endif
#ifdef SYS_keyctl
    case SYS_keyctl:
#endif
    /* Security - Sandboxing */
#ifdef SYS_bpf
    case SYS_bpf:
#endif
#ifdef SYS_landlock_create_ruleset
    case SYS_landlock_create_ruleset:
#endif
#ifdef SYS_landlock_add_rule
    case SYS_landlock_add_rule:
#endif
#ifdef SYS_landlock_restrict_self
    case SYS_landlock_restrict_self:
#endif
    /* File Notification */
#ifdef SYS_fanotify_init
    case SYS_fanotify_init:
#endif
#ifdef SYS_fanotify_mark
    case SYS_fanotify_mark:
#endif
    /* File Handles */
#ifdef SYS_name_to_handle_at
    case SYS_name_to_handle_at:
#endif
#ifdef SYS_open_by_handle_at
    case SYS_open_by_handle_at:
#endif
    /* Async I/O */
#ifdef SYS_io_pgetevents
    case SYS_io_pgetevents:
#endif
#ifdef SYS_io_uring_setup
    case SYS_io_uring_setup:
#endif
#ifdef SYS_io_uring_enter
    case SYS_io_uring_enter:
#endif
#ifdef SYS_io_uring_register
    case SYS_io_uring_register:
#endif
    /* Modules */
#ifdef SYS_init_module
    case SYS_init_module:
#endif
#ifdef SYS_delete_module
    case SYS_delete_module:
#endif
#ifdef SYS_finit_module
    case SYS_finit_module:
#endif
    /* Newer syscalls - commonly blocked */
#ifdef SYS_openat2
    case SYS_openat2:
#endif
#ifdef SYS_close_range
    case SYS_close_range:
#endif
#ifdef SYS_epoll_pwait2
    case SYS_epoll_pwait2:
#endif
#ifdef SYS_mount_setattr
    case SYS_mount_setattr:
#endif
#ifdef SYS_futex_waitv
    case SYS_futex_waitv:
#endif
#ifdef SYS_process_madvise
    case SYS_process_madvise:
#endif
#ifdef SYS_process_mrelease
    case SYS_process_mrelease:
#endif
#ifdef SYS_pidfd_send_signal
    case SYS_pidfd_send_signal:
#endif
        return 1;
    default:
        return 0;
    }
}

/*
 * Check if syscall is a Category 1 redirect syscall.
 * These are redirected in syscall() wrapper (e.g., faccessat2 → faccessat),
 * but need ENOSYS fallback in SIGSYS handler when raw syscalls bypass
 * the wrapper and trigger SIGSYS directly.
 */
static inline int is_redirect_syscall(int syscall_nr)
{
    switch (syscall_nr) {
#ifdef SYS_chmod
    case SYS_chmod:
#endif
#ifdef SYS_fchmodat2
    case SYS_fchmodat2:
#endif
#ifdef SYS_chown
    case SYS_chown:
#endif
#ifdef SYS_chown32
    case SYS_chown32:
#endif
#ifdef SYS_accept
    case SYS_accept:
#endif
#ifdef SYS_recv
    case SYS_recv:
#endif
#ifdef SYS_send
    case SYS_send:
#endif
#ifdef SYS_symlink
    case SYS_symlink:
#endif
#ifdef SYS_link
    case SYS_link:
#endif
#ifdef SYS_rmdir
    case SYS_rmdir:
#endif
#ifdef SYS_getpgrp
    case SYS_getpgrp:
#endif
#ifdef SYS_faccessat2
    case SYS_faccessat2:
#endif
        return 1;
    default:
        return 0;
    }
}

#endif /* ANDROID_SYSCALLS_H */
