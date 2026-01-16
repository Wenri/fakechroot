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

/* Require syscall numbers from system headers */
#ifndef SYS_faccessat2
#error "SYS_faccessat2 not defined - check sys/syscall.h"
#endif
#ifndef SYS_clone3
#error "SYS_clone3 not defined - check sys/syscall.h"
#endif
#ifndef SYS_close_range
#error "SYS_close_range not defined - check sys/syscall.h"
#endif

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

/*
 * Syscalls blocked by Android seccomp that need ENOSYS for fallback.
 * Go and other runtimes bypass glibc and make direct syscalls.
 * When seccomp blocks them, we return ENOSYS so they can fallback.
 */
static int is_blocked_syscall(int syscall_nr)
{
    switch (syscall_nr) {
    case SYS_faccessat2:   /* Go falls back to faccessat */
    case SYS_clone3:       /* Go falls back to clone */
    case SYS_close_range:  /* Go falls back to close loop */
        return 1;
    default:
        return 0;
    }
}

/* Saved SIGSYS handler from other code (e.g., Go runtime) */
/* Initialized when we install our handler, so always valid */
static struct sigaction saved_sigsys_handler;

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
void fakechroot_install_sigsys_handler(void)
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
