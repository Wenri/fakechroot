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
#include "libfakechroot.h"

/* Saved SIGSYS handler from other code (e.g., Go runtime) */
static struct sigaction saved_sigsys_handler;
static int have_saved_sigsys_handler = 0;

/* Our SIGSYS handler - declared in libfakechroot.c */
extern void fakechroot_sigsys_handler(int sig, siginfo_t *info, void *ucontext);

/* Get the saved handler for chaining */
struct sigaction *fakechroot_get_saved_sigsys_handler(void)
{
    return have_saved_sigsys_handler ? &saved_sigsys_handler : NULL;
}

wrapper(sigaction, int, (int signum, const struct sigaction *act, struct sigaction *oldact))
{
    debug("sigaction(%d, %p, %p)", signum, act, oldact);

    /* Only intercept SIGSYS */
    if (signum != SIGSYS) {
        return nextcall(sigaction)(signum, act, oldact);
    }

    /* If someone is querying the current handler, return our handler info */
    if (act == NULL) {
        return nextcall(sigaction)(signum, act, oldact);
    }

    /* Someone (e.g., Go) is trying to install a SIGSYS handler */
    debug("sigaction: intercepting SIGSYS handler installation");

    /* Save their handler for chaining */
    memcpy(&saved_sigsys_handler, act, sizeof(struct sigaction));
    have_saved_sigsys_handler = 1;

    /* If they want the old handler, give them what was there before */
    if (oldact != NULL) {
        /* Get the current handler (which should be ours) */
        nextcall(sigaction)(signum, NULL, oldact);
    }

    /* Don't actually install their handler - keep ours installed */
    /* Return success to make them think it worked */
    return 0;
}

#endif /* __linux__ */
