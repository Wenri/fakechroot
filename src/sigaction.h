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
 * sigaction.h - SIGSYS signal handler support for Android seccomp bypass
 *
 * This file provides macros for extracting syscall arguments from ucontext
 * registers when handling SIGSYS signals from Android's seccomp filter.
 */

#ifndef FAKECHROOT_SIGACTION_H
#define FAKECHROOT_SIGACTION_H

#include <sys/ucontext.h>

/*
 * ============================================================================
 * SIGSYS Register Access
 *
 * These macros extract syscall arguments from the ucontext registers when
 * handling SIGSYS signals from Android's seccomp filter.
 * ============================================================================
 */
#ifdef __aarch64__
#define SIGSYS_REG(ctx, n) ((long)(ctx)->uc_mcontext.regs[n])
#define SIGSYS_SET_RETURN(ctx, val) ((ctx)->uc_mcontext.regs[0] = (val))
#endif

#ifdef __x86_64__
/* x86_64 syscall argument registers: rdi, rsi, rdx, r10, r8, r9 */
#define SIGSYS_REG(ctx, n) ((long)(ctx)->uc_mcontext.gregs[ \
    (n) == 0 ? REG_RDI : \
    (n) == 1 ? REG_RSI : \
    (n) == 2 ? REG_RDX : \
    (n) == 3 ? REG_R10 : \
    (n) == 4 ? REG_R8 : REG_R9])
#define SIGSYS_SET_RETURN(ctx, val) ((ctx)->uc_mcontext.gregs[REG_RAX] = (val))
#endif

/* SIGSYS handler context - pointer to ucontext */
typedef ucontext_t * sigsys_ctx_t;

#endif /* FAKECHROOT_SIGACTION_H */
