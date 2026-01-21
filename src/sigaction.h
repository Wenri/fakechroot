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
 * These functions extract syscall arguments from the ucontext registers when
 * handling SIGSYS signals from Android's seccomp filter.
 * ============================================================================
 */
#ifdef __aarch64__
static inline long sigsys_get_arg(ucontext_t *ctx, int n)
{
    return (long)ctx->uc_mcontext.regs[n];
}

static inline void sigsys_set_return(ucontext_t *ctx, long val)
{
    ctx->uc_mcontext.regs[0] = val;
}
#endif

#ifdef __x86_64__
/* x86_64 syscall argument registers: rdi, rsi, rdx, r10, r8, r9 */
static inline long sigsys_get_arg(ucontext_t *ctx, int n)
{
    static const int reg_map[] = { REG_RDI, REG_RSI, REG_RDX, REG_R10, REG_R8, REG_R9 };
    return (long)ctx->uc_mcontext.gregs[reg_map[n]];
}

static inline void sigsys_set_return(ucontext_t *ctx, long val)
{
    ctx->uc_mcontext.gregs[REG_RAX] = val;
}
#endif

#endif /* FAKECHROOT_SIGACTION_H */
