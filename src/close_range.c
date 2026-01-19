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
 * close_range() wrapper for Android seccomp bypass.
 *
 * The close_range() syscall is blocked by Android's seccomp filter.
 * This wrapper returns ENOSYS directly so that callers (like Python's
 * subprocess module) will fall back to closing file descriptors one by one.
 *
 * Note: This wrapper intercepts the libc close_range() function.
 * Programs that call close_range via syscall() directly will hit the
 * SIGSYS handler in sigaction.c which also returns ENOSYS.
 */

#include <config.h>

#ifdef HAVE_CLOSE_RANGE

#include <errno.h>
#include <unistd.h>
#include "libfakechroot.h"

wrapper(close_range, int, (unsigned int first, unsigned int last, unsigned int flags))
{
    debug("close_range(%u, %u, %u) -> returning ENOSYS for Android", first, last, flags);
    errno = ENOSYS;
    return -1;
}

#else
typedef int empty_translation_unit;
#endif
