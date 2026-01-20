/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2010, 2013, 2016 Piotr Roszatycki <dexter@debian.org>

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

#include <string.h>
#include "libfakechroot.h"
#include "getcwd_real.h"


wrapper(chdir, int, (const char * path))
{
    char fakechroot_abspath[FAKECHROOT_PATH_MAX];
    char fakechroot_buf[FAKECHROOT_PATH_MAX];

    char cwd[FAKECHROOT_PATH_MAX];

    debug("chdir(\"%s\")", path);

    if (getcwd_real(cwd, FAKECHROOT_PATH_MAX) == NULL) {
        return -1;
    }

    /* Use compile-time ANDROID_BASE instead of getenv("FAKECHROOT_BASE")
     * since we compile the base path into the library */
    if (ANDROID_BASE != NULL) {
        if (strstr(cwd, ANDROID_BASE) == cwd) {
            expand_chroot_path(path);
        }
        else {
            expand_chroot_rel_path(path);
        }
    }

    return nextcall(chdir)(path);
}
