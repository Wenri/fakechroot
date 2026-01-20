/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2010, 2013 Piotr Roszatycki <dexter@debian.org>

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

#ifdef HAVE_GLOB64

#define _LARGEFILE64_SOURCE
#include <glob.h>
#include "libfakechroot.h"


wrapper(glob64, int, (const char * pattern, int flags, int (* errfunc) (const char *, int), glob64_t * pglob))
{
    char fakechroot_buf[FAKECHROOT_PATH_MAX];
    int rc, i;

    debug("glob64(\"%s\", %d, &errfunc, &pglob)", pattern, flags);
    pattern = expand_chroot_rel_path(pattern, fakechroot_buf);

    rc = nextcall(glob64)(pattern, flags, errfunc, pglob);
    if (rc < 0)
        return rc;

    /* Strip ANDROID_BASE prefix from results */
    for (i = 0; i < pglob->gl_pathc; i++) {
        char tmp[FAKECHROOT_PATH_MAX], *tmpptr;

        strcpy(tmp, pglob->gl_pathv[i]);

        const char *ptr = strstr(tmp, ANDROID_BASE);
        if (ptr != tmp) {
            tmpptr = tmp;
        } else {
            tmpptr = tmp + ANDROID_BASE_LEN;
        }
        strcpy(pglob->gl_pathv[i], tmpptr);
    }
    return rc;
}

#else
typedef int empty_translation_unit;
#endif
