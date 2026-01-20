/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2003-2015 Piotr Roszatycki <dexter@debian.org>
    Copyright (c) 2007 Mark Eichin <eichin@metacarta.com>
    Copyright (c) 2006, 2007 Alexander Shishkin <virtuoso@slind.org>

    klik2 support -- give direct access to a list of directories
    Copyright (c) 2006, 2007 Lionel Tricon <lionel.tricon@free.fr>

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

#define _GNU_SOURCE

#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <dlfcn.h>
#include "setenv.h"
#include "libfakechroot.h"
#include "getcwd_real.h"
#include "strchrnul.h"

/* Compile-time exclude list from configure --with-android-exclude-path */
#ifdef EXCLUDE_PATH_SEQ
#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/size.hpp>

#define EXCLUDE_PATH_ELEM(r, data, elem) elem,
#define EXCLUDE_LENGTH_ELEM(r, data, elem) sizeof(elem) - 1,

static const char * const exclude_list[] = {
    BOOST_PP_SEQ_FOR_EACH(EXCLUDE_PATH_ELEM, _, EXCLUDE_PATH_SEQ)
};
static const size_t exclude_length[] = {
    BOOST_PP_SEQ_FOR_EACH(EXCLUDE_LENGTH_ELEM, _, EXCLUDE_PATH_SEQ)
};
static const size_t list_max = BOOST_PP_SEQ_SIZE(EXCLUDE_PATH_SEQ);
#else
#error "ANDROID_EXCLUDE_PATH must be set at configure time"
#endif


/* List of environment variables to preserve on clearenv() */
const char * const preserve_env_list[] = {
    "FAKECHROOT_DEBUG",
    "FAKEROOTKEY",
    "FAKED_MODE",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD"
};
const size_t preserve_env_list_count = sizeof preserve_env_list / sizeof preserve_env_list[0];


LOCAL int fakechroot_debug (const char *fmt, ...)
{
    int ret;
    char newfmt[2048];
    va_list ap;

    /* Check FAKECHROOT_DEBUG BEFORE va_start to avoid undefined behavior.
     * Calling va_start without va_end is undefined behavior that can
     * corrupt the stack/heap on some architectures. */
    if (!getenv("FAKECHROOT_DEBUG"))
        return 0;

    va_start(ap, fmt);

    snprintf(newfmt, sizeof(newfmt), PACKAGE ": %s\n", fmt);

    ret = vfprintf(stderr, newfmt, ap);
    va_end(ap);

    return ret;
}


#include "getcwd.h"


/* Check if path is on exclude list */
LOCAL bool fakechroot_localdir (const char * p_path)
{
    const char *v_path = p_path;
    char cwd_path[FAKECHROOT_PATH_MAX];

    if (!p_path)
        return false;

    /* We need to expand relative paths */
    if (p_path[0] != '/') {
        getcwd_real(cwd_path, FAKECHROOT_PATH_MAX);
        narrow_chroot_path(cwd_path);
        v_path = cwd_path;
    }

    /* We try to find if we need direct access to a file */
    {
        const size_t len = strlen(v_path);
        size_t i;

        for (i = 0; i < list_max; i++) {
            if (exclude_length[i] > len ||
                    v_path[exclude_length[i] - 1] != (exclude_list[i])[exclude_length[i] - 1] ||
                    strncmp(exclude_list[i], v_path, exclude_length[i]) != 0) continue;
            if (exclude_length[i] == len || v_path[exclude_length[i]] == '/') return true;
        }
    }

    return false;
}


/*
 * Parse the FAKECHROOT_CMD_SUBST environment variable (the first
 * parameter) and if there is a match with filename, return the
 * substitution in cmd_subst.  Returns non-zero if there was a match.
 *
 * FAKECHROOT_CMD_SUBST=cmd=subst:cmd=subst:...
 */
LOCAL int fakechroot_try_cmd_subst (char * env, const char * filename, char * cmd_subst)
{
    int len, len2;
    char *p;

    if (env == NULL || filename == NULL)
        return 0;

    /* Remove trailing dot from filename */
    if (filename[0] == '.' && filename[1] == '/')
        filename++;
    len = strlen(filename);

    do {
        p = strchrnul(env, ':');

        if (strncmp(env, filename, len) == 0 && env[len] == '=') {
            len2 = p - &env[len+1];
            if (len2 >= FAKECHROOT_PATH_MAX)
                len2 = FAKECHROOT_PATH_MAX - 1;
            strncpy(cmd_subst, &env[len+1], len2);
            cmd_subst[len2] = '\0';
            return 1;
        }

        env = p;
    } while (*env++ != '\0');

    return 0;
}
