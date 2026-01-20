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
#include <fcntl.h>
#include <sys/prctl.h>
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


/*
 * Set process name from /proc/self/cmdline for correct ps/top display.
 * When running under ld.so, kernel sets comm to "ld-linux-aarch64.so.1".
 * We read the original argv[0] from cmdline and use prctl to fix it.
 *
 * The execve wrapper puts the original filename in argv[0] specifically
 * so we can read it here and set the process name correctly.
 *
 * Only runs if /proc/self/exe shows we're launched via ld.so.
 * Runs automatically as a CONSTRUCTOR when the library is loaded.
 */
static void fakechroot_set_process_name(void) CONSTRUCTOR;
static void fakechroot_set_process_name(void)
{
    char exebuf[256];
    char buf[4096];
    int fd;
    ssize_t n;
    const char *name;

    /* Get real libc functions to bypass our wrappers */
    ssize_t (*real_readlink)(const char *, char *, size_t) = dlsym(RTLD_NEXT, "readlink");
    int (*real_open)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");

    if (!real_readlink || !real_open)
        return;

    /* Check if we're actually running under ld.so */
    n = real_readlink("/proc/self/exe", exebuf, sizeof(exebuf) - 1);
    if (n <= 0)
        return;
    exebuf[n] = '\0';

    /* Only proceed if exe is ld-linux (the dynamic linker) */
    if (strstr(exebuf, "ld-linux") == NULL)
        return;

    fd = real_open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0)
        return;

    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0)
        return;

    buf[n] = '\0';

    /* First null-terminated string is original argv[0] */
    name = strrchr(buf, '/');
    name = name ? name + 1 : buf;

    /* PR_SET_NAME truncates to 15 chars, which is fine */
    prctl(PR_SET_NAME, name, 0, 0, 0);

    debug("fakechroot_set_process_name: set comm to \"%s\" (exe=%s)", name, exebuf);
}


/* Lazily load function */
LOCAL fakechroot_wrapperfn_t fakechroot_loadfunc (struct fakechroot_wrapper * w)
{
    char *msg;
    if (!(w->nextfunc = dlsym(RTLD_NEXT, w->name))) {;
        msg = dlerror();
        fprintf(stderr, "%s: %s: %s\n", PACKAGE, w->name, msg != NULL ? msg : "unresolved symbol");
        exit(EXIT_FAILURE);
    }
    return w->nextfunc;
}


/* Check if path is on exclude list */
LOCAL int fakechroot_localdir (const char * p_path)
{
    char *v_path = (char *)p_path;
    char cwd_path[FAKECHROOT_PATH_MAX];

    if (!p_path)
        return 0;

    /* We need to expand relative paths */
    if (p_path[0] != '/') {
        getcwd_real(cwd_path, FAKECHROOT_PATH_MAX);
        v_path = cwd_path;
        narrow_chroot_path(v_path);
    }

    /* We try to find if we need direct access to a file */
    {
        const size_t len = strlen(v_path);
        size_t i;

        for (i = 0; i < list_max; i++) {
            if (exclude_length[i] > len ||
                    v_path[exclude_length[i] - 1] != (exclude_list[i])[exclude_length[i] - 1] ||
                    strncmp(exclude_list[i], v_path, exclude_length[i]) != 0) continue;
            if (exclude_length[i] == len || v_path[exclude_length[i]] == '/') return 1;
        }
    }

    return 0;
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
