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

#ifdef HAVE_POSIX_SPAWN
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <spawn.h>
#include <stdlib.h>
#include <fcntl.h>
#include <alloca.h>
#include "strchrnul.h"
#include "libfakechroot.h"
#include "open.h"
#include "setenv.h"
#include "readlink.h"
#include "android-config.h"


wrapper(posix_spawn, int, (pid_t* pid, const char * filename,
        const posix_spawn_file_actions_t* file_actions,
        const posix_spawnattr_t* attrp, char* const argv[],
        char * const envp []))
{
    char fakechroot_abspath[FAKECHROOT_PATH_MAX];
    char fakechroot_buf[FAKECHROOT_PATH_MAX];

    int status;
    int file;
    char hashbang[FAKECHROOT_PATH_MAX];
    size_t argv_max = 1024;
    const char **newargv = alloca(argv_max * sizeof (const char *));
    char **newenvp, **ep;
    char *key, *env;
    char tmpkey[1024], *tp;
    char tmp[FAKECHROOT_PATH_MAX];
    char newfilename[FAKECHROOT_PATH_MAX];
    char argv0[FAKECHROOT_PATH_MAX];
    unsigned int i, j, n, newenvppos;
    size_t sizeenvp;
    char c;

    debug("posix_spawn(\"%s\", {\"%s\", ...}, {\"%s\", ...})", filename, argv[0], envp ? envp[0] : "(null)");

    /* Use original argv[0] for --argv0, not filename
     * This is important for login shells where argv[0] is "-zsh" or "-bash" */
    strncpy(argv0, argv[0], FAKECHROOT_PATH_MAX - 1);

    /* Scan envp and check its size */
    sizeenvp = 0;
    if (envp) {
        for (ep = (char **)envp; *ep != NULL; ++ep) {
            sizeenvp++;
        }
    }

    /* Copy envp to newenvp */
    newenvp = malloc( (sizeenvp + preserve_env_list_count + 1) * sizeof (char *) );
    if (newenvp == NULL) {
        __set_errno(ENOMEM);
        return errno;
    }
    newenvppos = 0;

    /* Preserve environment variables from preserve_env_list if not in envp */
    for (j = 0; j < preserve_env_list_count; j++) {
        key = preserve_env_list[j];
        env = getenv(key);
        if (env != NULL && *env) {
            if (envp) {
                for (ep = (char **) envp; *ep != NULL; ++ep) {
                    strncpy(tmpkey, *ep, 1024);
                    tmpkey[1023] = 0;
                    if ((tp = strchr(tmpkey, '=')) != NULL) {
                        *tp = 0;
                        if (strcmp(tmpkey, key) == 0) {
                            goto skip1;
                        }
                    }
                }
            }
            newenvp[newenvppos] = malloc(strlen(key) + strlen(env) + 3);
            strcpy(newenvp[newenvppos], key);
            strcat(newenvp[newenvppos], "=");
            strcat(newenvp[newenvppos], env);
            newenvppos++;
        skip1: ;
        }
    }

    /* Append old envp to new envp */
    if (envp) {
        for (ep = (char **) envp; *ep != NULL; ++ep) {
            newenvp[newenvppos] = *ep;
            newenvppos++;
        }
    }

    newenvp[newenvppos] = NULL;

    /* Check hashbang */
    expand_chroot_path(filename);
    strcpy(tmp, filename);
    filename = tmp;

    if ((file = nextcall(open)(filename, O_RDONLY)) == -1) {
        __set_errno(ENOENT);
        return errno;
    }

    i = read(file, hashbang, FAKECHROOT_PATH_MAX-2);
    close(file);
    if (i == -1) {
        __set_errno(ENOENT);
        return errno;
    }

    /* No hashbang in argv */
    if (hashbang[0] != '#' || hashbang[1] != '!') {
        /* Run via elfloader */
        /* Calculate number of extra args: elfloader + --library-path <path> + --preload <lib> + --argv0 <name> + filename */
        int extra_args = 1 + 2 + 2 + 2 + 1;

        /* Skip original argv[0] as it's already passed via --argv0 */
        for (i = 1, n = extra_args; argv[i] != NULL && i < argv_max; ) {
            newargv[n++] = argv[i++];
        }

        newargv[n] = 0;

        n = 0;
        newargv[n++] = ANDROID_ELFLOADER;
        newargv[n++] = "--library-path";
        newargv[n++] = ANDROID_LIBRARY_PATH;
        newargv[n++] = "--preload";
        newargv[n++] = ANDROID_PRELOAD;
        newargv[n++] = ANDROID_ARGV0_OPT;
        newargv[n++] = argv0;
        newargv[n] = filename;

        debug("nextcall(posix_spawn)(\"%s\", {\"%s\", \"%s\", ...}, {\"%s\", ...})", ANDROID_ELFLOADER, newargv[0], newargv[n], newenvp[0]);
        status = nextcall(posix_spawn)(pid, ANDROID_ELFLOADER, file_actions, attrp, (char * const *)newargv, newenvp);
        goto error;
    }

    /* For hashbang we must fix argv[0] */
    hashbang[i] = hashbang[i+1] = 0;
    for (i = j = 2; (hashbang[i] == ' ' || hashbang[i] == '\t') && i < FAKECHROOT_PATH_MAX; i++, j++);
    for (n = 0; i < FAKECHROOT_PATH_MAX; i++) {
        c = hashbang[i];
        if (hashbang[i] == 0 || hashbang[i] == ' ' || hashbang[i] == '\t' || hashbang[i] == '\n') {
            hashbang[i] = 0;
            if (i > j) {
                if (n == 0) {
                    const char *ptr = &hashbang[j];
                    expand_chroot_path(ptr);
                    strcpy(newfilename, ptr);
                }
                newargv[n++] = &hashbang[j];
            }
            j = i + 1;
        }
        if (c == '\n' || c == 0)
            break;
    }

    newargv[n++] = argv0;

    for (i = 1; argv[i] != NULL && i < argv_max; ) {
        newargv[n++] = argv[i++];
    }

    newargv[n] = 0;

    /* Run via elfloader for hashbang scripts
     * Note: We don't use --argv0 for hashbang scripts because the interpreter
     * already gets proper argv[0] from the hashbang parsing. */
    int extra_args2 = 1 + 2 + 2 + 1; /* elfloader + --library-path <path> + --preload <lib> + newfilename */

    j = extra_args2;
    if (n >= argv_max - j) {
        n = argv_max - j;
    }
    /* Shift elements from [1..n-1] to [j..j+n-2]
     * Skip newargv[0] (interpreter from hashbang) since it's redundant with newfilename.
     * The elfloader will load newfilename as the interpreter, so we don't want
     * the interpreter path to appear twice in the final argv.
     * Must iterate backwards to avoid overwriting uncopied elements. */
    newargv[j + n - 1] = 0;  /* null terminator at new end position */
    for (i = n - 1; i >= 1; i--) {
        newargv[i - 1 + j] = newargv[i];
    }
    n = 0;
    newargv[n++] = ANDROID_ELFLOADER;
    newargv[n++] = "--library-path";
    newargv[n++] = ANDROID_LIBRARY_PATH;
    newargv[n++] = "--preload";
    newargv[n++] = ANDROID_PRELOAD;
    newargv[n] = newfilename;
    debug("nextcall(posix_spawn)(\"%s\", {\"%s\", \"%s\", \"%s\", ...}, {\"%s\", ...})", ANDROID_ELFLOADER, newargv[0], newargv[1], newargv[n], newenvp[0]);
    status = nextcall(posix_spawn)(pid, ANDROID_ELFLOADER, file_actions, attrp, (char * const *)newargv, newenvp);

error:
    free(newenvp);

    return status;
}

#endif
