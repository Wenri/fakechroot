/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2010-2015 Piotr Roszatycki <dexter@debian.org>

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

#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#endif
#include <stdlib.h>
#include <fcntl.h>
#include "strchrnul.h"
#include "libfakechroot.h"
#include "open.h"
#include "setenv.h"
#include "readlink.h"
#include "android-config.h"


wrapper(execve, int, (const char * filename, char * const argv [], char * const envp []))
{
    char fakechroot_abspath[FAKECHROOT_PATH_MAX];
    char fakechroot_buf[FAKECHROOT_PATH_MAX];

    int status;
    int file;
    char hashbang[FAKECHROOT_PATH_MAX];
    size_t argv_max = 1024;
    char **newenvp, **ep;
    char *key, *env;
    char tmpkey[1024], *tp;
    char tmp[FAKECHROOT_PATH_MAX];
    char newfilename[FAKECHROOT_PATH_MAX];
    char argv0[FAKECHROOT_PATH_MAX];
    char shebang_argv0[FAKECHROOT_PATH_MAX];  /* Original shebang interpreter for argv[0] */
    unsigned int i, j, n, newenvppos;
    size_t sizeenvp;
    char c;

    const char **newargv = alloca(argv_max * sizeof (const char *));

    debug("execve(\"%s\", {\"%s\", ...}, {\"%s\", ...})", filename, argv[0], envp ? envp[0] : "(null)");

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
        return -1;
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

    /* If executing any dynamic linker (ld.so), don't wrap it - ld.so cannot load itself.
     * This happens when programs like the login script or nix daemon invoke ld.so directly.
     *
     * We detect ld.so by checking if the basename starts with "ld-" and ends with ".so" variants.
     * Note: We must NOT replace the path with ANDROID_ELFLOADER - different programs may use
     * different versions of glibc, and we need to respect their choice. */
    {
        const char *filename_basename = strrchr(filename, '/');
        if (filename_basename) {
            filename_basename++;  /* Skip the '/' */
            /* Check for common dynamic linker names: ld-linux-*.so.*, ld.so.*, etc. */
            if (strncmp(filename_basename, "ld-", 3) == 0 ||
                strncmp(filename_basename, "ld.so", 5) == 0) {
                debug("execve: executing dynamic linker directly, no wrapping: %s", filename);
                status = nextcall(execve)(filename, argv, newenvp);
                free(newenvp);
                return status;
            }
        }
    }

    if ((file = nextcall(open)(filename, O_RDONLY)) == -1) {
        __set_errno(ENOENT);
        return -1;
    }

    i = read(file, hashbang, FAKECHROOT_PATH_MAX-2);
    close(file);
    if (i == -1) {
        __set_errno(ENOENT);
        return -1;
    }

    /* No hashbang in argv */
    if (hashbang[0] != '#' || hashbang[1] != '!') {
        /* Run via elfloader for ELF binaries.
         * ld.so handles:
         *   - preloading libfakechroot via /etc/ld.so.preload
         *   - glibc path redirection (standard glibc -> android glibc)
         *   - /nix/store path translation
         *
         * argv layout: [argv0, --argv0, argv0, filename, user_args...]
         * - First argv0 is ld.so's argv[0] (shows in ps/top as command name)
         * - --argv0 + argv0 sets the program's argv[0] (for login shell detection)
         * - filename is the actual program to execute
         */
        int extra_args = 1 + 2 + 1;  /* argv0 + --argv0 + argv0 + filename */

        /* Skip original argv[0] as it's already passed via --argv0
         * This prevents login shells from seeing "-zsh" as both argv[0] and argv[1] */
        for (i = 1, n = extra_args; argv[i] != NULL && i < argv_max; ) {
            newargv[n++] = argv[i++];
        }

        newargv[n] = 0;

        n = 0;
        newargv[n++] = argv0;             /* ld.so's argv[0]: original command name for ps */
        newargv[n++] = ANDROID_ARGV0_OPT;
        newargv[n++] = argv0;
        newargv[n] = filename;

        debug("nextcall(execve)(\"%s\", {\"%s\", \"%s\", \"%s\", \"%s\", ...}, {\"%s\", ...})", ANDROID_ELFLOADER, newargv[0], newargv[1], newargv[2], newargv[3], newenvp[0]);
        status = nextcall(execve)(ANDROID_ELFLOADER, (char * const *)newargv, newenvp);
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
                    /* Save original shebang interpreter path for argv[0] (before expansion)
                     * This follows kernel behavior: interpreter's argv[0] = shebang path as-is */
                    strncpy(shebang_argv0, &hashbang[j], FAKECHROOT_PATH_MAX - 1);
                    shebang_argv0[FAKECHROOT_PATH_MAX - 1] = '\0';
                    debug("execve: shebang_argv0=\"%s\" (original shebang interpreter)", shebang_argv0);
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

    /* Add the script path for the interpreter to execute.
     * This is critical - the interpreter needs to know what script to run.
     * Using 'filename' (expanded path) instead of 'argv0' (just the name). */
    newargv[n++] = filename;

    for (i = 1; argv[i] != NULL && i < argv_max; ) {
        newargv[n++] = argv[i++];
    }

    newargv[n] = 0;

    /* Run via elfloader for hashbang scripts.
     * ld.so handles preloading and glibc redirection automatically.
     *
     * Final argv should be:
     *   [shebang_interp, --argv0, shebang_interp, interpreter, interp_args..., script_path, user_args...]
     *
     * Where:
     * - First shebang_interp is ld.so's argv[0] (shows in ps/top)
     * - --argv0 + shebang_interp tells ld.so to set interpreter's argv[0] to the
     *   shebang interpreter path (as-is), following kernel behavior for $^X etc.
     * - interpreter is the resolved hashbang interpreter path
     * - interp_args are hashbang arguments (e.g., -e)
     * - script_path is the script to execute (interpreter uses this for $0)
     * - user_args are the original arguments after argv[0]
     */
    int extra_args2 = 1 + 2 + 1; /* shebang_argv0 + --argv0 + shebang_argv0 + newfilename (interpreter) */

    j = extra_args2;
    if (n >= argv_max - j) {
        n = argv_max - j;
    }
    /* Shift elements from [1..n-1] to [j..j+n-2]
     * Skip newargv[0] (interpreter from hashbang) since it's redundant with newfilename.
     * The elfloader will load newfilename as the interpreter.
     * Must iterate backwards to avoid overwriting uncopied elements. */
    newargv[j + n - 1] = 0;  /* null terminator at new end position */
    for (i = n - 1; i >= 1; i--) {
        newargv[i - 1 + j] = newargv[i];
    }
    n = 0;
    newargv[n++] = shebang_argv0;     /* ld.so's argv[0]: shebang interpreter path for ps */
    newargv[n++] = ANDROID_ARGV0_OPT; /* --argv0 */
    newargv[n++] = shebang_argv0;     /* interpreter's argv[0]: shebang path (kernel behavior for $^X) */
    newargv[n] = newfilename;         /* interpreter path (resolved) */
    debug("nextcall(execve)(\"%s\", {\"%s\", \"%s\", \"%s\", \"%s\", ...}, {\"%s\", ...})", ANDROID_ELFLOADER, newargv[0], newargv[1], newargv[2], newargv[3], newenvp[0]);
    status = nextcall(execve)(ANDROID_ELFLOADER, (char * const *)newargv, newenvp);

error:
    free(newenvp);

    return status;
}
