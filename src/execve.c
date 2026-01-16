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
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include "strchrnul.h"
#include "libfakechroot.h"
#include "open.h"
#include "setenv.h"
#include "readlink.h"
#include "android-config.h"
#include "execve.h"


/*
 * Check if filename is a dynamic linker (ld.so).
 */
static int is_dynamic_linker(const char *filename)
{
    const char *basename = strrchr(filename, '/');
    if (basename) {
        basename++;  /* Skip the '/' */
        /* Check for common dynamic linker names: ld-linux-*.so.*, ld.so.*, etc. */
        if (strncmp(basename, "ld-", 3) == 0 ||
            strncmp(basename, "ld.so", 5) == 0) {
            return 1;
        }
    }
    return 0;
}


/*
 * Build environment array with preserved variables.
 * If newenvp/envbuf are NULL, just calculate required buffer size.
 * If newenvp/envbuf are non-NULL, build complete environment array.
 *
 * @param envp       Original environment
 * @param newenvp    Environment array to populate (NULL for size calc only)
 * @param envbuf     Buffer for env strings (NULL for size calc only)
 * @return Buffer size needed/used (minimum 1 for empty VLA)
 */
size_t exec_preserve_env(char * const envp[], char **newenvp, char *envbuf)
{
    size_t total = 0;
    char *bufptr = envbuf;
    unsigned int j, envpos = 0;
    char *key, *env;
    char **ep;
    char tmpkey[1024], *tp;
    int skip;

    /* Add preserved vars not already in envp */
    for (j = 0; j < preserve_env_list_count; j++) {
        key = preserve_env_list[j];
        env = getenv(key);
        if (env != NULL && *env) {
            /* Check if already in envp */
            skip = 0;
            if (envp) {
                for (ep = (char **)envp; *ep != NULL; ++ep) {
                    strncpy(tmpkey, *ep, 1024);
                    tmpkey[1023] = 0;
                    if ((tp = strchr(tmpkey, '=')) != NULL) {
                        *tp = 0;
                        if (strcmp(tmpkey, key) == 0) {
                            skip = 1;
                            break;
                        }
                    }
                }
            }
            if (!skip) {
                size_t len = strlen(key) + strlen(env) + 2;
                total += len;
                if (newenvp) {
                    newenvp[envpos] = bufptr;
                    strcpy(bufptr, key);
                    strcat(bufptr, "=");
                    strcat(bufptr, env);
                    bufptr += len;
                    envpos++;
                }
            }
        }
    }

    /* Append original envp */
    if (newenvp) {
        if (envp) {
            for (ep = (char **)envp; *ep != NULL; ++ep) {
                newenvp[envpos++] = *ep;
            }
        }
        newenvp[envpos] = NULL;
    }

    return total;
}


/*
 * Prepare execution context: initialize, copy environment, expand filename.
 */
int exec_prepare(exec_ctx_t *ctx, const char **newargv, char **newenvp,
                 char *envbuf, const char *filename,
                 char * const argv[], char * const envp[])
{
    /* These local refs are needed for expand_chroot_path macro */
    char *fakechroot_abspath = ctx->fakechroot_abspath;
    char *fakechroot_buf = ctx->fakechroot_buf;

    /* Initialize context */
    memset(ctx, 0, sizeof(*ctx));
    ctx->newargv = newargv;
    ctx->newenvp = newenvp;

    /* Preserve original argv[0] for --argv0 option.
     * This is important for login shells where argv[0] is "-zsh" or "-bash" */
    if (argv && argv[0]) {
        strncpy(ctx->argv0, argv[0], FAKECHROOT_PATH_MAX - 1);
        ctx->argv0[FAKECHROOT_PATH_MAX - 1] = '\0';
    }

    /* Build environment: preserved vars + original envp */
    exec_preserve_env(envp, ctx->newenvp, envbuf);

    /* Expand filename path */
    expand_chroot_path(filename);
    strncpy(ctx->tmp, filename, FAKECHROOT_PATH_MAX - 1);
    ctx->tmp[FAKECHROOT_PATH_MAX - 1] = '\0';

    /* Check if executing dynamic linker directly */
    ctx->is_ld_so = is_dynamic_linker(ctx->tmp);
    if (ctx->is_ld_so) {
        debug("exec: executing dynamic linker directly, no wrapping: %s", ctx->tmp);
    }

    return 0;
}


/*
 * Read file header to detect hashbang scripts vs ELF binaries.
 */
int exec_read_header(exec_ctx_t *ctx)
{
    int file;
    int i;

    file = nextcall(open)(ctx->tmp, O_RDONLY);
    if (file == -1) {
        __set_errno(ENOENT);
        return -1;
    }

    i = read(file, ctx->hashbang, FAKECHROOT_PATH_MAX - 2);
    close(file);

    if (i == -1) {
        __set_errno(ENOENT);
        return -1;
    }

    ctx->hashbang_len = i;
    ctx->hashbang[i] = ctx->hashbang[i + 1] = '\0';

    /* Check for hashbang */
    ctx->is_script = (ctx->hashbang[0] == '#' && ctx->hashbang[1] == '!');

    return 0;
}


/*
 * Build argument vector for ELF binary execution via elfloader.
 *
 * argv layout: [argv0, --argv0, argv0, filename, user_args...]
 * - First argv0 is ld.so's argv[0] (shows in ps/top as command name)
 * - --argv0 + argv0 sets the program's argv[0] (for login shell detection)
 * - filename is the actual program to execute
 */
void exec_build_elf_argv(exec_ctx_t *ctx, char * const argv[])
{
    unsigned int i, n;

    /* Copy user arguments (skip original argv[0], it's passed via --argv0) */
    for (i = 1, n = EXEC_EXTRA_ARGV; argv[i] != NULL; ) {
        ctx->newargv[n++] = argv[i++];
    }
    ctx->newargv[n] = NULL;

    /* Set up elfloader arguments */
    n = 0;
    ctx->newargv[n++] = ctx->argv0;           /* ld.so's argv[0]: command name for ps */
    ctx->newargv[n++] = ANDROID_ARGV0_OPT;    /* --argv0 */
    ctx->newargv[n++] = ctx->argv0;           /* program's argv[0] */
    ctx->newargv[n] = ctx->tmp;               /* program path */
}


/*
 * Parse hashbang line and build argument vector for script execution.
 *
 * Final argv layout:
 *   [shebang_interp, --argv0, shebang_interp, interpreter, interp_args..., script_path, user_args...]
 */
void exec_build_script_argv(exec_ctx_t *ctx, char * const argv[])
{
    /* These local refs are needed for expand_chroot_path macro */
    char *fakechroot_abspath = ctx->fakechroot_abspath;
    char *fakechroot_buf = ctx->fakechroot_buf;

    unsigned int i, j, n;
    char c;

    /* Parse hashbang: skip "#!" and leading whitespace */
    for (i = j = 2; (ctx->hashbang[i] == ' ' || ctx->hashbang[i] == '\t') && i < FAKECHROOT_PATH_MAX; i++, j++)
        ;

    /* Parse interpreter and arguments from hashbang line */
    for (n = 0; i < FAKECHROOT_PATH_MAX; i++) {
        c = ctx->hashbang[i];
        if (c == '\0' || c == ' ' || c == '\t' || c == '\n') {
            ctx->hashbang[i] = '\0';
            if (i > j) {
                if (n == 0) {
                    /* First token is the interpreter.
                     * Save original shebang path for argv[0] (kernel behavior for $^X) */
                    strncpy(ctx->shebang_argv0, &ctx->hashbang[j], FAKECHROOT_PATH_MAX - 1);
                    ctx->shebang_argv0[FAKECHROOT_PATH_MAX - 1] = '\0';
                    debug("exec: shebang_argv0=\"%s\"", ctx->shebang_argv0);

                    /* Expand interpreter path */
                    const char *ptr = &ctx->hashbang[j];
                    expand_chroot_path(ptr);
                    strncpy(ctx->newfilename, ptr, FAKECHROOT_PATH_MAX - 1);
                    ctx->newfilename[FAKECHROOT_PATH_MAX - 1] = '\0';
                }
                ctx->newargv[n++] = &ctx->hashbang[j];
            }
            j = i + 1;
        }
        if (c == '\n' || c == '\0')
            break;
    }

    /* Add the script path for the interpreter */
    ctx->newargv[n++] = ctx->tmp;

    /* Add user arguments (skip argv[0]) */
    for (i = 1; argv[i] != NULL; ) {
        ctx->newargv[n++] = argv[i++];
    }
    ctx->newargv[n] = NULL;

    /* Now shift everything to make room for elfloader args at the front.
     * Skip newargv[0] (interpreter from hashbang) since it's redundant with newfilename. */
    j = EXEC_EXTRA_ARGV;

    /* Shift elements from [1..n-1] to [j..j+n-2], iterate backwards */
    ctx->newargv[j + n - 1] = NULL;
    for (i = n - 1; i >= 1; i--) {
        ctx->newargv[i - 1 + j] = ctx->newargv[i];
    }

    /* Set up elfloader arguments */
    n = 0;
    ctx->newargv[n++] = ctx->shebang_argv0;   /* ld.so's argv[0]: shebang path for ps */
    ctx->newargv[n++] = ANDROID_ARGV0_OPT;    /* --argv0 */
    ctx->newargv[n++] = ctx->shebang_argv0;   /* interpreter's argv[0]: shebang path */
    ctx->newargv[n] = ctx->newfilename;       /* interpreter path (resolved) */
}


/*
 * Get the executable path for the final exec call.
 */
const char *exec_get_path(exec_ctx_t *ctx)
{
    if (ctx->is_ld_so) {
        return ctx->tmp;
    }
    return ANDROID_ELFLOADER;
}


/*
 * execve wrapper - uses shared exec_* functions with VLAs
 */
wrapper(execve, int, (const char * filename, char * const argv [], char * const envp []))
{
    exec_ctx_t ctx;
    int argc, envc;
    char **p;

    debug("execve(\"%s\", {\"%s\", ...}, {\"%s\", ...})", filename, argv[0], envp ? envp[0] : "(null)");

    /* Count arguments and environment variables */
    for (argc = 0, p = (char **)argv; *p; p++) argc++;
    for (envc = 0, p = (char **)envp; envp && *p; p++) envc++;

    /* VLAs for exact-size allocation */
    const char *newargv[argc + EXEC_EXTRA_ARGV + 1];
    char *newenvp[envc + preserve_env_list_count + 1];
    char envbuf[exec_preserve_env(envp, NULL, NULL) + 1];

    if (exec_prepare(&ctx, newargv, newenvp, envbuf, filename, argv, envp) != 0) {
        return -1;
    }

    /* If executing ld.so directly, don't wrap it */
    if (ctx.is_ld_so) {
        return nextcall(execve)(ctx.tmp, argv, ctx.newenvp);
    }

    if (exec_read_header(&ctx) != 0) {
        return -1;
    }

    if (ctx.is_script) {
        exec_build_script_argv(&ctx, argv);
    } else {
        exec_build_elf_argv(&ctx, argv);
    }

    debug("nextcall(execve)(\"%s\", {\"%s\", \"%s\", \"%s\", \"%s\", ...}, ...)",
          exec_get_path(&ctx), ctx.newargv[0], ctx.newargv[1], ctx.newargv[2], ctx.newargv[3]);

    return nextcall(execve)(exec_get_path(&ctx), (char * const *)ctx.newargv, ctx.newenvp);
}
