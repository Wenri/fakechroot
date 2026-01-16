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
#include <elf.h>
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
 * Read PT_INTERP from 64-bit ELF file.
 * Stores interpreter path in ctx->hashbang.
 *
 * Returns:
 *   1  = PT_INTERP found and stored
 *   0  = Valid ELF but no PT_INTERP (static binary)
 *  -1  = Read error
 */
static int exec_read_elf64_interp(exec_ctx_t *ctx, int fd, const unsigned char *header)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)header;
    Elf64_Phdr phdr;
    int i;

    /* Iterate program headers looking for PT_INTERP */
    for (i = 0; i < ehdr->e_phnum; i++) {
        off_t phdr_offset = ehdr->e_phoff + (i * ehdr->e_phentsize);

        if (lseek(fd, phdr_offset, SEEK_SET) == (off_t)-1) {
            return -1;
        }

        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) {
            return -1;
        }

        if (phdr.p_type == PT_INTERP) {
            /* Validate size */
            if (phdr.p_filesz == 0 || phdr.p_filesz >= FAKECHROOT_PATH_MAX) {
                return -1;
            }

            if (lseek(fd, phdr.p_offset, SEEK_SET) == (off_t)-1) {
                return -1;
            }

            /* Read interpreter path into hashbang buffer */
            ssize_t n = read(fd, ctx->hashbang, phdr.p_filesz);
            if (n != (ssize_t)phdr.p_filesz) {
                return -1;
            }
            ctx->hashbang[phdr.p_filesz] = '\0';
            return 1;  /* PT_INTERP found */
        }
    }

    return 0;  /* No PT_INTERP = static binary */
}


/*
 * Read PT_INTERP from 32-bit ELF file.
 * Stores interpreter path in ctx->hashbang.
 *
 * Returns:
 *   1  = PT_INTERP found and stored
 *   0  = Valid ELF but no PT_INTERP (static binary)
 *  -1  = Read error
 */
static int exec_read_elf32_interp(exec_ctx_t *ctx, int fd, const unsigned char *header)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)header;
    Elf32_Phdr phdr;
    int i;

    /* Iterate program headers looking for PT_INTERP */
    for (i = 0; i < ehdr->e_phnum; i++) {
        off_t phdr_offset = ehdr->e_phoff + (i * ehdr->e_phentsize);

        if (lseek(fd, phdr_offset, SEEK_SET) == (off_t)-1) {
            return -1;
        }

        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) {
            return -1;
        }

        if (phdr.p_type == PT_INTERP) {
            /* Validate size */
            if (phdr.p_filesz == 0 || phdr.p_filesz >= FAKECHROOT_PATH_MAX) {
                return -1;
            }

            if (lseek(fd, phdr.p_offset, SEEK_SET) == (off_t)-1) {
                return -1;
            }

            /* Read interpreter path into hashbang buffer */
            ssize_t n = read(fd, ctx->hashbang, phdr.p_filesz);
            if (n != (ssize_t)phdr.p_filesz) {
                return -1;
            }
            ctx->hashbang[phdr.p_filesz] = '\0';
            return 1;  /* PT_INTERP found */
        }
    }

    return 0;  /* No PT_INTERP = static binary */
}


/*
 * Read PT_INTERP from ELF file (dispatches to 32/64-bit parser).
 * Stores interpreter path in ctx->hashbang.
 *
 * Returns:
 *   1  = PT_INTERP found and stored in ctx->hashbang
 *   0  = Valid ELF but no PT_INTERP (static binary)
 *  -1  = Not ELF or read error
 */
static int exec_read_elf_interp(exec_ctx_t *ctx, int fd, const unsigned char *header)
{
    /* Check ELF magic: 0x7f 'E' 'L' 'F' */
    if (header[0] != 0x7f || header[1] != 'E' ||
        header[2] != 'L' || header[3] != 'F') {
        return -1;  /* Not ELF */
    }

    /* Dispatch to 32/64-bit parser based on EI_CLASS */
    if (header[EI_CLASS] == ELFCLASS64) {
        return exec_read_elf64_interp(ctx, fd, header);
    } else {
        return exec_read_elf32_interp(ctx, fd, header);
    }
}


/*
 * Check if interpreter path allows direct execution (no ld.so wrapper needed).
 * Returns 1 if direct execution is allowed, 0 otherwise.
 */
static int is_direct_exec_interp(const char *interp)
{
    /* Android glibc's ld.so */
    if (strcmp(interp, ANDROID_ELFLOADER) == 0) {
        return 1;
    }

    /* nix-ld shim path (patched nix binaries) */
    if (strcmp(interp, "/data/data/com.termux.nix/files/usr/lib/ld-linux-aarch64.so.1") == 0) {
        return 1;
    }

    /* Android Bionic linker (native Android binaries) */
    if (strcmp(interp, "/system/bin/linker64") == 0 ||
        strcmp(interp, "/system/bin/linker") == 0) {
        return 1;
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
 * Prepare execution context: initialize and expand filename.
 */
exec_ctx_t exec_prepare(const char *filename, char * const argv[])
{
    exec_ctx_t ctx = {0};

    /* Local buffers for expand_chroot_path macro */
    char fakechroot_abspath[FAKECHROOT_PATH_MAX];
    char fakechroot_buf[FAKECHROOT_PATH_MAX];

    /* Preserve original argv[0] for --argv0 option.
     * This is important for login shells where argv[0] is "-zsh" or "-bash" */
    if (argv && argv[0]) {
        strncpy(ctx.argv0, argv[0], FAKECHROOT_PATH_MAX - 1);
        ctx.argv0[FAKECHROOT_PATH_MAX - 1] = '\0';
    }

    /* Expand filename path */
    expand_chroot_path(filename);
    strncpy(ctx.expandedFilename, filename, FAKECHROOT_PATH_MAX - 1);
    ctx.expandedFilename[FAKECHROOT_PATH_MAX - 1] = '\0';

    /* Check if executing dynamic linker directly */
    if (is_dynamic_linker(ctx.expandedFilename)) {
        ctx.type = EXEC_TYPE_LDSO;
        debug("exec: executing dynamic linker directly, no wrapping: %s", ctx.expandedFilename);
    }

    return ctx;
}


/*
 * Read file header to detect hashbang scripts vs ELF binaries.
 * For ELF files, also reads PT_INTERP to determine if direct execution is possible.
 */
static int exec_read_header(exec_ctx_t *ctx)
{
    int file;
    int i;

    file = nextcall(open)(ctx->expandedFilename, O_RDONLY);
    if (file == -1) {
        __set_errno(ENOENT);
        return -1;
    }

    i = read(file, ctx->hashbang, FAKECHROOT_PATH_MAX - 2);
    if (i == -1) {
        close(file);
        __set_errno(ENOENT);
        return -1;
    }

    /* Null-terminate the buffer */
    ctx->hashbang[i] = ctx->hashbang[i + 1] = '\0';

    /* Check for hashbang */
    if (ctx->hashbang[0] == '#' && ctx->hashbang[1] == '!') {
        ctx->type = EXEC_TYPE_SCRIPT;
        close(file);
        return 0;
    }

    /* Try to read PT_INTERP from ELF to determine execution type */
    int result = exec_read_elf_interp(ctx, file, (unsigned char *)ctx->hashbang);

    if (result == 1) {
        /* PT_INTERP found - check if direct execution allowed */
        if (is_direct_exec_interp(ctx->hashbang)) {
            ctx->type = EXEC_TYPE_ELF_DIRECT;
            debug("exec: ELF with direct-exec interpreter: %s", ctx->hashbang);
        } else {
            ctx->type = EXEC_TYPE_ELF;
            debug("exec: ELF needs wrapper, PT_INTERP: %s", ctx->hashbang);
        }
    } else if (result == 0) {
        /* Valid ELF but no PT_INTERP = static binary, needs wrapper for sigaction setup */
        ctx->type = EXEC_TYPE_ELF;
        debug("exec: static ELF binary, using wrapper for sigaction setup");
    } else {
        /* Not ELF or read error - use wrapper (safe fallback) */
        ctx->type = EXEC_TYPE_ELF;
        debug("exec: not ELF or read error, using wrapper");
    }

    close(file);
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
static void exec_build_elf_argv(exec_ctx_t *ctx, char **newargv, char * const argv[])
{
    unsigned int i, n;

    /* Copy user arguments (skip original argv[0], it's passed via --argv0) */
    for (i = 1, n = EXEC_PREFIX_LEN; argv[i] != NULL; ) {
        newargv[n++] = argv[i++];
    }
    newargv[n] = NULL;

    /* Set up elfloader arguments */
    n = 0;
    newargv[n++] = ctx->argv0;           /* ld.so's argv[0]: command name for ps */
    newargv[n++] = ANDROID_ARGV0_OPT;    /* --argv0 */
    newargv[n++] = ctx->argv0;           /* program's argv[0] */
    newargv[n] = ctx->expandedFilename;               /* program path */
}


/*
 * Build argument vector for direct ELF execution (no wrapper needed).
 * Simply copies original argv unchanged.
 */
static void exec_build_direct_argv(exec_ctx_t *ctx, char **newargv, char * const argv[])
{
    unsigned int i;

    (void)ctx;  /* unused, but kept for consistent API */

    for (i = 0; argv[i] != NULL; i++) {
        newargv[i] = argv[i];
    }
    newargv[i] = NULL;
}


/*
 * Parse hashbang line following Linux kernel behavior:
 * - Interpreter path (first token)
 * - Optional single argument (everything after first whitespace until newline)
 *
 * Stores expanded interpreter in ctx->argv0.
 * Returns pointer to original interpreter in hashbang (for display/argv0).
 * Sets *shebangArg to optional argument (or NULL).
 */
static char *parse_shebang(exec_ctx_t *ctx, char **shebangArg)
{
    /* Local buffers for expand_chroot_path macro */
    char fakechroot_abspath[FAKECHROOT_PATH_MAX];
    char fakechroot_buf[FAKECHROOT_PATH_MAX];

    /* Null-terminate at first newline - we only care about shebang line */
    char *nl = strchr(ctx->hashbang, '\n');
    if (nl) *nl = '\0';

    /* Get interpreter (first whitespace-delimited token after "#!")
     * shebangArg is used as saveptr, will point to rest of line */
    char *originalInterp = strtok_r(ctx->hashbang + 2, " \t", shebangArg);
    if (!originalInterp) {
        *shebangArg = NULL;
        return NULL;
    }
    debug("exec: originalInterp=\"%s\" (from shebang)", originalInterp);

    /* Expand interpreter path and store in ctx->argv0 */
    const char *ptr = originalInterp;
    expand_chroot_path(ptr);
    strncpy(ctx->argv0, ptr, FAKECHROOT_PATH_MAX - 1);
    ctx->argv0[FAKECHROOT_PATH_MAX - 1] = '\0';

    /* Skip leading whitespace in shebangArg */
    *shebangArg += strspn(*shebangArg, " \t");

    /* If empty, set to NULL */
    if (!**shebangArg) {
        *shebangArg = NULL;
    } else {
        debug("exec: shebangArg=\"%s\"", *shebangArg);
    }

    return originalInterp;
}

/*
 * Build argument vector for script execution via elfloader.
 *
 * Final argv layout:
 *   [displayArgv0, --argv0, displayArgv0, expandedInterp, shebang_arg?, script_path, user_args..., NULL]
 *
 * Where:
 *   - displayArgv0 = original interpreter from shebang (for ps/top and $^X)
 *   - expandedInterp = ctx->argv0 = expanded interpreter path (for ld.so to load)
 *   - shebang_arg is optional (only if shebang has argument after interpreter)
 */
static void exec_build_script_argv(exec_ctx_t *ctx, char **newargv, char * const argv[])
{
    unsigned int i, n;
    char *shebangArg;
    char *displayArgv0;

    /* Parse shebang line:
     * - Stores expanded interpreter in ctx->argv0
     * - Returns original interpreter pointer (for display)
     * - Sets shebangArg pointer (or NULL) */
    displayArgv0 = parse_shebang(ctx, &shebangArg);

    /* Build argv directly in correct order */
    n = 0;
    newargv[n++] = displayArgv0;         /* ld.so's argv[0]: original for ps */
    newargv[n++] = ANDROID_ARGV0_OPT;    /* --argv0 */
    newargv[n++] = displayArgv0;         /* interpreter's argv[0]: original for $^X */
    newargv[n++] = ctx->argv0;           /* expanded interpreter (for ld.so to load) */

    /* Add optional shebang argument (kernel passes only 1 arg) */
    if (shebangArg) {
        newargv[n++] = shebangArg;
    }

    /* Add script path */
    newargv[n++] = ctx->expandedFilename;

    /* Add user arguments (skip argv[0]) */
    for (i = 1; argv[i] != NULL; ) {
        newargv[n++] = argv[i++];
    }
    newargv[n] = NULL;
}


/*
 * Read file header and build argument vector for elfloader.
 * Dispatches to appropriate builder based on detected file type.
 */
int exec_build_argv(exec_ctx_t *ctx, char **newargv, char * const argv[])
{
    if (exec_read_header(ctx) != 0) {
        return -1;
    }

    switch (ctx->type) {
        case EXEC_TYPE_SCRIPT:
            exec_build_script_argv(ctx, newargv, argv);
            break;
        case EXEC_TYPE_ELF_DIRECT:
            exec_build_direct_argv(ctx, newargv, argv);
            break;
        case EXEC_TYPE_ELF:
        default:
            exec_build_elf_argv(ctx, newargv, argv);
            break;
    }

    return 0;
}


/*
 * Get the executable path for the final exec call.
 */
const char *exec_get_path(exec_ctx_t *ctx)
{
    switch (ctx->type) {
        case EXEC_TYPE_LDSO:
        case EXEC_TYPE_ELF_DIRECT:
            return ctx->expandedFilename;
        default:
            return ANDROID_ELFLOADER;
    }
}


/*
 * execve wrapper - uses shared exec_* functions with VLAs
 */
wrapper(execve, int, (const char * filename, char * const argv [], char * const envp []))
{
    int argc, envc;
    char **p;

    debug("execve(\"%s\", {\"%s\", ...}, {\"%s\", ...})", filename, argv[0], envp ? envp[0] : "(null)");

    /* Count arguments and environment variables */
    for (argc = 0, p = (char **)argv; *p; p++) argc++;
    for (envc = 0, p = (char **)envp; envp && *p; p++) envc++;

    /* VLAs for exact-size allocation
     * newargv max (script with shebang arg):
     *   prefix(4) + shebang_arg(1) + script(1) + user_args(argc-1) + NULL(1) = argc + 6
     * Expressed as: argc + EXEC_PREFIX_LEN(4) + MAX_SHEBANG_ARGS(1) + 1 (script path) */
    char *newargv[argc + EXEC_PREFIX_LEN + MAX_SHEBANG_ARGS + 1];
    char *newenvp[envc + preserve_env_list_count + 1];
    char envbuf[exec_preserve_env(envp, NULL, NULL) + 1];

    /* Build environment and prepare context */
    exec_preserve_env(envp, newenvp, envbuf);
    exec_ctx_t ctx = exec_prepare(filename, argv);

    /* If executing ld.so directly, don't wrap it */
    if (ctx.type == EXEC_TYPE_LDSO) {
        return nextcall(execve)(ctx.expandedFilename, argv, newenvp);
    }

    if (exec_build_argv(&ctx, newargv, argv) != 0) {
        return -1;
    }

    if (ctx.type == EXEC_TYPE_ELF_DIRECT) {
        debug("nextcall(execve)(\"%s\", {\"%s\", ...}, ...) [direct]",
              exec_get_path(&ctx), newargv[0]);
    } else {
        debug("nextcall(execve)(\"%s\", {\"%s\", \"%s\", \"%s\", \"%s\", ...}, ...)",
              exec_get_path(&ctx), newargv[0], newargv[1], newargv[2], newargv[3]);
    }

    return nextcall(execve)(exec_get_path(&ctx), newargv, newenvp);
}
