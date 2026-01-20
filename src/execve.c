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
 * Stores interpreter path in interp_buf.
 *
 * Returns:
 *   1  = PT_INTERP found and stored
 *   0  = Valid ELF but no PT_INTERP (static binary)
 *  -1  = Read error
 */
static int exec_read_elf64_interp(char *interp_buf, int fd, const unsigned char *header)
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

            /* Read interpreter path into buffer */
            ssize_t n = read(fd, interp_buf, phdr.p_filesz);
            if (n != (ssize_t)phdr.p_filesz) {
                return -1;
            }
            interp_buf[phdr.p_filesz] = '\0';
            return 1;  /* PT_INTERP found */
        }
    }

    return 0;  /* No PT_INTERP = static binary */
}


/*
 * Read PT_INTERP from 32-bit ELF file.
 * Stores interpreter path in interp_buf.
 *
 * Returns:
 *   1  = PT_INTERP found and stored
 *   0  = Valid ELF but no PT_INTERP (static binary)
 *  -1  = Read error
 */
static int exec_read_elf32_interp(char *interp_buf, int fd, const unsigned char *header)
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

            /* Read interpreter path into buffer */
            ssize_t n = read(fd, interp_buf, phdr.p_filesz);
            if (n != (ssize_t)phdr.p_filesz) {
                return -1;
            }
            interp_buf[phdr.p_filesz] = '\0';
            return 1;  /* PT_INTERP found */
        }
    }

    return 0;  /* No PT_INTERP = static binary */
}


/*
 * Read PT_INTERP from ELF file (dispatches to 32/64-bit parser).
 * Stores interpreter path in interp_buf.
 *
 * Returns:
 *   1  = PT_INTERP found and stored in interp_buf
 *   0  = Valid ELF but no PT_INTERP (static binary)
 *  -1  = Not ELF or read error
 */
static int exec_read_elf_interp(char *interp_buf, int fd, const unsigned char *header)
{
    /* Check ELF magic: 0x7f 'E' 'L' 'F' */
    if (header[0] != 0x7f || header[1] != 'E' ||
        header[2] != 'L' || header[3] != 'F') {
        return -1;  /* Not ELF */
    }

    /* Dispatch to 32/64-bit parser based on EI_CLASS */
    if (header[EI_CLASS] == ELFCLASS64) {
        return exec_read_elf64_interp(interp_buf, fd, header);
    } else {
        return exec_read_elf32_interp(interp_buf, fd, header);
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
LOCAL size_t exec_preserve_env(char * const envp[], char **newenvp, char *envbuf)
{
    size_t total = 0;
    char *bufptr = envbuf;
    size_t j;
    unsigned int envpos = 0;
    const char *key;
    char *env;
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
                size_t keylen = strlen(key);
                size_t envlen = strlen(env);
                size_t len = keylen + envlen + 2;
                total += len;
                if (newenvp) {
                    newenvp[envpos] = bufptr;
                    memcpy(bufptr, key, keylen);
                    bufptr[keylen] = '=';
                    memcpy(bufptr + keylen + 1, env, envlen + 1);
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
 * Prepare execution context: expand filename and detect file type.
 * Reads file header to determine if it's ELF, script, or other.
 * Returns context with type set; errno set on error.
 *
 * Buffer Reuse Strategy:
 * ----------------------
 * The expand_chroot_path() macro requires two temporary buffers:
 *   - fakechroot_abspath: for building absolute paths
 *   - fakechroot_buf: for intermediate path manipulation
 *
 * Instead of allocating 2 * FAKECHROOT_PATH_MAX (~8KB) on the stack,
 * we reuse ctx.interpPath and ctx.hashbang which are unused at this point:
 *
 *   Timeline of ctx buffer usage in exec_prepare():
 *   ┌─────────────────────┬──────────────────┬─────────────────────┐
 *   │ Phase               │ ctx.interpPath   │ ctx.hashbang        │
 *   ├─────────────────────┼──────────────────┼─────────────────────┤
 *   │ expand_chroot_path  │ fakechroot_abspath│ fakechroot_buf     │
 *   │ After expand        │ (garbage)        │ (garbage)           │
 *   │ read() file header  │ (garbage)        │ file header data    │
 *   │ Return for scripts  │ (unused)         │ shebang line        │
 *   │ Return for ELF      │ (unused)         │ PT_INTERP path      │
 *   └─────────────────────┴──────────────────┴─────────────────────┘
 *
 * This saves ~8KB of stack space per exec call.
 */
LOCAL exec_ctx_t exec_prepare(const char *filename)
{
    exec_ctx_t ctx = {0};
    int file, i;

    /*
     * Buffer reuse: ctx.interpPath and ctx.hashbang are unused until later.
     * We use them as temporary buffers for the expand_chroot_path macro.
     * After expansion, ctx.hashbang will be overwritten by file read().
     * ctx.interpPath remains garbage until parse_shebang() (scripts only).
     */
    char *fakechroot_abspath = ctx.interpPath;
    char *fakechroot_buf = ctx.hashbang;

    /* Expand filename path (uses fakechroot_abspath/buf as temp buffers) */
    filename = expand_chroot_path(filename, fakechroot_abspath, fakechroot_buf);
    strncpy(ctx.expandedFilename, filename, FAKECHROOT_PATH_MAX - 1);
    ctx.expandedFilename[FAKECHROOT_PATH_MAX - 1] = '\0';

    /* Check if executing dynamic linker directly */
    if (is_dynamic_linker(ctx.expandedFilename)) {
        ctx.type = EXEC_TYPE_DIRECT_LDSO;
        debug("exec: executing dynamic linker directly, no wrapping: %s", ctx.expandedFilename);
        return ctx;
    }

    /* Read file header to detect type */
    file = nextcall(open)(ctx.expandedFilename, O_RDONLY);
    if (file == -1) {
        __set_errno(ENOENT);
        return ctx;
    }

    i = read(file, ctx.hashbang, FAKECHROOT_PATH_MAX - 2);
    if (i == -1) {
        close(file);
        __set_errno(ENOENT);
        return ctx;
    }

    /* Null-terminate the buffer */
    ctx.hashbang[i] = ctx.hashbang[i + 1] = '\0';

    /* Check for hashbang */
    if (ctx.hashbang[0] == '#' && ctx.hashbang[1] == '!') {
        ctx.type = EXEC_TYPE_ELFLOADER_SCRIPT;
        close(file);
        return ctx;
    }

    /* Try to read PT_INTERP from ELF to determine execution type */
    int result = exec_read_elf_interp(ctx.hashbang, file, (unsigned char *)ctx.hashbang);

    if (result == 1) {
        /* PT_INTERP found - check if direct execution allowed */
        if (is_direct_exec_interp(ctx.hashbang)) {
            ctx.type = EXEC_TYPE_DIRECT_ELF;
            debug("exec: ELF with direct-exec interpreter: %s", ctx.hashbang);
        } else {
            ctx.type = EXEC_TYPE_ELFLOADER_ELF;
            debug("exec: ELF needs wrapper, PT_INTERP: %s", ctx.hashbang);
        }
    } else if (result == 0) {
        /* Valid ELF but no PT_INTERP = static binary, needs wrapper for sigaction setup */
        ctx.type = EXEC_TYPE_ELFLOADER_ELF;
        debug("exec: static ELF binary, using wrapper for sigaction setup");
    } else {
        /* Not ELF or read error - let kernel handle it directly */
        ctx.type = EXEC_TYPE_DIRECT_ELF;
        debug("exec: not ELF, direct execution (let kernel handle binfmt)");
    }

    close(file);
    return ctx;
}


/*
 * Build argument vector for ELF binary execution via elfloader.
 *
 * argv layout: [filename, --argv0, argv0, expanded_path, user_args...]
 * - filename is original unexpanded path (for /proc/self/cmdline → prctl)
 * - --argv0 + argv0 sets the program's argv[0] (for login shell detection)
 * - expanded_path is the actual program to execute
 *
 * Note: newargv[0] is set by caller (exec_build_argv), we start from n=1.
 */
static void exec_build_elf_argv(exec_ctx_t *ctx, char **newargv, char * const argv[])
{
    unsigned int i, n;

    /* Copy user arguments (skip original argv[0], it's passed via --argv0) */
    for (i = 1, n = EXEC_PREFIX_LEN; argv[i] != NULL; ) {
        newargv[n++] = argv[i++];
    }
    newargv[n] = NULL;

    /* Set up elfloader arguments starting from [1] - caller sets [0] */
    n = 1;
    newargv[n++] = ANDROID_ARGV0_OPT;    /* --argv0 */
    newargv[n++] = argv[0];              /* program's argv[0] */
    newargv[n] = ctx->expandedFilename;  /* program path */
}


/*
 * Parse hashbang line following Linux kernel behavior:
 * - Interpreter path (first token)
 * - Optional single argument (everything after first whitespace until newline)
 *
 * Stores expanded interpreter in ctx->interpPath.
 * Returns pointer to original interpreter in hashbang (for display/argv0).
 * Sets *shebangArg to optional argument (or NULL).
 *
 * Buffer Reuse Strategy:
 * ----------------------
 * The expand_chroot_path() macro requires two temporary buffers.
 * Instead of allocating them on stack, we reuse existing buffers:
 *
 *   fakechroot_abspath = ctx->interpPath
 *     - ctx->interpPath is our destination anyway
 *     - If expand_chroot_path puts result here, we skip the final copy
 *
 *   fakechroot_buf = *shebangArg (caller-provided)
 *     - Caller (exec_build_script_argv) passes interp_buf via shebangArg
 *     - We capture this pointer BEFORE strtok_r modifies *shebangArg
 *     - After strtok_r, *shebangArg points into ctx->hashbang
 *
 *   Timeline of shebangArg pointer:
 *   ┌────────────────────────┬─────────────────────────────────────┐
 *   │ Phase                  │ *shebangArg points to               │
 *   ├────────────────────────┼─────────────────────────────────────┤
 *   │ Entry                  │ caller's interp_buf (temp buffer)   │
 *   │ After fakechroot_buf=  │ (saved to fakechroot_buf)           │
 *   │ After strtok_r         │ rest of shebang line in ctx->hashbang│
 *   │ Return                 │ shebang arg or NULL                 │
 *   └────────────────────────┴─────────────────────────────────────┘
 *
 * This saves ~4KB of stack space.
 */
static char *parse_shebang(exec_ctx_t *ctx, char **shebangArg)
{
    /*
     * Buffer reuse for expand_chroot_path macro:
     *
     * fakechroot_abspath: Use ctx->interpPath directly since it's our
     * destination. If the macro stores the result there, we avoid a copy.
     *
     * fakechroot_buf: Use the buffer passed by caller through shebangArg.
     * IMPORTANT: We must capture *shebangArg BEFORE strtok_r modifies it!
     * The caller (exec_build_script_argv) initializes shebangArg to point
     * to interp_buf, which we borrow as our temporary buffer.
     */
    char *fakechroot_abspath = ctx->interpPath;
    char *fakechroot_buf = *shebangArg;  /* Capture before strtok_r! */

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

    /* Expand interpreter path - result may end up in fakechroot_abspath (ctx->interpPath) */
    const char *ptr = originalInterp;
    ptr = expand_chroot_path(ptr, fakechroot_abspath, fakechroot_buf);
    /* Copy if result is not already in ctx->interpPath */
    if (ptr != ctx->interpPath) {
        strncpy(ctx->interpPath, ptr, FAKECHROOT_PATH_MAX - 1);
    }
    ctx->interpPath[FAKECHROOT_PATH_MAX - 1] = '\0';

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
 * Final argv layout (wrapped execution):
 *   [displayArgv0, --argv0, displayArgv0, interpPath, shebang_arg?, script_path, user_args..., NULL]
 *
 * Final argv layout (direct execution):
 *   [displayArgv0, shebang_arg?, script_path, user_args..., NULL]
 *
 * Where:
 *   - displayArgv0 = original interpreter from shebang (for ps/top and $^X)
 *   - interpPath = ctx->interpPath = expanded interpreter path (for ld.so to load)
 *   - shebang_arg is optional (only if shebang has argument after interpreter)
 *
 * Buffer Reuse Strategy:
 * ----------------------
 * We allocate ONE local buffer (interp_buf) that serves multiple purposes:
 *
 *   1. Passed to parse_shebang() as fakechroot_buf for path expansion
 *   2. Reused to read interpreter's PT_INTERP for direct-exec check
 *
 * The shebangArg pointer serves as a "baton" to pass interp_buf to parse_shebang:
 *   - Initially: shebangArg = interp_buf (points to our temp buffer)
 *   - parse_shebang captures this, uses it as fakechroot_buf
 *   - After strtok_r: shebangArg points into ctx->hashbang (or NULL)
 *
 *   Timeline of interp_buf usage:
 *   ┌─────────────────────────┬─────────────────────────────────────────────┐
 *   │ Phase                   │ interp_buf contains                         │
 *   ├─────────────────────────┼─────────────────────────────────────────────┤
 *   │ Before parse_shebang    │ (uninitialized - used as fakechroot_buf)    │
 *   │ During parse_shebang    │ temp path data from expand_chroot_path      │
 *   │ After parse_shebang     │ (garbage from path expansion)               │
 *   │ After exec_read_elf     │ interpreter's PT_INTERP path (if ELF)       │
 *   └─────────────────────────┴─────────────────────────────────────────────┘
 *
 *   Timeline of shebangArg pointer:
 *   ┌─────────────────────────┬─────────────────────────────────────────────┐
 *   │ Phase                   │ shebangArg points to                        │
 *   ├─────────────────────────┼─────────────────────────────────────────────┤
 *   │ Before parse_shebang    │ interp_buf (our temp buffer)                │
 *   │ After parse_shebang     │ shebang arg in ctx->hashbang, or NULL       │
 *   └─────────────────────────┴─────────────────────────────────────────────┘
 *
 * This saves ~4KB of stack space by reusing one buffer for two purposes.
 */
static void exec_build_script_argv(exec_ctx_t *ctx, char **newargv, char * const argv[])
{
    unsigned int i, n;
    char *displayArgv0;
    int direct_exec = 0;

    /*
     * Single buffer serving dual purpose:
     * 1. Passed to parse_shebang as fakechroot_buf (via shebangArg pointer)
     * 2. Later reused to store interpreter's PT_INTERP for direct-exec check
     */
    char interp_buf[FAKECHROOT_PATH_MAX];
    char *shebangArg = interp_buf;  /* parse_shebang captures this for fakechroot_buf */

    /*
     * Parse shebang line and expand interpreter path:
     *   - Reads ctx->hashbang which contains "#!..." from exec_prepare()
     *   - Stores expanded interpreter path in ctx->interpPath
     *   - Returns pointer to original interpreter in ctx->hashbang (for display)
     *   - Uses interp_buf (via *shebangArg) as fakechroot_buf for path expansion
     *   - After return, shebangArg points to optional arg in ctx->hashbang (or NULL)
     */
    displayArgv0 = parse_shebang(ctx, &shebangArg);

    /*
     * Check if interpreter can be executed directly (has direct-exec PT_INTERP).
     *
     * Direct-exec interpreters are those already patched to use Android glibc
     * or nix-ld shim, so they don't need the ld.so wrapper.
     *
     * IMPORTANT: We reuse interp_buf here to store the PT_INTERP path.
     * This is SAFE because:
     *   - displayArgv0 points into ctx->hashbang (original interpreter name)
     *   - shebangArg points into ctx->hashbang (optional arg) or is NULL
     *   - Neither points to interp_buf after parse_shebang returns
     */
    int fd = nextcall(open)(ctx->interpPath, O_RDONLY);
    if (fd >= 0) {
        unsigned char header[64];
        if (read(fd, header, sizeof(header)) >= (ssize_t)sizeof(header)) {
            /* Read interpreter's PT_INTERP into interp_buf (reusing the buffer) */
            int result = exec_read_elf_interp(interp_buf, fd, header);
            if (result == 1 && is_direct_exec_interp(interp_buf)) {
                direct_exec = 1;
                debug("exec: script interpreter has direct-exec PT_INTERP: %s", interp_buf);
            }
        }
        close(fd);
    }

    /*
     * Build argument vector based on execution type.
     *
     * Direct execution (interpreter already patched):
     *   [displayArgv0, shebang_arg?, script_path, user_args..., NULL]
     *   exec_get_path() returns ctx->interpPath (actual binary to execute)
     *
     * Wrapped execution (needs ld.so --argv0):
     *   [displayArgv0, --argv0, displayArgv0, interpPath, shebang_arg?, script_path, user_args..., NULL]
     *   exec_get_path() returns ANDROID_ELFLOADER
     *
     * Note: displayArgv0 is the original interpreter name from shebang,
     * used for ps/top display and $^X in scripts (e.g., "/usr/bin/perl").
     * interpPath is the expanded path (e.g., "/nix/store/.../bin/perl").
     */
    n = 0;
    if (direct_exec) {
        /* Direct: [displayArgv0, ...] - no ld.so wrapper needed
         * Use displayArgv0 for argv[0] to match kernel behavior:
         * kernel sets interpreter's argv[0] to the shebang path (e.g., "/usr/bin/perl")
         * This ensures $^X in Perl, sys.executable in Python, etc. show expected value.
         * The actual execution path is ctx->interpPath (returned by exec_get_path). */
        newargv[n++] = displayArgv0;
        ctx->type = EXEC_TYPE_DIRECT_SCRIPT;
    } else {
        /* Wrapped: [displayArgv0, --argv0, displayArgv0, interpreter, ...] */
        newargv[n++] = displayArgv0;         /* ld.so's argv[0] for ps/top */
        newargv[n++] = ANDROID_ARGV0_OPT;    /* --argv0 option */
        newargv[n++] = displayArgv0;         /* interpreter's argv[0] for $^X */
        newargv[n++] = ctx->interpPath;      /* actual interpreter to load */
    }

    /* Common suffix for both execution types: [shebang_arg?, script, user_args...] */
    if (shebangArg) {
        newargv[n++] = shebangArg;
    }
    newargv[n++] = ctx->expandedFilename;
    for (i = 1; argv[i] != NULL; i++) {
        newargv[n++] = argv[i];
    }
    newargv[n] = NULL;
}


/*
 * Build argument vector for elfloader.
 * Dispatches to appropriate builder based on file type (already detected in exec_prepare).
 * Only called for types that need argv transformation.
 *
 * For ELF: sets newargv[0] = filename (original unexpanded path) for /proc/self/cmdline.
 * For scripts: inner function sets newargv[0] = displayArgv0 (original interpreter),
 *              matching kernel behavior where scripts show interpreter name in ps.
 */
LOCAL void exec_build_argv(exec_ctx_t *ctx, char **newargv, char * const argv[], const char *filename)
{
    switch (ctx->type) {
        case EXEC_TYPE_ELFLOADER_SCRIPT:
            /* Script: inner function sets newargv[0] = displayArgv0 (matches kernel) */
            exec_build_script_argv(ctx, newargv, argv);
            break;
        case EXEC_TYPE_ELFLOADER_ELF:
        default:
            /* ELF: set newargv[0] = original filename for /proc/self/cmdline */
            newargv[0] = (char *)filename;
            exec_build_elf_argv(ctx, newargv, argv);
            break;
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

    /* VLAs for exact-size allocation */
    char *newenvp[envc + preserve_env_list_count + 1];
    char envbuf[exec_preserve_env(envp, NULL, NULL) + 1];

    /* Build environment and prepare context */
    exec_preserve_env(envp, newenvp, envbuf);
    exec_ctx_t ctx = exec_prepare(filename);

    /* Direct execution types: use original argv, no transformation needed */
    if (ctx.type == EXEC_TYPE_DIRECT_LDSO || ctx.type == EXEC_TYPE_DIRECT_ELF) {
        debug("nextcall(execve)(\"%s\", {\"%s\", ...}, ...) [direct]",
              ctx.expandedFilename, argv[0]);
        return nextcall(execve)(ctx.expandedFilename, argv, newenvp);
    }

    /* Wrapped execution: build new argv with elfloader prefix */
    char *newargv[argc + EXEC_PREFIX_LEN + MAX_SHEBANG_ARGS + 1];
    exec_build_argv(&ctx, newargv, argv, filename);

    debug("nextcall(execve)(\"%s\", {\"%s\", \"%s\", \"%s\", \"%s\", ...}, ...)",
          exec_get_path(&ctx), newargv[0], newargv[1], newargv[2], newargv[3]);

    return nextcall(execve)(exec_get_path(&ctx), newargv, newenvp);
}
