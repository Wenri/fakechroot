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

#ifndef EXECVE_H
#define EXECVE_H

#include "libfakechroot.h"

/* Extra argv slots needed for elfloader: argv0 + --argv0 + argv0 + filename */
#define EXEC_EXTRA_ARGV 4

/*
 * Execution context structure - holds buffers and state for exec operations.
 * Used by both execve() and posix_spawn() to share common logic.
 *
 * The newargv/newenvp arrays are VLAs allocated by the caller and passed
 * as pointers here. This allows exact-size allocation on the stack.
 */
typedef struct {
    /* Buffers required by expand_chroot_path macro */
    char fakechroot_abspath[FAKECHROOT_PATH_MAX];
    char fakechroot_buf[FAKECHROOT_PATH_MAX];

    /* Execution state */
    char hashbang[FAKECHROOT_PATH_MAX];       /* File header / hashbang content */
    char tmp[FAKECHROOT_PATH_MAX];            /* Expanded filename */
    char newfilename[FAKECHROOT_PATH_MAX];    /* Resolved interpreter path (for shebang) */
    char argv0[FAKECHROOT_PATH_MAX];          /* Original argv[0] (for --argv0) */
    char shebang_argv0[FAKECHROOT_PATH_MAX];  /* Shebang interpreter path for argv[0] */

    /* Pointers to VLAs allocated by caller */
    char **newenvp;
    const char **newargv;

    /* Execution flags */
    int is_script;      /* 1 if hashbang script, 0 if ELF binary */
    int is_ld_so;       /* 1 if executing dynamic linker directly */

    /* Hashbang parsing state */
    int hashbang_len;   /* Length of hashbang content read */
} exec_ctx_t;

/*
 * Prepare execution context: initialize, copy environment, expand filename.
 *
 * @param ctx       Context to initialize
 * @param newargv   VLA for arguments (allocated by caller)
 * @param newenvp   VLA for environment (allocated by caller)
 * @param envbuf    VLA buffer for preserved env strings (allocated by caller)
 * @param filename  Original filename (will be expanded)
 * @param argv      Original argument vector (argv[0] is preserved)
 * @param envp      Original environment
 * @return 0 on success, -1 on error (errno set)
 */
int exec_prepare(exec_ctx_t *ctx, const char **newargv, char **newenvp,
                 char *envbuf, const char *filename,
                 char * const argv[], char * const envp[]);

/*
 * Build environment array with preserved variables.
 * If newenvp/envbuf are NULL, just calculate required buffer size.
 * If newenvp/envbuf are non-NULL, build complete environment array:
 *   [preserved vars not in envp] + [original envp] + [NULL]
 *
 * @param envp       Original environment
 * @param newenvp    Environment array to populate (NULL for size calc only)
 * @param envbuf     Buffer for preserved env strings (NULL for size calc only)
 * @return Buffer size needed/used (may be 0, caller should use size+1 for VLA)
 */
size_t exec_preserve_env(char * const envp[], char **newenvp, char *envbuf);

/*
 * Read file header to detect hashbang scripts vs ELF binaries.
 * Sets ctx->is_script based on "#!" detection.
 *
 * @param ctx  Execution context (ctx->tmp must contain expanded filename)
 * @return 0 on success, -1 on error (errno set)
 */
int exec_read_header(exec_ctx_t *ctx);

/*
 * Build argument vector for ELF binary execution via elfloader.
 * Result is stored in ctx->newargv.
 *
 * @param ctx   Execution context
 * @param argv  Original argument vector
 */
void exec_build_elf_argv(exec_ctx_t *ctx, char * const argv[]);

/*
 * Parse hashbang line and build argument vector for script execution.
 * Result is stored in ctx->newargv.
 *
 * @param ctx   Execution context
 * @param argv  Original argument vector
 */
void exec_build_script_argv(exec_ctx_t *ctx, char * const argv[]);

/*
 * Get the executable path for the final exec call.
 *
 * @param ctx  Execution context
 * @return ANDROID_ELFLOADER for wrapped execution, or ctx->tmp for direct ld.so
 */
const char *exec_get_path(exec_ctx_t *ctx);

#endif /* EXECVE_H */
