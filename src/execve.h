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

/* Elfloader prefix length: [argv0, --argv0, argv0, program] */
#define EXEC_PREFIX_LEN 4

/* Max shebang args (Linux kernel only passes 1 optional arg after interpreter) */
#define MAX_SHEBANG_ARGS 1

/* Extra slots needed beyond argc for script argv:
 * - Replace argv[0] with prefix (4 elements) -> +3
 * - Add script path -> +1
 * - Add shebang arg (optional) -> +1
 * Total extra: 3 + 1 + 1 = 5, but we express as PREFIX_LEN + SHEBANG_ARGS + 1 */

/* Execution type determined by file header */
typedef enum {
    /* Direct execution (no ld.so wrapper needed) */
    EXEC_TYPE_DIRECT_ELF,       /* Already-patched ELF with direct-exec PT_INTERP */
    EXEC_TYPE_DIRECT_LDSO,      /* Dynamic linker (ld.so) itself */
    EXEC_TYPE_DIRECT_SCRIPT,    /* Script with direct-exec interpreter */

    /* Elfloader wrapped execution (needs ld.so wrapper) */
    EXEC_TYPE_ELFLOADER_ELF,    /* Regular ELF binary */
    EXEC_TYPE_ELFLOADER_SCRIPT, /* Script with wrapped interpreter */
} exec_type_t;

/*
 * Execution context structure - holds buffers and state for exec operations.
 * Used by both execve() and posix_spawn() to share common logic.
 */
typedef struct {
    exec_type_t type;                           /* Execution type (first for easy init) */
    char hashbang[FAKECHROOT_PATH_MAX];         /* Script: shebang line (original interp)
                                                   ELF: PT_INTERP path (for direct exec check) */
    char expandedFilename[FAKECHROOT_PATH_MAX]; /* Expanded path to execute */
    char interpPath[FAKECHROOT_PATH_MAX];       /* Script only: expanded interpreter path */
} exec_ctx_t;

/*
 * Prepare execution context: expand filename and detect file type.
 * Reads file header to determine if it's ELF, script, or other.
 *
 * @param filename  Original filename (will be expanded)
 * @return Initialized execution context with type set
 */
exec_ctx_t exec_prepare(const char *filename);

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
 * Build argument vector for elfloader.
 * Dispatches to appropriate builder based on file type (already detected in exec_prepare).
 * Only called for types that need argv transformation (ELFLOADER_*).
 *
 * For ELF binaries, sets newargv[0] = filename (original unexpanded path) so that
 * /proc/self/cmdline contains the original command for prctl(PR_SET_NAME).
 *
 * For scripts, newargv[0] = displayArgv0 (original interpreter from shebang),
 * matching kernel behavior where scripts show interpreter name in ps.
 *
 * @param ctx      Execution context (type already set by exec_prepare)
 * @param newargv  Argument array to populate
 * @param argv     Original argument vector
 * @param filename Original filename passed to execve (before path expansion)
 */
void exec_build_argv(exec_ctx_t *ctx, char **newargv, char * const argv[], const char *filename);

/*
 * Get the executable path for the final exec call.
 *
 * @param ctx  Execution context
 * @return ANDROID_ELFLOADER for wrapped execution,
 *         ctx->expandedFilename for direct ELF/ld.so,
 *         ctx->interpPath for direct script (expanded interpreter)
 */
static inline const char *exec_get_path(exec_ctx_t *ctx)
{
    switch (ctx->type) {
        case EXEC_TYPE_DIRECT_LDSO:
        case EXEC_TYPE_DIRECT_ELF:
            return ctx->expandedFilename;
        case EXEC_TYPE_DIRECT_SCRIPT:
            return ctx->interpPath;
        default:
            return ANDROID_ELFLOADER;
    }
}

#endif /* EXECVE_H */
