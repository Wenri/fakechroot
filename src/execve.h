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
    EXEC_TYPE_ELF,      /* Regular ELF binary */
    EXEC_TYPE_SCRIPT,   /* Hashbang script (#!) */
    EXEC_TYPE_LDSO      /* Dynamic linker (ld.so) - no wrapping needed */
} exec_type_t;

/*
 * Execution context structure - holds buffers and state for exec operations.
 * Used by both execve() and posix_spawn() to share common logic.
 */
typedef struct {
    char hashbang[FAKECHROOT_PATH_MAX];         /* File header / hashbang content */
    char expandedFilename[FAKECHROOT_PATH_MAX]; /* Expanded path to execute */
    char interpreterPath[FAKECHROOT_PATH_MAX];  /* Expanded interpreter (scripts only) */
    char argv0[FAKECHROOT_PATH_MAX];            /* argv[0] for --argv0 (original or shebang) */

    exec_type_t type;   /* Execution type (ELF, script, or ld.so) */
    char *shebangArg;   /* Optional shebang arg (points into hashbang buffer, may be NULL) */
} exec_ctx_t;

/*
 * Prepare execution context: initialize and expand filename.
 *
 * @param filename  Original filename (will be expanded)
 * @param argv      Original argument vector (argv[0] is preserved for --argv0)
 * @return Initialized execution context
 */
exec_ctx_t exec_prepare(const char *filename, char * const argv[]);

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
 * Read file header and build argument vector for elfloader.
 * Dispatches to appropriate builder based on detected file type (ELF or script).
 *
 * @param ctx      Execution context
 * @param newargv  Argument array to populate
 * @param argv     Original argument vector
 * @return 0 on success, -1 on error (errno set)
 */
int exec_build_argv(exec_ctx_t *ctx, char **newargv, char * const argv[]);

/*
 * Get the executable path for the final exec call.
 *
 * @param ctx  Execution context
 * @return ANDROID_ELFLOADER for wrapped execution, or ctx->expandedFilename for direct ld.so
 */
const char *exec_get_path(exec_ctx_t *ctx);

#endif /* EXECVE_H */
