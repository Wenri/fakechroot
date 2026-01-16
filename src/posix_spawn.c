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

#include <errno.h>
#include <spawn.h>
#include "libfakechroot.h"
#include "execve.h"


/*
 * posix_spawn wrapper - uses shared exec_* functions with VLAs
 */
wrapper(posix_spawn, int, (pid_t* pid, const char * filename,
        const posix_spawn_file_actions_t* file_actions,
        const posix_spawnattr_t* attrp, char* const argv[],
        char * const envp []))
{
    int argc, envc;
    char **p;

    debug("posix_spawn(\"%s\", {\"%s\", ...}, {\"%s\", ...})", filename, argv[0], envp ? envp[0] : "(null)");

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
        return nextcall(posix_spawn)(pid, ctx.expandedFilename, file_actions, attrp, argv, newenvp);
    }

    if (exec_read_header(&ctx) != 0) {
        return errno;
    }

    if (ctx.type == EXEC_TYPE_SCRIPT) {
        exec_build_script_argv(&ctx, newargv, argv);
    } else {
        exec_build_elf_argv(&ctx, newargv, argv);
    }

    debug("nextcall(posix_spawn)(\"%s\", {\"%s\", \"%s\", \"%s\", \"%s\", ...}, ...)",
          exec_get_path(&ctx), newargv[0], newargv[1], newargv[2], newargv[3]);

    return nextcall(posix_spawn)(pid, exec_get_path(&ctx), file_actions, attrp,
                                 newargv, newenvp);
}

#endif
