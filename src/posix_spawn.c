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
 * posix_spawn wrapper - uses shared exec_* functions from execve.c
 */
wrapper(posix_spawn, int, (pid_t* pid, const char * filename,
        const posix_spawn_file_actions_t* file_actions,
        const posix_spawnattr_t* attrp, char* const argv[],
        char * const envp []))
{
    exec_ctx_t ctx;

    debug("posix_spawn(\"%s\", {\"%s\", ...}, {\"%s\", ...})", filename, argv[0], envp ? envp[0] : "(null)");

    if (exec_prepare(&ctx, filename, argv, envp) != 0) {
        return errno;
    }

    /* If executing ld.so directly, don't wrap it */
    if (ctx.is_ld_so) {
        return nextcall(posix_spawn)(pid, ctx.tmp, file_actions, attrp, argv, ctx.newenvp);
    }

    if (exec_read_header(&ctx) != 0) {
        return errno;
    }

    if (ctx.is_script) {
        exec_build_script_argv(&ctx, argv);
    } else {
        exec_build_elf_argv(&ctx, argv);
    }

    debug("nextcall(posix_spawn)(\"%s\", {\"%s\", \"%s\", \"%s\", \"%s\", ...}, ...)",
          exec_get_path(&ctx), ctx.newargv[0], ctx.newargv[1], ctx.newargv[2], ctx.newargv[3]);

    return nextcall(posix_spawn)(pid, exec_get_path(&ctx), file_actions, attrp,
                                 (char * const *)ctx.newargv, ctx.newenvp);
}

#endif
