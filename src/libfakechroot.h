/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2010-2015, 2019 Piotr Roszatycki <dexter@debian.org>

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


#ifndef __LIBFAKECHROOT_H
#define __LIBFAKECHROOT_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "rel2abs.h"
#include "rel2absat.h"


#define debug fakechroot_debug


#ifdef HAVE___ATTRIBUTE__VISIBILITY
# define LOCAL __attribute__((visibility("hidden")))
# define PUBLIC __attribute__((visibility("default")))
#else
# define LOCAL
# define PUBLIC
#endif

#ifdef HAVE___ATTRIBUTE__CONSTRUCTOR
# define CONSTRUCTOR __attribute__((constructor))
#else
# define CONSTRUCTOR
#endif

#ifdef HAVE___ATTRIBUTE__SECTION_DATA_FAKECHROOT
# define SECTION_DATA_FAKECHROOT __attribute__((section("data.fakechroot")))
#else
# define SECTION_DATA_FAKECHROOT
#endif

#if defined(PATH_MAX)
# define FAKECHROOT_PATH_MAX PATH_MAX
#elif defined(_POSIX_PATH_MAX)
# define FAKECHROOT_PATH_MAX _POSIX_PATH_MAX
#elif defined(MAXPATHLEN)
# define FAKECHROOT_PATH_MAX MAXPATHLEN
#else
# define FAKECHROOT_PATH_MAX 2048
#endif

#ifndef UNIX_PATH_MAX
# define UNIX_PATH_MAX 108
#endif


#ifdef AF_UNIX
# ifndef SUN_LEN
#  define SUN_LEN(su) (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
# endif
#endif

#ifndef __set_errno
# define __set_errno(e) (errno = (e))
#endif

#ifndef HAVE_VFORK
# define vfork fork
#endif

/* Forward declarations needed by inline functions below */
int fakechroot_localdir (const char *);
#ifndef snprintf
int snprintf(char *, size_t, const char *, ...);
#endif


static inline void narrow_chroot_path(char *path)
{
    if (path == NULL || *path == '\0') {
        return;
    }
    if (ANDROID_BASE == NULL) {
        return;
    }

    char *fakechroot_ptr = strstr(path, ANDROID_BASE);
    if (fakechroot_ptr != path) {
        return;
    }

    const size_t fakechroot_base_len = strlen(ANDROID_BASE);
    const size_t path_len = strlen(path);

    if (path_len == fakechroot_base_len) {
        path[0] = '/';
        path[1] = '\0';
    }
    else if (path[fakechroot_base_len] == '/') {
        memmove(path, path + fakechroot_base_len, 1 + path_len - fakechroot_base_len);
    }
}

static inline const char *expand_chroot_rel_path(const char *path, char *buf)
{
    if (fakechroot_localdir(path)) {
        return path;
    }
    if (path == NULL || *path != '/') {
        return path;
    }
    if (ANDROID_BASE == NULL) {
        return path;
    }
    snprintf(buf, FAKECHROOT_PATH_MAX, "%s%s", ANDROID_BASE, path);
    return buf;
}

static inline const char *expand_chroot_path(const char *path, char *abspath_buf, char *buf)
{
    if (fakechroot_localdir(path)) {
        return path;
    }
    if (path == NULL) {
        return path;
    }
    rel2abs(path, abspath_buf);
    return expand_chroot_rel_path(abspath_buf, buf);
}

static inline const char *expand_chroot_path_at(int dirfd, const char *path, char *abspath_buf, char *buf)
{
    if (fakechroot_localdir(path)) {
        return path;
    }
    if (path == NULL) {
        return path;
    }
    rel2absat(dirfd, path, abspath_buf);
    return expand_chroot_rel_path(abspath_buf, buf);
}


#define wrapper_decl_proto(function) \
    extern LOCAL fakechroot_##function##_fn_t fakechroot_##function##_nextfunc SECTION_DATA_FAKECHROOT

/*
 * Lazy-load stub using GCC's __builtin_apply to forward all arguments.
 * Most args are in registers anyway (6 on x86-64, 8 on aarch64).
 */
#define wrapper_stub(function, return_type, arguments) \
    static return_type fakechroot_##function##_stub arguments { \
        fakechroot_##function##_nextfunc = \
            (fakechroot_##function##_fn_t)dlsym(RTLD_NEXT, #function); \
        void *args = __builtin_apply_args(); \
        void *ret = __builtin_apply( \
            (void(*)())fakechroot_##function##_nextfunc, \
            args, 0); \
        __builtin_return(ret); \
    }

#define wrapper_decl(function, return_type, arguments) \
    wrapper_stub(function, return_type, arguments); \
    LOCAL fakechroot_##function##_fn_t fakechroot_##function##_nextfunc SECTION_DATA_FAKECHROOT = \
        fakechroot_##function##_stub

#define wrapper_fn_t(function, return_type, arguments) \
    typedef return_type (*fakechroot_##function##_fn_t) arguments

#define wrapper_proto(function, return_type, arguments) \
    extern return_type function arguments; \
    wrapper_fn_t(function, return_type, arguments); \
    wrapper_decl_proto(function)

#if __USE_FORTIFY_LEVEL > 0 && defined __extern_always_inline && defined __va_arg_pack_len
# define wrapper_fn_name(function) __##function##_alias
# define wrapper_proto_alias(function, return_type, arguments) \
    extern return_type __REDIRECT (wrapper_fn_name(function), arguments, function); \
    wrapper_fn_t(function, return_type, arguments); \
    wrapper_decl_proto(function)
#else
# define wrapper_fn_name(function) function
# define wrapper_proto_alias(function, return_type, arguments) \
    wrapper_proto(function, return_type, arguments)
#endif

#define wrapper(function, return_type, arguments) \
    wrapper_proto(function, return_type, arguments); \
    wrapper_decl(function, return_type, arguments); \
    PUBLIC return_type function arguments

#define wrapper_alias(function, return_type, arguments) \
    wrapper_proto_alias(function, return_type, arguments); \
    wrapper_decl(function, return_type, arguments); \
    PUBLIC return_type wrapper_fn_name(function) arguments

#define nextcall(function) (fakechroot_##function##_nextfunc)


#ifdef __GNUC__
# if __GNUC__ >= 6
#  pragma GCC diagnostic ignored "-Wnonnull-compare"
# endif
#endif

#ifdef __clang__
# if __clang_major__ >= 4 || __clang_major__ == 3 && __clang_minor__ >= 6
#  pragma clang diagnostic ignored "-Wpointer-bool-conversion"
# endif
#endif

#ifndef _STAT_VER
 #if defined (__aarch64__)
  #define _STAT_VER 0
 #elif defined (__powerpc__) && __WORDSIZE == 64
  #define _STAT_VER 1
 #elif defined (__riscv) && __riscv_xlen==64
  #define _STAT_VER 0
 #elif defined (__s390x__)
  #define _STAT_VER 1
 #elif defined (__x86_64__)
  #define _STAT_VER 1
 #else
  #define _STAT_VER 3
 #endif
#endif

extern const char * const preserve_env_list[];
extern const size_t preserve_env_list_count;

int fakechroot_debug (const char *, ...);
int fakechroot_try_cmd_subst (char *, const char *, char *);

#endif
