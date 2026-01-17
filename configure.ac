AC_PREREQ(2.64)
AC_INIT([fakechroot], [2.20.2], [dexter@debian.org], [fakechroot], [https://github.com/dex4er/fakechroot])

AC_CONFIG_SRCDIR([src/libfakechroot.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADER([config.h])

# Enable GNU extensions and large file support (needed for symver declarations)
AC_DEFINE([_GNU_SOURCE], [1], [Enable GNU extensions])
AC_DEFINE([_LARGEFILE64_SOURCE], [1], [Enable large file support])

AM_INIT_AUTOMAKE([1.10 foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_MAINTAINER_MODE

AC_ARG_VAR([V], [Verbose output])
AC_ARG_VAR([EXTRA_CFLAGS], [Extra C compiler flags])
AC_ARG_VAR([EXTRA_LDFLAGS], [Extra linker flags])

# C toolchain
AM_PROG_AR
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LN_S
AM_PROG_LIBTOOL
AM_PROG_NM
LT_INIT

AC_CANONICAL_HOST
AC_CANONICAL_BUILD
AC_LANG([C])

# --disable-static by default
AC_DISABLE_STATIC

# --with-libpath
AC_ARG_WITH([libpath],
    [AS_HELP_STRING([--with-libpath@<:@=LIBPATH@:>@],
        [path list where library might be located @<:@default=$pkglibdir@:>@])],
    [with_libpath=$withval],
    [with_libpath=$libdir/$PACKAGE_NAME])
AS_IF([test "x$with_libpath" = x],
    [AC_MSG_FAILURE([invalid libpath specified])])
AC_SUBST(libpath, $with_libpath)

# Checks for programs.
AC_PATH_PROG([CHROOT], [chroot], [/usr/sbin/chroot], [/usr/sbin:/sbin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:$PATH])
AC_PATH_PROG([DEBOOTSTRAP], [debootstrap], [/usr/sbin/debootstrap], [/usr/sbin:/sbin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:$PATH])
AC_PATH_PROG([DEVFS], [devfs], [/sbin/devfs], [/sbin:/usr/sbin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:$PATH])
AC_PATH_PROG([ECHO], [echo], [/bin/echo], [/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([ENV], [env], [/usr/bin/env], [/usr/bin:/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([FAKEROOT], [fakeroot], [/usr/bin/fakeroot], [/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([INSSERV], [insserv], [/sbin/insserv], [/sbin:/usr/sbin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:$PATH])
AC_PATH_PROG([ISCHROOT], [ischroot], [/usr/bin/ischroot], [/usr/bin:/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([LDCONFIG], [ldconfig], [/sbin/chroot], [/sbin:/usr/sbin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:$PATH])
AC_PATH_PROG([LDD], [ldd], [/usr/bin/ldd], [/usr/bin:/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([LS], [ls], [/bin/ls], [/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([MKFIFO], [mkfifo], [/usr/bin/mkfifo], [/usr/bin:/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([PERL], [perl], [/usr/bin/perl], [/usr/bin:/bin:/usr/sbin:/sbin:/usr/bin/core_perl:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([POD2MAN], [pod2man], [], [/usr/bin:/bin:/usr/sbin:/sbin:/usr/bin/core_perl:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([PROVE], [prove], [], [/usr/bin:/bin:/usr/sbin:/sbin:/usr/bin/core_perl:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([SEQ], [seq gseq], [], [/usr/bin:/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([SH], [sh], [/bin/sh], [/bin:/usr/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([SHELL], [bash dash sh], [/bin/sh], [/bin:/usr/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:$PATH])
AC_PATH_PROG([SYSTEMCTL], [systemctl], [/sbin/systemctl], [/sbin:/usr/sbin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:$PATH])

# Additional C macros
AC_DEFINE([FAKECHROOT], [PACKAGE_VERSION], [FAKECHROOT])
AC_DEFINE_UNQUOTED([BIN_LS], ["$ac_cv_path_LS"], [BIN_LS])
AC_DEFINE_UNQUOTED([BIN_SH], ["$ac_cv_path_SH"], [BIN_SH])

# Checks for compiler features
ACX_CHECK_C_ALIGNOF
ACX_CHECK_C_ATTRIBUTE([constructor])
ACX_CHECK_C_ATTRIBUTE_SECTION([data.fakechroot])
ACX_CHECK_C_ATTRIBUTE_VISIBILITY

# Checks for libraries.
AC_CHECK_LIB([dl], [dlsym])

AH_TEMPLATE([NEW_GLIBC], [glibc >= 2.33])
AC_MSG_CHECKING([for glibc 2.33+])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
       #include <sys/stat.h>
  ]], [[
#ifdef __GLIBC__
#if !__GLIBC_PREREQ(2,33)
#error glibc<2.33
#endif
#else
#error not glibc
#endif
  ]])],[
   AC_DEFINE(NEW_GLIBC,1)
   AC_MSG_RESULT([yes])
  ],[
   AC_DEFINE(NEW_GLIBC,0)
   AC_MSG_RESULT([no])
  ])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS(m4_normalize([
    alloca.h
    dirent.h
    dlfcn.h
    errno.h
    fcntl.h
    ftw.h
    glob.h
    libintl.h
    link.h
    pwd.h
    shadow.h
    spawn.h
    signal.h
    stdarg.h
    stdint.h
    stdio.h
    stdlib.h
    string.h
    sys/inotify.h
    sys/mount.h
    sys/param.h
    sys/socket.h
    sys/stat.h
    sys/statfs.h
    sys/statvfs.h
    sys/syscall.h
    sys/times.h
    sys/types.h
    sys/un.h
    sys/vfs.h
    sys/wait.h
    sys/xattr.h
    unistd.h
    utime.h
]))

AC_CHECK_HEADERS([fts.h], [], [], [
#define _BSD_SOURCE
#define _DEFAULT_SOURCE
])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for additional typedefs.
AC_CHECK_MEMBERS([struct sockaddr_un.sun_len],,, ACX_INCLUDES_HEADERS([sys/un.h]))
AC_CHECK_MEMBERS([struct _ftsent.fts_fts],,, ACX_INCLUDES_HEADERS([sys/types.h sys/stat.h fts.h]))
ACX_CHECK_FTS_NAME_TYPE

# Checks for library functions.
AC_CHECK_FUNCS(m4_normalize([
    __chk_fail
    __fxstat64
    __fxstatat
    __fxstatat64
    __getcwd_chk
    __getwd_chk
    __lxstat
    __lxstat64
    __open
    __open_2
    __open64
    __open64_2
    __openat_2
    __openat64_2
    __opendir2
    __realpath_chk
    __readlink_chk
    __readlinkat_chk
    __statfs
    __xmknod
    __xmknodat
    __xstat
    __xstat64
    _xftw
    _xftw64
    access
    acct
    audit_log_acct_message
    bind
    bindtextdomain
    canonicalize_file_name
    chdir
    chmod
    chown
    chroot
    clearenv
    connect
    creat
    creat64
    dl_iterate_phdr
    dladdr
    dlmopen
    dlopen
    eaccess
    euidaccess
    execl
    execle
    execlp
    execv
    execve
    execvp
    faccessat
    fchdir
    fchmodat
    fchownat
    fopen
    fopen64
    freopen
    freopen64
    fstat
    fstat64
    fstatat
    fstatat64
    fts_children
    fts_open
    fts_read
    fts64_open
    ftw
    ftw64
    futimesat
    get_current_dir_name
    getcwd
    getpeername
    getsockname
    getwd
    getxattr
    glob
    glob64
    glob_pattern_p
    inotify_add_watch
    lchmod
    lchown
    lckpwdf
    lgetxattr
    link
    linkat
    listxattr
    llistxattr
    lremovexattr
    lsetxattr
    lstat
    lstat64
    lutimes
    mempcpy
    mkdir
    mkdirat
    mkdtemp
    mkfifo
    mkfifoat
    mknod
    mknodat
    mkostemp
    mkostemp64
    mkostemps
    mkostemps64
    mkstemp
    mkstemp64
    mkstemps
    mkstemps64
    mktemp
    nftw
    nftw64
    open
    open64
    openat
    openat64
    opendir
    pathconf
    popen
    posix_spawn
    posix_spawnp
    rawmemchr
    readlink
    readlinkat
    realpath
    remove
    removexattr
    rename
    renameat
    renameat2
    revoke
    rmdir
    scandir
    scandir64
    setenv
    setxattr
    stat
    stat64
    statfs
    statfs64
    statvfs
    statvfs64
    statx
    stpcpy
    strchrnul
    strlcpy
    symlink
    symlinkat
    system
    tempnam
    tmpnam
    truncate
    truncate64
    unlink
    unlinkat
    unsetenv
    ulckpwdf
    utime
    utimensat
    utimes
    vfork
]))
AC_FUNC_ALLOCA
ASX_NO_CROSS_COMPILING([AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK])

# Check for internal dependencies
ACX_CHECK_OPENDIR_CALLS_INTERNALLY([__open])
ACX_CHECK_OPENDIR_CALLS_INTERNALLY([__opendir2])

# Check return type and arguments types for functions
m4_foreach_w([function], [bind connect],
    [ACX_CHECK_FUNC_ARGTYPES(function,
        [
#define _GNU_SOURCE
        ], [sys/types.h sys/socket.h],
        [[int], [int _], [const struct sockaddr *_], [socklen_t _]],
        [[int]],
        [[int _]],
        [[__CONST_SOCKADDR_ARG _], [const struct sockaddr *_]],
        [[socklen_t _]])])

m4_foreach_w([function], [getpeername getsockname],
    [ACX_CHECK_FUNC_ARGTYPES(function,
        [
#define _GNU_SOURCE
        ], [sys/types.h sys/socket.h],
        [[int], [int _], [struct sockaddr *_], [socklen_t _]],
        [[int]],
        [[int _]],
        [[__SOCKADDR_ARG _], [struct sockaddr *_]],
        [[socklen_t *__restrict _], [socket_t *_]])])

ACX_CHECK_FUNC_ARGTYPES([fts_open],
    [], [sys/types.h sys/stat.h fts.h],
    [[FTSOBJ *], [char * const *_], [int], [int (*_)(const FTSENTRY **, const FTSENTRY **)]],
    [[FTSOBJ *]],
    [[char * const *_]],
    [[int _]],
    [[int (*_)(const FTSENTRY * const *, const FTSENTRY * const *)], [int (*_)(const FTSENTRY **, const FTSENTRY **)]])

ACX_CHECK_FUNC_ARGTYPES([fts64_open],
    [], [sys/types.h sys/stat.h fts.h],
    [[FTSOBJ *], [char * const *_], [int], [int (*_)(const FTSENTRY **, const FTSENTRY **)]],
    [[FTSOBJ *]],
    [[char * const *_]],
    [[int _]],
    [[int (*_)(const FTSENTRY * const *, const FTSENTRY * const *)], [int (*_)(const FTSENTRY **, const FTSENTRY **)]])

ACX_CHECK_FUNC_ARGTYPES([readlink],
    [
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
    ], [unistd.h],
    [[ssize_t], [const char *_], [char *_], [size_t _]],
    [[ssize_t], [int]],
    [[const char *_]],
    [[char *_]],
    [[size_t _], [int _]])

ACX_CHECK_FUNC_ARGTYPES([scandir],
    [
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
    ], [dirent.h],
    [[int], [const char *_], [struct dirent ***_], [int(*_)(const struct dirent *)], [int(*_)(const void *,const void *)]],
    [[int]],
    [[const char *_]],
    [[struct dirent ***_]],
    [[int(*_)(const struct dirent *)], [int(*_)(struct dirent *)]],
    [[int(*_)(const struct dirent **, const struct dirent **)], [int(*_)(const void *,const void *)]])

ACX_CHECK_FUNC_ARGTYPES([scandir64],
    [
#define _BSD_SOURCE
#define _GNU_SOURCE 1
#define _DEFAULT_SOURCE 1
    ], [dirent.h],
    [[int], [const char *_], [struct dirent64 ***_], [int(*_)(const struct dirent64 *)], [int(*_)(const void *,const void *)]],
    [[int]],
    [[const char *_]],
    [[struct dirent64 ***_]],
    [[int(*_)(const struct dirent64 *)], [int(*_)(struct dirent64 *)]],
    [[int(*_)(const struct dirent64 **, const struct dirent64 **)], [int(*_)(const void *,const void *)]])

ACX_CHECK_FUNC_ARGTYPES([utimes],
    [], [sys/time.h],
    [[int], [const char *_], [const struct timeval _@<:@2@:>@]],
    [[int]],
    [[const char *_]],
    [[const struct timeval _@<:@2@:>@], [struct timeval _@<:@2@:>@]])

# Android-specific configuration (replaces android-config.h)
AC_ARG_VAR([ANDROID_ELFLOADER], [Path to Android glibc's ld.so dynamic linker])
AC_ARG_VAR([ANDROID_BASE], [Installation prefix for Android (e.g., /data/data/.../usr)])
AC_ARG_VAR([ANDROID_EXCLUDE_PATH], [Colon-separated paths excluded from chroot translation])

if test -n "$ANDROID_ELFLOADER"; then
    AC_DEFINE_UNQUOTED([ANDROID_ELFLOADER], ["$ANDROID_ELFLOADER"],
        [Path to Android glibc's dynamic linker])
fi

if test -n "$ANDROID_BASE"; then
    AC_DEFINE_UNQUOTED([ANDROID_BASE], ["$ANDROID_BASE"],
        [Installation prefix for Android])
fi

if test -n "$ANDROID_EXCLUDE_PATH"; then
    AC_DEFINE_UNQUOTED([ANDROID_EXCLUDE_PATH], ["$ANDROID_EXCLUDE_PATH"],
        [Paths excluded from chroot translation])
fi

AC_DEFINE([ANDROID_ARGV0_OPT], ["--argv0"], [Option for argv0 override in ld.so])

# Glibc symbol version detection and declaration generation
ACX_GLIBC_SYMVER_INIT

# Detect versions and accumulate declarations for all wrapped functions
# Format: ACX_GLIBC_SYMVER([function], [return_type], [(args)])

dnl Internal glibc functions (__ prefix)
ACX_GLIBC_SYMVER([__fxstatat], [int], [(int ver, int dirfd, const char *pathname, struct stat *buf, int flags)])
ACX_GLIBC_SYMVER([__fxstatat64], [int], [(int ver, int dirfd, const char *pathname, struct stat64 *buf, int flags)])
ACX_GLIBC_SYMVER([__getcwd_chk], [char *], [(char *buf, size_t size, size_t buflen)])
ACX_GLIBC_SYMVER([__getwd_chk], [char *], [(char *buf, size_t buflen)])
ACX_GLIBC_SYMVER([__lxstat], [int], [(int ver, const char *filename, struct stat *buf)])
ACX_GLIBC_SYMVER([__lxstat64], [int], [(int ver, const char *filename, struct stat64 *buf)])
ACX_GLIBC_SYMVER([__open], [int], [(const char *pathname, int flags, ...)])
ACX_GLIBC_SYMVER([__open64], [int], [(const char *pathname, int flags, ...)])
ACX_GLIBC_SYMVER([__open64_2], [int], [(const char *pathname, int flags)])
ACX_GLIBC_SYMVER([__open_2], [int], [(const char *pathname, int flags)])
ACX_GLIBC_SYMVER([__openat64_2], [int], [(int dirfd, const char *pathname, int flags)])
ACX_GLIBC_SYMVER([__openat_2], [int], [(int dirfd, const char *pathname, int flags)])
ACX_GLIBC_SYMVER([__readlink_chk], [ssize_t], [(const char *path, char *buf, size_t bufsiz, size_t buflen)])
ACX_GLIBC_SYMVER([__readlinkat_chk], [ssize_t], [(int dirfd, const char *path, char *buf, size_t bufsiz, size_t buflen)])
ACX_GLIBC_SYMVER([__realpath_chk], [char *], [(const char *path, char *resolved, size_t resolvedlen)])
ACX_GLIBC_SYMVER([__statfs], [int], [(const char *path, struct statfs *buf)])
ACX_GLIBC_SYMVER([__xmknod], [int], [(int ver, const char *path, mode_t mode, dev_t *dev)])
ACX_GLIBC_SYMVER([__xmknodat], [int], [(int ver, int dirfd, const char *path, mode_t mode, dev_t *dev)])
ACX_GLIBC_SYMVER([__xstat], [int], [(int ver, const char *filename, struct stat *buf)])
ACX_GLIBC_SYMVER([__xstat64], [int], [(int ver, const char *filename, struct stat64 *buf)])

dnl File operations
ACX_GLIBC_SYMVER([open], [int], [(const char *pathname, int flags, ...)])
ACX_GLIBC_SYMVER([open64], [int], [(const char *pathname, int flags, ...)])
ACX_GLIBC_SYMVER([openat], [int], [(int dirfd, const char *pathname, int flags, ...)])
ACX_GLIBC_SYMVER([openat64], [int], [(int dirfd, const char *pathname, int flags, ...)])
ACX_GLIBC_SYMVER([creat], [int], [(const char *pathname, mode_t mode)])
ACX_GLIBC_SYMVER([creat64], [int], [(const char *pathname, mode_t mode)])
ACX_GLIBC_SYMVER([fopen], [FILE *], [(const char *path, const char *mode)])
ACX_GLIBC_SYMVER([fopen64], [FILE *], [(const char *path, const char *mode)])
ACX_GLIBC_SYMVER([freopen], [FILE *], [(const char *path, const char *mode, FILE *stream)])
ACX_GLIBC_SYMVER([freopen64], [FILE *], [(const char *path, const char *mode, FILE *stream)])
ACX_GLIBC_SYMVER([opendir], [DIR *], [(const char *name)])

dnl Stat operations
ACX_GLIBC_SYMVER([stat], [int], [(const char *pathname, struct stat *buf)])
ACX_GLIBC_SYMVER([stat64], [int], [(const char *pathname, struct stat64 *buf)])
ACX_GLIBC_SYMVER([lstat], [int], [(const char *pathname, struct stat *buf)])
ACX_GLIBC_SYMVER([lstat64], [int], [(const char *pathname, struct stat64 *buf)])
ACX_GLIBC_SYMVER([fstatat], [int], [(int dirfd, const char *pathname, struct stat *buf, int flags)])
ACX_GLIBC_SYMVER([fstatat64], [int], [(int dirfd, const char *pathname, struct stat64 *buf, int flags)])
ACX_GLIBC_SYMVER([statx], [int], [(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf)])
ACX_GLIBC_SYMVER([statfs], [int], [(const char *path, struct statfs *buf)])
ACX_GLIBC_SYMVER([statfs64], [int], [(const char *path, struct statfs64 *buf)])
ACX_GLIBC_SYMVER([statvfs], [int], [(const char *path, struct statvfs *buf)])
ACX_GLIBC_SYMVER([statvfs64], [int], [(const char *path, struct statvfs64 *buf)])

dnl Link operations
ACX_GLIBC_SYMVER([readlink], [ssize_t], [(const char *pathname, char *buf, size_t bufsiz)])
ACX_GLIBC_SYMVER([readlinkat], [ssize_t], [(int dirfd, const char *pathname, char *buf, size_t bufsiz)])
ACX_GLIBC_SYMVER([symlink], [int], [(const char *oldpath, const char *newpath)])
ACX_GLIBC_SYMVER([symlinkat], [int], [(const char *oldpath, int newdirfd, const char *newpath)])
ACX_GLIBC_SYMVER([link], [int], [(const char *oldpath, const char *newpath)])
ACX_GLIBC_SYMVER([linkat], [int], [(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)])
ACX_GLIBC_SYMVER([unlink], [int], [(const char *pathname)])
ACX_GLIBC_SYMVER([unlinkat], [int], [(int dirfd, const char *pathname, int flags)])

dnl Directory operations
ACX_GLIBC_SYMVER([chdir], [int], [(const char *path)])
ACX_GLIBC_SYMVER([getcwd], [char *], [(char *buf, size_t size)])
ACX_GLIBC_SYMVER([getwd], [char *], [(char *buf)])
ACX_GLIBC_SYMVER([get_current_dir_name], [char *], [(void)])
ACX_GLIBC_SYMVER([mkdir], [int], [(const char *pathname, mode_t mode)])
ACX_GLIBC_SYMVER([mkdirat], [int], [(int dirfd, const char *pathname, mode_t mode)])
ACX_GLIBC_SYMVER([rmdir], [int], [(const char *pathname)])
ACX_GLIBC_SYMVER([chroot], [int], [(const char *path)])

dnl Permission operations
ACX_GLIBC_SYMVER([access], [int], [(const char *pathname, int mode)])
ACX_GLIBC_SYMVER([eaccess], [int], [(const char *pathname, int mode)])
ACX_GLIBC_SYMVER([euidaccess], [int], [(const char *pathname, int mode)])
ACX_GLIBC_SYMVER([faccessat], [int], [(int dirfd, const char *pathname, int mode, int flags)])
ACX_GLIBC_SYMVER([chmod], [int], [(const char *path, mode_t mode)])
ACX_GLIBC_SYMVER([lchmod], [int], [(const char *path, mode_t mode)])
ACX_GLIBC_SYMVER([fchmodat], [int], [(int dirfd, const char *path, mode_t mode, int flags)])
ACX_GLIBC_SYMVER([chown], [int], [(const char *path, uid_t owner, gid_t group)])
ACX_GLIBC_SYMVER([lchown], [int], [(const char *path, uid_t owner, gid_t group)])
ACX_GLIBC_SYMVER([fchownat], [int], [(int dirfd, const char *path, uid_t owner, gid_t group, int flags)])

dnl Exec operations
ACX_GLIBC_SYMVER([execve], [int], [(const char *pathname, char *const argv[], char *const envp[])])
ACX_GLIBC_SYMVER([execv], [int], [(const char *pathname, char *const argv[])])
ACX_GLIBC_SYMVER([execvp], [int], [(const char *file, char *const argv[])])
ACX_GLIBC_SYMVER([execl], [int], [(const char *pathname, const char *arg, ...)])
ACX_GLIBC_SYMVER([execle], [int], [(const char *pathname, const char *arg, ...)])
ACX_GLIBC_SYMVER([execlp], [int], [(const char *file, const char *arg, ...)])
ACX_GLIBC_SYMVER([posix_spawn], [int], [(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[])])
ACX_GLIBC_SYMVER([posix_spawnp], [int], [(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[])])

dnl Rename operations
ACX_GLIBC_SYMVER([rename], [int], [(const char *oldpath, const char *newpath)])
ACX_GLIBC_SYMVER([renameat], [int], [(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)])
ACX_GLIBC_SYMVER([renameat2], [int], [(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)])

dnl Temp file operations
ACX_GLIBC_SYMVER([mktemp], [char *], [(char *template)])
ACX_GLIBC_SYMVER([mkstemp], [int], [(char *template)])
ACX_GLIBC_SYMVER([mkstemp64], [int], [(char *template)])
ACX_GLIBC_SYMVER([mkstemps], [int], [(char *template, int suffixlen)])
ACX_GLIBC_SYMVER([mkstemps64], [int], [(char *template, int suffixlen)])
ACX_GLIBC_SYMVER([mkostemp], [int], [(char *template, int flags)])
ACX_GLIBC_SYMVER([mkostemp64], [int], [(char *template, int flags)])
ACX_GLIBC_SYMVER([mkostemps], [int], [(char *template, int suffixlen, int flags)])
ACX_GLIBC_SYMVER([mkostemps64], [int], [(char *template, int suffixlen, int flags)])
ACX_GLIBC_SYMVER([mkdtemp], [char *], [(char *template)])
ACX_GLIBC_SYMVER([tempnam], [char *], [(const char *dir, const char *pfx)])
ACX_GLIBC_SYMVER([tmpnam], [char *], [(char *s)])

dnl FIFO/device operations
ACX_GLIBC_SYMVER([mkfifo], [int], [(const char *pathname, mode_t mode)])
ACX_GLIBC_SYMVER([mkfifoat], [int], [(int dirfd, const char *pathname, mode_t mode)])
ACX_GLIBC_SYMVER([mknod], [int], [(const char *pathname, mode_t mode, dev_t dev)])
ACX_GLIBC_SYMVER([mknodat], [int], [(int dirfd, const char *pathname, mode_t mode, dev_t dev)])

dnl Path operations
ACX_GLIBC_SYMVER([realpath], [char *], [(const char *path, char *resolved_path)])
ACX_GLIBC_SYMVER([canonicalize_file_name], [char *], [(const char *path)])
ACX_GLIBC_SYMVER([pathconf], [long], [(const char *path, int name)])

dnl Truncate operations
ACX_GLIBC_SYMVER([truncate], [int], [(const char *path, off_t length)])
ACX_GLIBC_SYMVER([truncate64], [int], [(const char *path, off64_t length)])

dnl Time operations
ACX_GLIBC_SYMVER([utime], [int], [(const char *filename, const struct utimbuf *times)])
ACX_GLIBC_SYMVER([utimes], [int], [(const char *filename, const struct timeval times[2])])
ACX_GLIBC_SYMVER([lutimes], [int], [(const char *filename, const struct timeval times[2])])
ACX_GLIBC_SYMVER([futimesat], [int], [(int dirfd, const char *pathname, const struct timeval times[2])])
ACX_GLIBC_SYMVER([utimensat], [int], [(int dirfd, const char *pathname, const struct timespec times[2], int flags)])

dnl Extended attributes
ACX_GLIBC_SYMVER([getxattr], [ssize_t], [(const char *path, const char *name, void *value, size_t size)])
ACX_GLIBC_SYMVER([lgetxattr], [ssize_t], [(const char *path, const char *name, void *value, size_t size)])
ACX_GLIBC_SYMVER([setxattr], [int], [(const char *path, const char *name, const void *value, size_t size, int flags)])
ACX_GLIBC_SYMVER([lsetxattr], [int], [(const char *path, const char *name, const void *value, size_t size, int flags)])
ACX_GLIBC_SYMVER([listxattr], [ssize_t], [(const char *path, char *list, size_t size)])
ACX_GLIBC_SYMVER([llistxattr], [ssize_t], [(const char *path, char *list, size_t size)])
ACX_GLIBC_SYMVER([removexattr], [int], [(const char *path, const char *name)])
ACX_GLIBC_SYMVER([lremovexattr], [int], [(const char *path, const char *name)])

dnl Glob and scandir
ACX_GLIBC_SYMVER([glob], [int], [(const char *pattern, int flags, int (*errfunc)(const char *, int), glob_t *pglob)])
ACX_GLIBC_SYMVER([glob64], [int], [(const char *pattern, int flags, int (*errfunc)(const char *, int), glob64_t *pglob)])
ACX_GLIBC_SYMVER([glob_pattern_p], [int], [(const char *pattern, int quote)])
ACX_GLIBC_SYMVER([scandir], [int], [(const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **))])
ACX_GLIBC_SYMVER([scandir64], [int], [(const char *dirp, struct dirent64 ***namelist, int (*filter)(const struct dirent64 *), int (*compar)(const struct dirent64 **, const struct dirent64 **))])

dnl Socket operations
ACX_GLIBC_SYMVER([bind], [int], [(int sockfd, const struct sockaddr *addr, socklen_t addrlen)])
ACX_GLIBC_SYMVER([connect], [int], [(int sockfd, const struct sockaddr *addr, socklen_t addrlen)])
ACX_GLIBC_SYMVER([getpeername], [int], [(int sockfd, struct sockaddr *addr, socklen_t *addrlen)])
ACX_GLIBC_SYMVER([getsockname], [int], [(int sockfd, struct sockaddr *addr, socklen_t *addrlen)])

dnl Dynamic linker
ACX_GLIBC_SYMVER([dlopen], [void *], [(const char *filename, int flags)])
ACX_GLIBC_SYMVER([dlmopen], [void *], [(Lmid_t lmid, const char *filename, int flags)])
ACX_GLIBC_SYMVER([dladdr], [int], [(const void *addr, Dl_info *info)])
ACX_GLIBC_SYMVER([dl_iterate_phdr], [int], [(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data)])

dnl FTW internal functions
ACX_GLIBC_SYMVER([_xftw], [int], [(int mode, const char *dir, int (*fn)(const char *, const struct stat *, int), int nopenfd)])
ACX_GLIBC_SYMVER([_xftw64], [int], [(int mode, const char *dir, int (*fn)(const char *, const struct stat64 *, int), int nopenfd)])

dnl Misc operations
ACX_GLIBC_SYMVER([acct], [int], [(const char *filename)])
ACX_GLIBC_SYMVER([bindtextdomain], [char *], [(const char *domainname, const char *dirname)])
ACX_GLIBC_SYMVER([clearenv], [int], [(void)])
ACX_GLIBC_SYMVER([inotify_add_watch], [int], [(int fd, const char *pathname, uint32_t mask)])
ACX_GLIBC_SYMVER([lckpwdf], [int], [(void)])
ACX_GLIBC_SYMVER([ulckpwdf], [int], [(void)])
ACX_GLIBC_SYMVER([remove], [int], [(const char *pathname)])
ACX_GLIBC_SYMVER([revoke], [int], [(const char *file)])
ACX_GLIBC_SYMVER([sigaction], [int], [(int signum, const struct sigaction *act, struct sigaction *oldact)])
ACX_GLIBC_SYMVER([system], [int], [(const char *command)])

dnl Create separate symver header (included after system headers in libfakechroot.h)
AC_CONFIG_COMMANDS([libc-symver-h], [
    echo "/* Versioned libc symbol declarations - generated by configure */" > src/libc-symver.h
    echo "/* Include after system headers that define the types used here */" >> src/libc-symver.h
    cat "$LIBC_SYMVER_FILE" >> src/libc-symver.h
], [LIBC_SYMVER_FILE="$LIBC_SYMVER_FILE"])

# List of Makefiles
AC_CONFIG_FILES(m4_normalize([
    config.sh
    Makefile
    man/Makefile
    src/Makefile
    scripts/Makefile
    test/Makefile
    test/src/Makefile
]))

# prove --failures --exec /bin/sh
ACX_PROG_PROVE_OPT([--failures])
ACX_PROG_PROVE_OPT([--exec /bin/sh])

# Silence warning: ar: 'u' modifier ignored since 'D' is the default
AC_SUBST(AR_FLAGS, [cr])

# Generate output
AC_OUTPUT
