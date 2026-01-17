dnl acx_glibc_symver.m4 - Detect glibc symbol versions and generate declarations
dnl
dnl ACX_GLIBC_SYMVER_INIT
dnl   Initialize symbol version detection (find readelf, libc path)
dnl
dnl ACX_GLIBC_SYMVER(FUNCTION, RETURN_TYPE, ARGS)
dnl   Extract default version for FUNCTION from libc.so
dnl   Accumulates declaration in LIBC_SYMVER_DECLS for config.h

AC_DEFUN([ACX_GLIBC_SYMVER_INIT], [
    AC_PATH_PROG([READELF], [readelf], [no])

    AC_MSG_CHECKING([for libc.so path])
    if test -n "$LIBC_PATH" && test -f "$LIBC_PATH"; then
        AC_MSG_RESULT([$LIBC_PATH (from environment)])
    else
        dnl Try compiler first (works in nix)
        LIBC_PATH=$($CC -print-file-name=libc.so.6 2>/dev/null)
        if test -z "$LIBC_PATH" || ! test -f "$LIBC_PATH"; then
            dnl Try ldconfig
            LIBC_PATH=$(ldconfig -p 2>/dev/null | grep 'libc\.so\.6' | head -1 | awk '{print $NF}')
        fi
        if test -z "$LIBC_PATH" || ! test -f "$LIBC_PATH"; then
            dnl Try common paths
            for p in /lib/aarch64-linux-gnu/libc.so.6 /lib64/libc.so.6 /lib/libc.so.6 /usr/lib/libc.so.6; do
                if test -f "$p"; then
                    LIBC_PATH="$p"
                    break
                fi
            done
        fi
        if test -n "$LIBC_PATH" && test -f "$LIBC_PATH"; then
            AC_MSG_RESULT([$LIBC_PATH])
        else
            AC_MSG_RESULT([not found])
            LIBC_PATH=""
        fi
    fi
    AC_SUBST([LIBC_PATH])

    dnl Check if symbol versioning is possible
    if test "$READELF" = no || test -z "$LIBC_PATH"; then
        AC_MSG_WARN([Symbol versioning disabled: readelf or libc.so not found])
        acx_glibc_symver_enabled=no
    else
        acx_glibc_symver_enabled=yes
    fi

    dnl Initialize temp file for symbol declarations
    LIBC_SYMVER_FILE="conftest.symver"
    rm -f "$LIBC_SYMVER_FILE"
    touch "$LIBC_SYMVER_FILE"
    AC_SUBST([LIBC_SYMVER_FILE])
])

AC_DEFUN([ACX_GLIBC_SYMVER], [
    AC_REQUIRE([ACX_GLIBC_SYMVER_INIT])

    acx_glibc_ver=""
    if test "$acx_glibc_symver_enabled" = yes; then
        AC_MSG_CHECKING([glibc symbol version for $1])

        dnl Extract default version (marked with @@)
        acx_glibc_ver=$(${READELF} -sW "${LIBC_PATH}" 2>/dev/null | \
            grep " $1@@GLIBC" | head -1 | \
            sed -n 's/.*@@\(GLIBC_[[0-9.]]*\).*/\1/p')

        if test -n "$acx_glibc_ver"; then
            AC_MSG_RESULT([$acx_glibc_ver])
        else
            AC_MSG_RESULT([not found - will use dlsym fallback])
        fi
    fi

    dnl Write declaration to temp file
    dnl Use .symver with single @ for referencing (not @@ which defines default)
    if test -n "$acx_glibc_ver"; then
        echo "extern $2 __real_$1$3; __asm__(\".symver __real_$1, $1@$acx_glibc_ver\");" >> "$LIBC_SYMVER_FILE"
    else
        echo "#define __real_$1 fakechroot_$1_wrapper_decl.nextfunc" >> "$LIBC_SYMVER_FILE"
    fi
])
