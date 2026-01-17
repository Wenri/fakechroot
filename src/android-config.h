/*
    libfakechroot -- fake chroot environment
    Android-specific configuration for nix-on-droid

    All paths are compile-time constants defined via -D flags:
      -DANDROID_ELFLOADER="..."      - Path to ld.so (Android glibc's dynamic linker)
      -DANDROID_BASE="..."           - Installation prefix (/data/data/.../usr)
      -DANDROID_EXCLUDE_PATH="..."   - Paths excluded from chroot translation

    Note: --library-path and --preload are no longer needed because:
      - ld.so.preload handles libfakechroot preloading
      - ld.so has built-in glibc path redirection
      - ld.so has built-in /nix/store path translation
*/

#ifndef __ANDROID_CONFIG_H
#define __ANDROID_CONFIG_H

/* Validate required compile-time definitions */
#ifndef ANDROID_ELFLOADER
#error "ANDROID_ELFLOADER must be defined at compile time"
#endif

#ifndef ANDROID_BASE
#error "ANDROID_BASE must be defined at compile time"
#endif

#ifndef ANDROID_EXCLUDE_PATH
#error "ANDROID_EXCLUDE_PATH must be defined at compile time"
#endif

/* Hardcoded --argv0 option for login shell detection */
#define ANDROID_ARGV0_OPT "--argv0"

#endif /* __ANDROID_CONFIG_H */
