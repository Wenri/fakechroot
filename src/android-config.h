/*
    libfakechroot -- fake chroot environment
    Android-specific configuration for nix-on-droid

    All paths are compile-time constants defined via -D flags:
      -DFAKECHROOT_ANDROID_ELFLOADER="..."
      -DFAKECHROOT_ANDROID_LIBRARY_PATH="..."
      -DFAKECHROOT_ANDROID_PRELOAD="..."
      -DFAKECHROOT_ANDROID_BASE="..."
      -DFAKECHROOT_ANDROID_EXCLUDE_PATH="..."
*/

#ifndef __ANDROID_CONFIG_H
#define __ANDROID_CONFIG_H

/* Validate required compile-time definitions */
#ifndef FAKECHROOT_ANDROID_ELFLOADER
#error "FAKECHROOT_ANDROID_ELFLOADER must be defined at compile time"
#endif

#ifndef FAKECHROOT_ANDROID_LIBRARY_PATH
#error "FAKECHROOT_ANDROID_LIBRARY_PATH must be defined at compile time"
#endif

#ifndef FAKECHROOT_ANDROID_PRELOAD
#error "FAKECHROOT_ANDROID_PRELOAD must be defined at compile time"
#endif

#ifndef FAKECHROOT_ANDROID_BASE
#error "FAKECHROOT_ANDROID_BASE must be defined at compile time"
#endif

#ifndef FAKECHROOT_ANDROID_EXCLUDE_PATH
#error "FAKECHROOT_ANDROID_EXCLUDE_PATH must be defined at compile time"
#endif

/* Use macros directly - string literals are deduplicated by linker */
#define ANDROID_ELFLOADER       FAKECHROOT_ANDROID_ELFLOADER
#define ANDROID_LIBRARY_PATH    FAKECHROOT_ANDROID_LIBRARY_PATH
#define ANDROID_PRELOAD         FAKECHROOT_ANDROID_PRELOAD
#define ANDROID_BASE            FAKECHROOT_ANDROID_BASE
#define ANDROID_EXCLUDE_PATH    FAKECHROOT_ANDROID_EXCLUDE_PATH
#define ANDROID_ARGV0_OPT       "--argv0"

#endif /* __ANDROID_CONFIG_H */
