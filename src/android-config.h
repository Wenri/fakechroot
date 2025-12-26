/*
    libfakechroot -- fake chroot environment
    Android-specific configuration for nix-on-droid

    All paths are compile-time constants defined via -D flags:
      -DANDROID_ELFLOADER="..."
      -DANDROID_LIBRARY_PATH="..."
      -DANDROID_PRELOAD="..."
      -DANDROID_BASE="..."
      -DANDROID_EXCLUDE_PATH="..."
*/

#ifndef __ANDROID_CONFIG_H
#define __ANDROID_CONFIG_H

/* Validate required compile-time definitions */
#ifndef ANDROID_ELFLOADER
#error "ANDROID_ELFLOADER must be defined at compile time"
#endif

#ifndef ANDROID_LIBRARY_PATH
#error "ANDROID_LIBRARY_PATH must be defined at compile time"
#endif

#ifndef ANDROID_PRELOAD
#error "ANDROID_PRELOAD must be defined at compile time"
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
