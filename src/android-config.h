/*
    libfakechroot -- fake chroot environment
    Android-specific configuration for nix-on-droid

    This header provides compile-time configuration for Android environments.
    All paths MUST be defined via CFLAGS during the Nix build process.
    No runtime environment variable fallback is supported.

    Build with:
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

/*
 * Configuration constants - defined in android-config.c
 * Using extern declarations avoids string duplication across translation units
 */
extern const char *const android_elfloader;
extern const char *const android_library_path;
extern const char *const android_preload;
extern const char *const android_base;
extern const char *const android_exclude_path;

/* Hardcoded --argv0 option for login shell detection */
#define ANDROID_ARGV0_OPT "--argv0"

#endif /* __ANDROID_CONFIG_H */
