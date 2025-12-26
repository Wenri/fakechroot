/*
    libfakechroot -- fake chroot environment
    Android-specific configuration for nix-on-droid

    This header provides compile-time configuration for Android environments.
    All paths MUST be defined via CFLAGS during the Nix build process.
    No runtime environment variable fallback is supported.
*/

#ifndef __ANDROID_CONFIG_H
#define __ANDROID_CONFIG_H

/*
 * All configuration values are compile-time constants.
 * They must be defined via -D flags during build:
 *   -DFAKECHROOT_ANDROID_ELFLOADER="..."
 *   -DFAKECHROOT_ANDROID_LIBRARY_PATH="..."
 *   -DFAKECHROOT_ANDROID_PRELOAD="..."
 *   -DFAKECHROOT_ANDROID_BASE="..."
 *   -DFAKECHROOT_ANDROID_EXCLUDE_PATH="..."
 */

/* FAKECHROOT_ANDROID_ELFLOADER: Path to Android glibc's ld.so */
#ifndef FAKECHROOT_ANDROID_ELFLOADER
#error "FAKECHROOT_ANDROID_ELFLOADER must be defined at compile time"
#endif

/* FAKECHROOT_ANDROID_LIBRARY_PATH: Path to Android glibc's lib directory */
#ifndef FAKECHROOT_ANDROID_LIBRARY_PATH
#error "FAKECHROOT_ANDROID_LIBRARY_PATH must be defined at compile time"
#endif

/* FAKECHROOT_ANDROID_PRELOAD: Path to libfakechroot.so */
#ifndef FAKECHROOT_ANDROID_PRELOAD
#error "FAKECHROOT_ANDROID_PRELOAD must be defined at compile time"
#endif

/* FAKECHROOT_ANDROID_BASE: Base path for fakechroot path translation */
#ifndef FAKECHROOT_ANDROID_BASE
#error "FAKECHROOT_ANDROID_BASE must be defined at compile time"
#endif

/* FAKECHROOT_ANDROID_EXCLUDE_PATH: Paths to exclude from translation */
#ifndef FAKECHROOT_ANDROID_EXCLUDE_PATH
#error "FAKECHROOT_ANDROID_EXCLUDE_PATH must be defined at compile time"
#endif

/*
 * Simple accessor functions - return compile-time constants directly
 */
static inline int android_elfloader_enabled(void) {
    return (FAKECHROOT_ANDROID_ELFLOADER != NULL && FAKECHROOT_ANDROID_ELFLOADER[0] != '\0');
}

static inline const char* android_get_elfloader(void) {
    return FAKECHROOT_ANDROID_ELFLOADER;
}

static inline const char* android_get_library_path(void) {
    return FAKECHROOT_ANDROID_LIBRARY_PATH;
}

static inline const char* android_get_preload(void) {
    return FAKECHROOT_ANDROID_PRELOAD;
}

static inline const char* android_get_base(void) {
    return FAKECHROOT_ANDROID_BASE;
}

static inline const char* android_get_exclude_path(void) {
    return FAKECHROOT_ANDROID_EXCLUDE_PATH;
}

/*
 * --argv0 option is always enabled to preserve login shell detection
 */
static inline const char* android_get_argv0_opt(void) {
    return android_elfloader_enabled() ? "--argv0" : NULL;
}

#endif /* __ANDROID_CONFIG_H */
