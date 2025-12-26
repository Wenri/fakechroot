/*
    libfakechroot -- fake chroot environment
    Android-specific configuration for nix-on-droid

    This header provides compile-time configuration for Android environments.
    Paths are passed via CFLAGS during the Nix build process.
*/

#ifndef __ANDROID_CONFIG_H
#define __ANDROID_CONFIG_H

/*
 * FAKECHROOT_ANDROID_ELFLOADER: Path to Android glibc's ld.so
 * This is used to execute all ELF binaries with the Android-patched glibc.
 * Defined at compile time via -DFAKECHROOT_ANDROID_ELFLOADER="..."
 */
#ifndef FAKECHROOT_ANDROID_ELFLOADER
#define FAKECHROOT_ANDROID_ELFLOADER NULL
#endif

/*
 * FAKECHROOT_ANDROID_LIBRARY_PATH: Path to Android glibc's lib directory
 * Passed to ld.so via --library-path to override binary's RPATH.
 * Defined at compile time via -DFAKECHROOT_ANDROID_LIBRARY_PATH="..."
 */
#ifndef FAKECHROOT_ANDROID_LIBRARY_PATH
#define FAKECHROOT_ANDROID_LIBRARY_PATH NULL
#endif

/*
 * FAKECHROOT_ANDROID_PRELOAD: Path to libfakechroot.so
 * Passed to ld.so via --preload to intercept libc calls.
 * Defined at compile time via -DFAKECHROOT_ANDROID_PRELOAD="..."
 */
#ifndef FAKECHROOT_ANDROID_PRELOAD
#define FAKECHROOT_ANDROID_PRELOAD NULL
#endif

/*
 * FAKECHROOT_ANDROID_BASE: Base path for fakechroot path translation
 * This is the nix-on-droid installation directory.
 * Defined at compile time via -DFAKECHROOT_ANDROID_BASE="..."
 */
#ifndef FAKECHROOT_ANDROID_BASE
#define FAKECHROOT_ANDROID_BASE NULL
#endif

/*
 * FAKECHROOT_ANDROID_EXCLUDE_PATH: Paths to exclude from translation
 * Colon-separated list of paths that should NOT be translated.
 * Defined at compile time via -DFAKECHROOT_ANDROID_EXCLUDE_PATH="..."
 */
#ifndef FAKECHROOT_ANDROID_EXCLUDE_PATH
#define FAKECHROOT_ANDROID_EXCLUDE_PATH NULL
#endif

/*
 * Helper macro to get config value: use compile-time constant if defined,
 * otherwise fall back to environment variable for backward compatibility.
 */
#define ANDROID_CONFIG_GET(compile_time, env_name) \
    ((compile_time) != NULL ? (compile_time) : getenv(env_name))

/*
 * Check if Android mode is enabled (either via compile-time config or env)
 */
static inline int android_elfloader_enabled(void) {
    const char *elfloader = ANDROID_CONFIG_GET(FAKECHROOT_ANDROID_ELFLOADER, "FAKECHROOT_ELFLOADER");
    return (elfloader != NULL && *elfloader != '\0');
}

static inline const char* android_get_elfloader(void) {
    return ANDROID_CONFIG_GET(FAKECHROOT_ANDROID_ELFLOADER, "FAKECHROOT_ELFLOADER");
}

static inline const char* android_get_library_path(void) {
    return ANDROID_CONFIG_GET(FAKECHROOT_ANDROID_LIBRARY_PATH, "FAKECHROOT_ELFLOADER_OPT_LIBRARY_PATH");
}

static inline const char* android_get_preload(void) {
    return ANDROID_CONFIG_GET(FAKECHROOT_ANDROID_PRELOAD, "FAKECHROOT_ELFLOADER_OPT_PRELOAD");
}

static inline const char* android_get_base(void) {
    return ANDROID_CONFIG_GET(FAKECHROOT_ANDROID_BASE, "FAKECHROOT_BASE");
}

static inline const char* android_get_exclude_path(void) {
    return ANDROID_CONFIG_GET(FAKECHROOT_ANDROID_EXCLUDE_PATH, "FAKECHROOT_EXCLUDE_PATH");
}

/*
 * --argv0 option is always enabled on Android to preserve login shell detection
 */
static inline const char* android_get_argv0_opt(void) {
    const char *opt = getenv("FAKECHROOT_ELFLOADER_OPT_ARGV0");
    if (opt != NULL && *opt != '\0') return opt;
    /* Default to --argv0 if elfloader is enabled */
    return android_elfloader_enabled() ? "--argv0" : NULL;
}

#endif /* __ANDROID_CONFIG_H */
