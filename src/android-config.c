/*
    libfakechroot -- fake chroot environment
    Android-specific configuration for nix-on-droid

    Definitions for compile-time configuration constants.
    Values are set via -D flags during build.
*/

#include "android-config.h"

/* Configuration constants - values come from -D compiler flags */
const char *const android_elfloader = FAKECHROOT_ANDROID_ELFLOADER;
const char *const android_library_path = FAKECHROOT_ANDROID_LIBRARY_PATH;
const char *const android_preload = FAKECHROOT_ANDROID_PRELOAD;
const char *const android_base = FAKECHROOT_ANDROID_BASE;
const char *const android_exclude_path = FAKECHROOT_ANDROID_EXCLUDE_PATH;
