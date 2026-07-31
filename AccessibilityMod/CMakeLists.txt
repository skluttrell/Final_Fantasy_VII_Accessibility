cmake_minimum_required(VERSION 3.16)

# Project: FF7 Accessibility Mod — version.dll proxy DLL
project(FF7AccessibilityMod CXX)

# ---------------------------------------------------------------------------
# CRITICAL: This DLL MUST be built as x86 (32-bit).
#
# FF7 2013 Steam Edition is a 32-bit process. Windows cannot load a 64-bit
# DLL into a 32-bit process — the loader will silently ignore the mismatch.
# If you are configuring CMake manually, pass:
#
#   cmake -A Win32 -B build
#
# or set the generator platform to Win32 in Visual Studio / CMake GUI.
# If you build 64-bit by mistake, the DLL will not load and FF7 will fall
# through to the system version.dll, disabling all accessibility features
# silently with no error message.
# ---------------------------------------------------------------------------

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR
        "FF7AccessibilityMod must be built as 32-bit (x86).\n"
        "Re-run CMake with: cmake -A Win32 -B build\n"
        "or use a 32-bit toolchain file.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------

set(MOD_SOURCES
    src/dllmain.cpp
    src/proxy.cpp           # version.dll stubs + background init thread
    src/hooks.cpp
    src/ff7_addresses.cpp
    src/ff7_text.cpp
    src/config.cpp
    src/log.cpp             # debug logging: file output + OutputDebugStringA
    src/tones.cpp           # waveOut tone playback (v2.30.41). Replaces
                            # kernel32 Beep(), which is silent on some
                            # systems (VMs/remote desktops). winmm is
                            # loaded dynamically from System32 at runtime,
                            # so winmm.lib is deliberately NOT linked —
                            # see "SELF-PROXY SAFETY" in tones.h.
    src/settings_menu.cpp   # F8 in-game audio-only accessibility menu
                            # (v2.30.42): browse/edit every cfg setting by
                            # ear, live apply + live save, no restart.
    src/tts.cpp
    src/gamepad.cpp         # right-analog-stick pathfinder input (v2.21).
                            # XInput is loaded dynamically at runtime, so no
                            # xinput import library is linked here — see the
                            # header comment in gamepad.cpp for why.
    # Including version.def in the source list is the correct CMake idiom for MSVC:
    # CMake recognizes .def files and passes them to the linker as /DEF:version.def.
    # This is preferred over LINK_FLAGS because CMake handles path quoting and
    # establishes a proper dependency (re-link if the .def changes).
    version.def
)

# ---------------------------------------------------------------------------
# Embed the canonical config file (v2.30.39).
#
# Config::Load() creates ffvii_accessibility.cfg next to the DLL when the
# file is missing. The content it writes is THIS repo's canonical cfg,
# embedded at configure time as a byte array — one source of truth, so the
# generated default can never drift from the committed file. A byte array
# (not a string literal) because MSVC caps a single string literal at ~16K
# (C2026) and the cfg sits near that size.
#
# CMAKE_CONFIGURE_DEPENDS makes an edit to the cfg re-run CMake (and thus
# regenerate the header) on the next build automatically.
# ---------------------------------------------------------------------------

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/ffvii_accessibility.cfg" DEFAULT_CFG_HEX HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," DEFAULT_CFG_BYTES "${DEFAULT_CFG_HEX}")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/default_config.h.in"
    "${CMAKE_BINARY_DIR}/generated/default_config.h"
    @ONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/ffvii_accessibility.cfg")

# ---------------------------------------------------------------------------
# DLL target
# ---------------------------------------------------------------------------

add_library(ff7access SHARED ${MOD_SOURCES})

set_target_properties(ff7access PROPERTIES
    OUTPUT_NAME "version"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/dist"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/dist"
)

# ---------------------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------------------

target_include_directories(ff7access PRIVATE
    src                   # for cross-module includes within our own source
    deps/tolk             # for Tolk.h (the Tolk screen reader library C API)
    "${CMAKE_BINARY_DIR}/generated"   # default_config.h (embedded cfg, see above)
)

# ---------------------------------------------------------------------------
# Compiler options
# ---------------------------------------------------------------------------

target_compile_options(ff7access PRIVATE
    # Treat warnings as errors in Release builds to catch issues early.
    $<$<CONFIG:Release>:/WX>

    # Disable RTTI — we never use dynamic_cast or typeid.
    # Exceptions: /EHsc is required by MSVC's STL headers (string, fstream)
    # even if we never explicitly throw. /EHs-c- causes C4530 in every STL
    # header include and forces us off std::string/wstring entirely.
    /GR-   # No RTTI
    /EHsc  # Standard C++ exception handling (required by STL headers)

    # Security hardening
    /GS    # Buffer security checks (stack cookies)
    /sdl   # Additional SDL checks

    # Suppress noisy but harmless warnings
    /wd4100  # unreferenced formal parameter (some hooks forward params)
    /wd4127  # conditional expression is constant (if constexpr emulation)
)

# ---------------------------------------------------------------------------
# Linker options
# ---------------------------------------------------------------------------

target_link_libraries(ff7access PRIVATE
    kernel32
    user32       # GetSystemDirectoryA, OutputDebugStringA
)

# Use the static CRT (/MT for Release, /MTd for Debug) to avoid a dependency
# on a specific MSVC redist version in the FF7 folder.
set_property(TARGET ff7access PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ---------------------------------------------------------------------------
# Post-build: copy the dist DLL to your FF7 install directory.
# Uncomment and set FF7_INSTALL_DIR to automate deployment during development.
# ---------------------------------------------------------------------------

# set(FF7_INSTALL_DIR "C:/Program Files (x86)/Steam/steamapps/common/FINAL FANTASY VII")
# add_custom_command(TARGET ff7access POST_BUILD
#     COMMAND ${CMAKE_COMMAND} -E copy_if_different
#         "$<TARGET_FILE:ff7access>"
#         "${FF7_INSTALL_DIR}/version.dll"
#     COMMENT "Deployed version.dll to FF7 install directory")

# ---------------------------------------------------------------------------
# Install rules (for manual packaging)
# ---------------------------------------------------------------------------

install(TARGETS ff7access
    RUNTIME DESTINATION .
    LIBRARY DESTINATION .)

install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/ffvii_accessibility.cfg"
    DESTINATION .)
