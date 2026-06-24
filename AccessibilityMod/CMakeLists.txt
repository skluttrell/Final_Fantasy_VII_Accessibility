cmake_minimum_required(VERSION 3.16)

# Project: FF7 Accessibility Mod — winmm.dll proxy DLL
project(FF7AccessibilityMod CXX)

# ---------------------------------------------------------------------------
# CRITICAL: This DLL MUST be built as x86 (32-bit).
#
# FF7 2013 Steam Edition is a 32-bit process. Windows cannot load a 64-bit
# DLL into a 32-bit process — the loader will silently ignore or crash on
# the mismatch. If you are configuring CMake manually, pass:
#
#   cmake -A Win32 -B build
#
# or set the generator platform to Win32 in Visual Studio / CMake GUI.
# Alternatively, use the provided build scripts which set this correctly.
#
# If you build 64-bit by mistake, the DLL will simply not load and FF7 will
# use the system winmm.dll, disabling all accessibility features with no error.
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
    src/winmm_proxy.cpp
    src/hooks.cpp
    src/ff7_addresses.cpp
    src/ff7_text.cpp
    src/config.cpp
    src/tts.cpp
    # Including winmm.def in the source list is the correct CMake idiom for MSVC:
    # CMake recognizes .def files and passes them to the linker as /DEF:winmm.def.
    # This is preferred over LINK_FLAGS because CMake handles path quoting and
    # establishes a proper dependency (re-link when the .def changes).
    winmm.def
)

# ---------------------------------------------------------------------------
# DLL target
# ---------------------------------------------------------------------------

add_library(winmm SHARED ${MOD_SOURCES})

set_target_properties(winmm PROPERTIES
    OUTPUT_NAME "winmm"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/dist"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/dist"
)

# ---------------------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------------------

target_include_directories(winmm PRIVATE
    src                   # for cross-module includes within our own source
    deps/tolk             # for Tolk.h (the Tolk screen reader library C API)
)

# ---------------------------------------------------------------------------
# Compiler options
# ---------------------------------------------------------------------------

target_compile_options(winmm PRIVATE
    # Treat warnings as errors in Release builds to catch issues early.
    $<$<CONFIG:Release>:/WX>

    # Disable RTTI — we never use dynamic_cast or typeid.
    # Exceptions: use /EHsc (standard C++ EH) — MSVC's STL headers require it
    # even if we never explicitly throw. Disabling with /EHs-c- causes C4530 in
    # every STL header include and would force us off std::string/wstring entirely.
    /GR-   # No RTTI
    /EHsc  # Standard C++ exception handling (required by STL)

    # Security hardening
    /GS    # Buffer security checks (stack cookies)
    /sdl   # Additional SDL checks

    # Suppress noisy but harmless warnings for MSVC
    /wd4100  # unreferenced formal parameter (some hooks forward params)
    /wd4127  # conditional expression is constant (if constexpr emulation)
)

# ---------------------------------------------------------------------------
# Linker options
# ---------------------------------------------------------------------------

target_link_libraries(winmm PRIVATE
    # Windows system libraries needed by our code.
    # kernel32 is implicit; we list the others explicitly.
    kernel32
    user32       # OutputDebugString, GetSystemDirectory
)

# Use the static CRT (/MT for Release, /MTd for Debug) to avoid a dependency
# on a specific MSVC redist DLL in the FF7 folder. FF7 ships its own CRT;
# we must not conflict with it.
set_property(TARGET winmm PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ---------------------------------------------------------------------------
# Post-build: copy the dist DLL to a known output path
# Useful if you want to point this directly at your FF7 install directory.
# Uncomment and set FF7_INSTALL_DIR to automate deployment during development.
# ---------------------------------------------------------------------------

# set(FF7_INSTALL_DIR "C:/Program Files (x86)/Steam/steamapps/common/FINAL FANTASY VII")
# add_custom_command(TARGET winmm POST_BUILD
#     COMMAND ${CMAKE_COMMAND} -E copy_if_different
#         "$<TARGET_FILE:winmm>"
#         "${FF7_INSTALL_DIR}/winmm.dll"
#     COMMENT "Deployed winmm.dll to FF7 install directory")

# ---------------------------------------------------------------------------
# Install rules (for manual packaging)
# ---------------------------------------------------------------------------

install(TARGETS winmm
    RUNTIME DESTINATION .
    LIBRARY DESTINATION .)

# Install the default config file alongside the DLL.
install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/ffvii_accessibility.cfg"
    DESTINATION .)
