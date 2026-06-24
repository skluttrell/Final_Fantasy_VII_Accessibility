/*
 * dllmain.cpp -- DLL entry point for the FF7 Accessibility Mod (version.dll proxy).
 *
 * WHY VERSION.DLL (NOT WINMM.DLL):
 *   The original implementation used winmm.dll as the proxy. This caused an
 *   immediate crash: FFNx's ff7_find_externals() uses GetModuleHandle("winmm.dll")
 *   + GetProcAddress to get a function address it then walks instruction-by-
 *   instruction. When we were winmm.dll, it got our naked JMP stub (6 bytes:
 *   FF 25 [addr]) instead of real winmm code, found 0xF800 where it expected
 *   an E8 CALL opcode, and crashed with Exception 0xc0000005. Switching to
 *   version.dll avoids this: FFNx does not walk version.dll's internals.
 *   See proxy.h for the full analysis.
 *
 * DLL_PROCESS_ATTACH:
 *   - DisableThreadLibraryCalls() — suppresses DLL_THREAD_ATTACH/DETACH
 *     notifications and reduces loader lock contention from the init thread.
 *     Must be called BEFORE Proxy::Init() spawns the background thread.
 *   - Proxy::Init() — loads the real system version.dll from System32,
 *     resolves all 17 function pointers, and spawns the background init thread.
 *
 * Background thread (in proxy.cpp):
 *   - Sleeps 200ms (loader lock released, FFNx init complete)
 *   - Config::Load() + TTS::Init()
 *   - Polls Hooks::Install() every 50ms until FF7's field module is ready
 *   - Exits after successful install
 *
 * DLL_PROCESS_DETACH:
 *   - Hooks::Uninstall() — restore game memory to pre-hook state
 *   - TTS::Shutdown()    — silence screen reader, release Tolk.dll
 *   - Proxy::Shutdown()  — release system version.dll handle
 *
 * LOADER LOCK:
 *   DllMain runs with the loader lock held. Calls made here:
 *     - DisableThreadLibraryCalls — documented safe from DllMain
 *     - Proxy::Init → GetSystemDirectoryA, LoadLibraryA (version.dll has
 *       no circular deps), GetProcAddress, CreateThread
 *   The background thread starts with Sleep(200ms), ensuring DllMain has
 *   returned and the loader lock is released before any LoadLibrary calls
 *   in the thread (TTS::Init → Tolk.dll). This is the standard proxy DLL
 *   pattern used by ReShade, ENBSeries, DXVK, and others.
 */

#include "proxy.h"
#include "hooks.h"
#include "tts.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID /*lpvReserved*/)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Must be called before CreateThread in Proxy::Init() to suppress
        // DLL_THREAD_ATTACH notifications and reduce loader lock pressure.
        DisableThreadLibraryCalls(hinstDLL);

        // Load system version.dll, capture all 17 function pointers, and
        // spawn the background thread that installs hooks when FF7 is ready.
        Proxy::Init();
        break;

    case DLL_PROCESS_DETACH:
        // Restore opcode table entries to their pre-hook values.
        Hooks::Uninstall();

        // Silence any ongoing TTS speech and unload Tolk.dll.
        TTS::Shutdown();

        // Release our handle to the system version.dll.
        Proxy::Shutdown();
        break;

    default:
        break;
    }

    return TRUE;
}
