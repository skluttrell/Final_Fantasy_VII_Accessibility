/*
 * dllmain.cpp -- DLL entry point for the FF7 Accessibility Mod (winmm.dll proxy).
 *
 * DLL_PROCESS_ATTACH:
 *   - Call WinmmProxy::Init() to load the system winmm.dll and capture the
 *     real timeGetTime pointer. This is safe from DllMain because we use the
 *     full System32 path (see winmm_proxy.h for the reasoning).
 *   - Config, TTS, and hook installation are deferred to the first call of
 *     our timeGetTime() implementation (see winmm_proxy.cpp).
 *
 * DLL_PROCESS_DETACH:
 *   - Uninstall hooks (restores game memory to its previous state).
 *   - Shut down TTS (silences screen reader, unloads Tolk.dll).
 *   - Unload system winmm handle.
 *
 * DLL_THREAD_ATTACH / DLL_THREAD_DETACH:
 *   - Not used. All our work happens on the main game thread.
 *     DisableThreadLibraryCalls() prevents these notifications for efficiency.
 *
 * LOADER LOCK NOTE:
 *   Windows calls DllMain with the loader lock held. Calling LoadLibrary,
 *   CreateThread, or most synchronization primitives from DllMain is unsafe.
 *   The ONLY Win32 calls made here during DLL_PROCESS_ATTACH are:
 *     - DisableThreadLibraryCalls (safe, documented exception)
 *     - WinmmProxy::Init → GetSystemDirectoryA, LoadLibraryA, GetProcAddress
 *   LoadLibraryA with a Known DLL full path is a documented safe case: the
 *   system winmm.dll is a Known DLL and its init has already completed before
 *   ours starts (it has no circular dependency on user-mode DLLs).
 */

#include "winmm_proxy.h"
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
        // Disable DLL_THREAD_ATTACH/DETACH notifications — we have no
        // per-thread state and this avoids unnecessary DllMain re-entries.
        DisableThreadLibraryCalls(hinstDLL);

        // Load the real system winmm.dll and capture its timeGetTime pointer.
        // All other initialization (Config, TTS, Hooks) is deferred to the
        // first timeGetTime() call, safely outside the loader lock.
        WinmmProxy::Init();
        break;

    case DLL_PROCESS_DETACH:
        // Restore game memory to its pre-hook state before we unload.
        // This prevents crashes if the game somehow continues to execute
        // after the DLL is detached (edge case with some mod managers).
        Hooks::Uninstall();

        // Stop any in-progress TTS speech and release Tolk.dll.
        TTS::Shutdown();

        // Release our handle to the system winmm.dll.
        WinmmProxy::Shutdown();
        break;

    default:
        break;
    }

    return TRUE;
}
