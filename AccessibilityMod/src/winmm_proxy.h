/*
 * winmm_proxy.h -- Public interface for the winmm.dll proxy layer.
 *
 * WHY WE ARE WINMM.DLL:
 *   FF7.exe (and many supporting mods) call timeGetTime() to drive their timing
 *   loops. By placing our DLL in the FF7 install folder as "winmm.dll", the OS
 *   loads us instead of the system winmm.dll. We forward all winmm functions
 *   to the real system DLL (via linker .def EXPORTS forwarding) except for
 *   timeGetTime(), which we implement ourselves.
 *
 * INIT TRIGGER:
 *   We cannot install hooks at DllMain time because:
 *     1. DLL loader lock prevents safe use of some Win32 API functions.
 *     2. FF7's field module (which populates the opcode dispatch table) has not
 *        yet initialized at DLL attach time — the opcode table entries are zero.
 *
 *   timeGetTime() is called many times per second throughout the entire game
 *   (in the main loop, timing subsystem, and audio). We use our implementation
 *   as a safe, post-init trigger: on the first call after FF7Addr::Resolve()
 *   succeeds, we install hooks. Resolve() itself detects "not ready" by checking
 *   whether the opcode table entries are valid.
 *
 * DELEGATE:
 *   For timeGetTime()'s actual timing work, we delegate to the real system
 *   winmm.dll after hooks are installed. Before that, we fall back to
 *   GetTickCount() which has the same semantic (ms since boot) and is always
 *   available. The few-millisecond drift during the init window is invisible
 *   to the game.
 *
 * PROXY CHAINING:
 *   If another mod (e.g., Reunion) has placed its own winmm.dll proxy in the
 *   FF7 folder and renamed it to "winmm_chain.dll", we load it first and
 *   forward calls through it. This is a v2 feature; v1 assumes we are the
 *   only winmm proxy. See FFVII-Accessibility-Research.md Section 6, Hurdle 3.
 */

#pragma once

namespace WinmmProxy {

/*
 * Init: Load the real system winmm.dll from System32 and capture the
 * timeGetTime function pointer. Called from DllMain DLL_PROCESS_ATTACH.
 *
 * This is safe to call from DllMain because we use the full absolute path to
 * the system DLL (System32\winmm.dll), which creates a separate module entry
 * distinct from our proxy (in the FF7 folder). The system DLL is a "Known DLL"
 * so Windows handles the re-entrant load without deadlock.
 */
void Init();

/*
 * Shutdown: Unload the system winmm.dll handle. Called from DllMain
 * DLL_PROCESS_DETACH. Safe to call even if Init() was never called.
 */
void Shutdown();

} // namespace WinmmProxy
