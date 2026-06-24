/*
 * proxy.h -- Public interface for the version.dll proxy layer.
 *
 * WHY VERSION.DLL (NOT WINMM.DLL):
 *   The original implementation used winmm.dll as the proxy vehicle. This
 *   caused an immediate crash during FFNx initialization. The crash trace:
 *
 *     [FFNx] WARNING: get_relative_call: Unrecognized call/jmp instruction
 *            at 0x70C932A0 + 0x3B (0x70C932DB): 0xF800
 *     [FFNx] Exception 0xc0000005 — ff7_find_externals → ff7_init_hooks
 *
 *   FFNx's ff7_find_externals() resolves FF7 internal addresses by walking
 *   call-instruction chains from system DLL function addresses as anchors:
 *
 *     GetProcAddress(GetModuleHandle("winmm.dll"), "timeBeginPeriod")
 *     → get_relative_call(that_addr, 0x3B)  -- expects an E8 CALL opcode
 *
 *   When we WERE winmm.dll, GetModuleHandle("winmm.dll") returned our proxy.
 *   GetProcAddress returned our naked JMP stub (6 bytes: FF 25 [addr]).
 *   At stub+0x3B, FFNx found 0xF800 (bytes from an adjacent stub), not E8.
 *   FFNx logged the warning, then crashed dereferencing an invalid pointer.
 *
 * WHY VERSION.DLL WORKS:
 *   - FFNx does not use version.dll for address chain resolution. Its
 *     GetModuleHandle("winmm.dll") now correctly returns the real system DLL.
 *   - FF7 (or an early dependency like FFNx itself) imports version.dll — it
 *     appears in the process module list as VERSION.dll (confirmed from
 *     FF7's FFNx.log: "VERSION.dll (75010000)").
 *   - Our proxy in the FF7 install folder is found before the system copy:
 *     standard DLL search order checks the application directory first.
 *   - version.dll is NOT in the Windows Known DLLs set, so the application-
 *     directory search is NOT bypassed by the kernel's fast path.
 *   - version.dll has only 17 exports — far simpler than winmm's 168.
 *
 * INIT APPROACH — BACKGROUND THREAD:
 *   Without owning timeGetTime(), there is no per-frame trigger available
 *   from version.dll functions. Instead, Proxy::Init() creates a background
 *   thread that:
 *     1. Sleeps 200ms — ensures DllMain has returned, loader lock is free,
 *        and FFNx has completed its own ff7_find_externals / ff7_init_hooks.
 *     2. Calls Config::Load() and TTS::Init() (which calls LoadLibrary).
 *     3. Polls Hooks::Install() every 50ms until FF7's field module has
 *        populated the opcode dispatch table and hooks can be installed.
 *     4. Exits — no ongoing background thread after successful install.
 *
 *   The 50ms poll adds no perceptible latency: FF7 takes several seconds to
 *   reach the first field map after startup, so hooks are always installed
 *   before any dialog can appear.
 */

#pragma once

namespace Proxy {

/*
 * Init: Load the real system version.dll from System32 by full absolute path,
 * resolve all 17 function pointers via GetProcAddress, and spawn the background
 * initialization thread.
 *
 * Called from DllMain DLL_PROCESS_ATTACH. Safe in practice because:
 *   - version.dll has no circular DLL dependencies, so LoadLibraryA doesn't
 *     re-enter the loader or deadlock.
 *   - The background thread begins with Sleep(200ms), ensuring DllMain has
 *     returned and the loader lock is released before any LoadLibrary calls
 *     in the thread (specifically: TTS::Init → Tolk.dll).
 */
void Init();

/*
 * Shutdown: Unload the system version.dll handle. Safe to call even if
 * Init() was not called or failed partway through.
 */
void Shutdown();

} // namespace Proxy
