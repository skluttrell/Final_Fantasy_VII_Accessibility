/*
 * hooks.h -- Game function hook declarations.
 *
 * All hooks are installed into the FF7 process by patching the opcode dispatch
 * table and specific CALL instruction sites. This module follows the exact same
 * pattern as FFNx/src/voice.cpp, which we studied to map all hook points.
 *
 * HOOK INSTALLATION MODEL:
 *
 *   FF7's field script VM dispatches opcodes through a table of function pointers:
 *     execute_opcode_table[opcode_byte]()
 *
 *   We replace specific entries with our functions. Before replacing each entry,
 *   we save the existing pointer. The existing pointer may already be FFNx's
 *   voice handler (if FFNx loaded before us, which it does). Our handler calls
 *   the saved pointer at the end, forming this chain:
 *
 *     our_hook → (FFNx voice handler) → original FF7 opcode handler
 *
 *   This means voice acting (via FFNx) and TTS (via us) both run. Neither
 *   mod blocks the other.
 *
 * THREAD SAFETY:
 *   Install() must be called from the game's main thread, during the game loop,
 *   after the game has finished initializing. It is not safe to call from
 *   DllMain. The winmm_proxy.cpp timeGetTime hook triggers Install() at the
 *   right moment.
 */

#pragma once

namespace Hooks {

/*
 * Install: Patch the opcode table and CALL sites to redirect game functions
 * through our hook handlers.
 *
 * This function is idempotent — calling it more than once is a no-op.
 * It is called once from WinmmProxy::OnGameLoopStarted() the first time
 * timeGetTime is called after the game's field subsystem has initialized.
 *
 * Returns true if all hooks were installed successfully.
 * Returns false if FF7Addr::Resolve() failed (game not yet initialized, or
 * wrong exe version). The caller should retry on the next timeGetTime call.
 */
bool Install();

/*
 * Uninstall: Restore all patched opcode table entries and CALL sites to
 * their previous values. Called from DllMain on DLL_PROCESS_DETACH.
 * Safe to call if Install() was never called or failed.
 */
void Uninstall();

} // namespace Hooks
