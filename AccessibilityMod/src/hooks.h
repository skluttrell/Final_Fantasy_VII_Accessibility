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
 *   Install() is called from the background init thread (proxy.cpp InitThread),
 *   which runs after the main thread's DllMain has returned and the loader lock
 *   is released. The opcode table DWORD write is atomic on x86 for naturally-
 *   aligned 4-byte accesses, so no additional locking is needed.
 */

#pragma once

namespace Hooks {

/*
 * Install: Patch the opcode table entries to redirect game functions through
 * our hook handlers.
 *
 * This function is idempotent — calling it more than once is a no-op.
 * It is polled by the background init thread (proxy.cpp) every 50ms until
 * FF7's field subsystem has initialized and the opcode table is populated.
 *
 * Returns true if all hooks were installed successfully.
 * Returns false if FF7Addr::Resolve() failed (field module not yet loaded, or
 * wrong exe version). The background thread will retry after 50ms.
 */
bool Install();

/*
 * Uninstall: Restore all patched opcode table entries and CALL sites to
 * their previous values. Called from DllMain on DLL_PROCESS_DETACH.
 * Safe to call if Install() was never called or failed.
 */
void Uninstall();

} // namespace Hooks
