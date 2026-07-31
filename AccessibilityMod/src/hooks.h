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

/*
 * LastDialogActivityTick: GetTickCount() timestamp of the most recent
 * MESSAGE or ASK hook invocation.
 *
 * WHY THIS EXISTS:
 *   The field script VM calls the MESSAGE/ASK opcode handlers EVERY FRAME
 *   while a dialog window is open, so "hook fired within the last ~250ms"
 *   is a reliable any-dialog-open signal. This is deliberately used instead
 *   of the opcode_message_loop_code state byte, which never changes for some
 *   windows (win=2 observed — see hooks.cpp state machine notes) and would
 *   miss those dialogs entirely.
 *
 *   Consumed by proxy.cpp's WallBumpThread: while a dialog is up the player
 *   may hold a direction (habit, or navigating an ASK choice) while their
 *   character is intentionally frozen — without this gate that state is
 *   indistinguishable from being blocked by a wall and would false-beep.
 *
 * THREAD SAFETY:
 *   Returns a DWORD (4-byte aligned, atomic on x86) written from the game's
 *   main thread and read from background polling threads. GetTickCount()
 *   wraps every 49.7 days; callers must compare with unsigned subtraction
 *   ("now - last < window"), which handles wrap correctly.
 *
 * Returns 0 if no dialog hook has fired yet this session.
 */
unsigned long LastDialogActivityTick();

/*
 * ConsumeDialogWaitTone / ConsumeDialogChoiceTone: edge-triggered signals
 * for the two optional dialog audio cues (v2.30.5):
 *
 *   WAIT tone   — a short high tone the instant a MESSAGE dialog's on-screen
 *                 text finishes displaying and the game is sitting there
 *                 waiting for the player to press the confirm button
 *                 (whether that press pages forward, closes the window, or
 *                 advances to the next line). Gated by
 *                 Config::Settings::dialog_wait_tone.
 *   CHOICE tone — a short high DOUBLE tone the instant an ASK choice menu is
 *                 presented. Gated by Config::Settings::dialog_choice_tone.
 *
 * WHY "CONSUME" (test-and-clear) INSTEAD OF A PLAIN GETTER:
 *   hook_message/hook_ask run on the GAME's main thread and can only SET
 *   these flags — tone playback (Tones::Play, waveOut since v2.30.41)
 *   blocks for the tone's whole duration, so calling it
 *   directly from an opcode hook would stall the game itself every time
 *   (same reasoning as WallBumpThread and the proximity/wander chirps in
 *   proxy.cpp: all of this mod's tones are played from a background polling
 *   thread, never from inside a hook). A background thread calls these once
 *   per poll; each call atomically reads AND clears the flag
 *   (InterlockedExchange), so a fresh set from the hook between the
 *   thread's read and its clear is never silently dropped, and the same
 *   event can never fire the tone twice.
 *
 * Returns true (once) if that cue's flag was set since the last call;
 * false otherwise.
 */
bool ConsumeDialogWaitTone();
bool ConsumeDialogChoiceTone();

/*
 * SttimSeen: true once a LIVE STTIM (opcode 0x38, "set timer") call has
 * been observed THIS PROCESS RUN. Sticky — once true, stays true for the
 * rest of the session (unlike the Consume* functions above, this is not
 * an edge event to drain, just a "has this happened yet at all" latch).
 *
 * WHY THIS EXISTS (v2.30.8):
 *   COUNTDOWN_TIMER_SECONDS (ff7_addresses.h) is savemap state, so it
 *   SURVIVES a save/load. Player report 2026-07-20: loading a save taken
 *   well after a timed escape had already completed (with time left on
 *   the clock, so the value never reached 0) made TimerThread treat that
 *   STALE, still-nonzero, still-ticking-in-the-background value as a
 *   brand new timer the instant it next ticked down a second — announcing
 *   "Timer started" in the slums, nowhere near an active escape. The
 *   value's behavior alone (nonzero, decrementing) can't distinguish a
 *   genuinely new countdown from leftover data a previous session saved
 *   that the game itself no longer shows anywhere (its on-screen clock
 *   window closed when the escape ended) but also never resets to 0.
 *
 *   A live STTIM call is the one unambiguous signal that a real countdown
 *   has (re)started. TimerThread only treats a nonzero timer value as
 *   "just started" (and only then begins announcing/tracking it) once
 *   this is true.
 *
 * RESIDUAL RISK: if a player reloads a save taken WHILE genuinely mid-
 * escape (a deliberate checkpoint/retry save), and the field's re-entry
 * logic does NOT call STTIM again on that load (unconfirmed either way),
 * this gate would also suppress announcements for that legitimate case
 * until STTIM does fire. Flagged for play verification, not fixed
 * speculatively — see TODO.txt.
 *
 * THREAD SAFETY: plain volatile LONG read; a monotonic latch needs no
 * read-modify-write atomicity, and aligned LONG access is atomic on x86.
 */
bool SttimSeen();

/*
 * TutorialActive / ClearTutorialActive (v2.30.27): nonzero from the
 * moment a TUTOR opcode (0x21, "play menu tutorial") fires until
 * MenuCursorThread observes MENU_OPEN back at 0 and calls the clear.
 * While active, hook_tutor has queued the tutorial's full text as a
 * narration and the menu announcement threads (main-menu cursor, Order
 * focus) must stand down: the tutorial script drives the cursor itself,
 * and announcing each scripted move with interrupting speech clobbers
 * the narration (the 2026-07-26 Materia-tutorial play report).
 */
bool TutorialActive();
void ClearTutorialActive();

} // namespace Hooks
