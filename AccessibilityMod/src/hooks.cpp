/*
 * hooks.cpp -- Implementation of all FF7 accessibility hooks.
 *
 * ----- HOOK POINTS IMPLEMENTED (v1) -----
 *
 *   [0x40] MESSAGE opcode  — field story dialog, speaks text on dialog start/page
 *   [0x48] ASK opcode      — choice menus, speaks full menu text on dialog start
 *
 * ----- V2 PLANNED -----
 *
 *   ASK per-option TTS:
 *     FFNx patches ff7_externals.opcode_ask + 0x8E to intercept the cursor-move
 *     inner loop (field_opcode_ask_update_loop_6310A1). We need that same call site.
 *     Problem: by the time our timeGetTime fires, FFNx has already replaced
 *     execute_opcode_table[0x48] with its own handler, so s_old_ask points to
 *     FFNx's compiled code — NOT FF7's original opcode_ask. Applying +0x8E to
 *     FFNx's handler is wrong (different layout, would corrupt code or crash).
 *     Fix in v2: hardcode the absolute address of FF7's opcode_ask CALL site
 *     (requires disassembly RE work), or scan memory for CALL 0x6310A1 within
 *     the known opcode_ask function range.
 *
 *   Battle TTS: display_battle_action_text_42782A, battle_menu_enter
 *   World map: world_opcode_message_sub_75EE86, world_opcode_ask_sub_75EEBB
 *   Main menu narration: MENU_OBJECTS cursor tracking
 *
 * ----- DIALOG DETECTION STRATEGY (v1.4) -----
 *
 *   New dialog (speak): dialog_id parameter changed for this window slot.
 *
 *     Every MESSAGE opcode carries two parameters: window_id (param[0]) and
 *     dialog_id (param[1]). dialog_id is a stable per-dialog identifier —
 *     it comes directly from the field script and does not change during the
 *     dialog's lifetime. When dialog_id changes for a given window, a new dialog
 *     just started on that window, regardless of what the state machine is doing.
 *
 *     We speak on the first hook call where BOTH conditions hold:
 *       (a) dialog_id != last spoken dialog_id for this window
 *       (b) the text pointer is readable and non-empty (0xFF = empty)
 *     Condition (b) requires a 1-frame delay because field_text_box_window_create
 *     is called INSIDE s_old_message() (not before), so on the first call for a
 *     new dialog_id the text pointer is still stale. By the second call (next
 *     game frame) the pointer has been set to the new dialog's text.
 *
 *   WHY THE PREVIOUS TEXT-POINTER DEBOUNCE FAILED:
 *     DIALOG_TEXT_PTRS[window_id] (0xCBF578) is a volatile typewriter pointer:
 *     the game updates it word-by-word as the typewriter animation progresses,
 *     then resets it to a 0xFF-terminated buffer when the dialog closes. This
 *     means the pointer is NEVER stable for 8+ consecutive frames while the
 *     typewriter is running, and by the time it IS stable (pointing to 0xFF
 *     after close), the dialog has already been dismissed. The debounce reliably
 *     fired 5-10 seconds late with no usable text.
 *
 *   WHY THE PREVIOUS STATE MACHINE DETECTION FAILED FOR WIN=2:
 *     The state byte at opcode_message_loop_code[24 * window_id] transitions
 *     correctly for win=0 (0→1→2→6→7→0) and win=1 (0→5→12→...→97→0).
 *     For win=2 (Barret's first line, Jessie's lines, mission briefing),
 *     the state byte NEVER changes — the hook is called every frame but
 *     current_state == last_state always, so the "starting" condition never
 *     fired and those dialogs were entirely silenced.
 *
 *   State machine is STILL used for:
 *     - Speaking the primary path for win=0/1 where "starting" reliably fires
 *       (the state machine provides earlier detection for those windows)
 *     - Page advance speaking (14→2, 4→8 transitions)
 *     - Closing detection (→7 transition): silence TTS and reset dialog tracking
 *
 *   Note: "closing" (→7) may not fire for all windows (e.g., win=2). For those
 *   windows, last_dialog_id is effectively reset when the next dialog's id differs.
 *
 * ----- ASK (v1) DESIGN -----
 *
 *   Speaks the full ASK dialog text (question + all option lines) once when
 *   the dialog first appears. Uses the same dialog_id tracking as MESSAGE.
 *   Per-option TTS on cursor movement is deferred to v2.
 *
 *   ASK opcode parameter layout (FF7 field script spec):
 *     param[0] = bank, param[1] = window_id, param[2] = dialog_id,
 *     param[3] = address_in_bank, param[4] = first_option, param[5] = last_option
 *
 * Sources: FFNx/src/voice.cpp (opcode_voice_message, opcode_voice_ask)
 *          FFNx/src/field.h   (get_field_parameter)
 *          FFNx/src/ff7_data.h (opcode table resolution chain)
 */

#include "hooks.h"
#include "ff7_addresses.h"
#include "ff7_text.h"
#include "tts.h"
#include "config.h"
#include "log.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <string>

namespace Hooks {

// ---------------------------------------------------------------------------
// patch_dword: Overwrite a 32-bit value at a given address.
//
// Used to replace function pointer entries in the opcode dispatch table.
// The table lives in a data segment; VirtualProtect guards against rare
// read-only configurations (e.g., hardened OS settings).
// ---------------------------------------------------------------------------
static void patch_dword(uint32_t addr, uint32_t new_value)
{
    DWORD old_protect = 0;
    VirtualProtect(reinterpret_cast<LPVOID>(addr), sizeof(uint32_t),
                   PAGE_EXECUTE_READWRITE, &old_protect);
    *reinterpret_cast<uint32_t*>(addr) = new_value;
    VirtualProtect(reinterpret_cast<LPVOID>(addr), sizeof(uint32_t),
                   old_protect, &old_protect);
}

// ---------------------------------------------------------------------------
// Saved original function pointers
//
// Before installing our hooks we save the current value in each slot.
// FFNx completes ff7_init_hooks during early game startup — well before our
// background thread's 200ms sleep elapses and Install() is called. So these
// saved values point to FFNx's handlers, not the bare FF7 originals.
// Chaining through them means both FFNx voice acting and our TTS fire correctly.
// ---------------------------------------------------------------------------

// Saved opcode table entry for MESSAGE (0x40).
// Calling convention: __cdecl, no parameters — handler reads script state directly.
static int (__cdecl* s_old_message)() = nullptr;

// Saved opcode table entry for ASK (0x48).
// The int parameter is passed by the opcode dispatcher (opaque, forwarded unchanged).
static int (__cdecl* s_old_ask)(int) = nullptr;

// ---------------------------------------------------------------------------
// Per-window dialog state tracking
//
// The game supports up to 8 simultaneous dialog windows (window IDs 0–7).
// We maintain a parallel state struct for each to detect transitions.
// ---------------------------------------------------------------------------
struct WindowState {
    // State byte from the previous frame. Used to detect state machine transitions
    // (starting, paging, closing) by comparing last vs. current each frame.
    uint8_t last_opcode    = 0;

    // Pages spoken so far on the current dialog (reserved for v2 multi-page TTS).
    uint8_t page_count     = 0;

    // The dialog_id we most recently spoke for this window slot (0xFF = none spoken yet).
    // When dialog_id changes from what we last spoke, a new dialog is starting.
    //
    // WHY 0xFF AS SENTINEL: dialog_id is a field script parameter ranging 0–254.
    // 0xFF is not a valid dialog_id (it would require 256 dialogs in one field file,
    // which FF7 never approaches). Initialising to 0xFF ensures the first dialog on
    // any window is always detected as "new" regardless of its actual id.
    uint8_t last_dialog_id = 0xFF;
};
static WindowState s_window[8];

// Whether our hooks are currently installed.
static bool s_installed = false;

// ---------------------------------------------------------------------------
// is_readable_ptr: Return true if ptr is a valid, readable memory address.
//
// WHY THIS IS NEEDED:
//   DIALOG_TEXT_PTRS[window_id] can contain a stale non-null pointer from a
//   previous dialog after the game closes a window and opens a new one
//   (especially for TUTOR-opcode windows which use the same DIALOG_TEXT_PTRS
//   slots but may not reset them). FF7Text::Decode dereferences the pointer
//   immediately, so a stale pointer to unmapped memory causes an access
//   violation before the 4096-byte safety cap in Decode can help.
//
//   VirtualQuery is the Windows-recommended way to test whether a range of
//   addresses is readable. It is not fast (~microsecond), but this function
//   is only called when a dialog starts or pages — a rare event.
// ---------------------------------------------------------------------------
static bool is_readable_ptr(const void* ptr)
{
    if (!ptr) return false;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) return false;
    // Memory must be committed and not have access-denied or guard protection.
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Hook: MESSAGE opcode (0x40)
//
// Called every game frame while a MESSAGE dialog window is open.
// FF7's field script VM calls execute_opcode_table[0x40]() on each frame
// until the player dismisses the dialog.
//
// ----- DETECTION STRATEGY (v1.4): DIALOG_ID TRACKING -----
//
// PRIMARY trigger (new dialog for win=0/1): state machine 0→N or 7→N transition.
//   Works reliably for windows whose state byte follows standard sequences.
//   Provides 1-frame earlier detection than the fallback path for those windows.
//
// FALLBACK trigger (new dialog for win=2 and others): dialog_id parameter changed.
//   dialog_id is read from the field script opcode parameters (param[1]).
//   It is stable throughout a dialog and changes only when a new MESSAGE opcode
//   executes. The fallback fires 1 frame after the state changes because the text
//   pointer is set inside s_old_message() (not before), so on the first call with
//   a new dialog_id the text is still stale — we retry until it reads as valid.
//
// PAGING trigger: state machine 14→2 or 4→8 transition.
//
// CLOSE trigger: state machine →7. Also resets dialog_id tracking for next dialog.
//
// Calling convention: __cdecl (confirmed from FFNx's opcode_voice_message).
// ---------------------------------------------------------------------------
static int __cdecl hook_message()
{
    // Log on the first call ever — confirms the hook is reached and active.
    static bool s_first_call_logged = false;
    if (!s_first_call_logged) {
        s_first_call_logged = true;
        Log::Write("[FF7Access] hook_message: first call (hook chain active).");
    }

    // Heartbeat every 500 calls: confirms the hook is still being called
    // during stretches where no new-dialog events are detected.
    static uint32_t s_call_count = 0;
    if ((++s_call_count % 500) == 0) {
        char hb[64];
        _snprintf_s(hb, sizeof(hb), _TRUNCATE,
            "[FF7Access] MSG heartbeat: calls=%u", s_call_count);
        Log::Write(hb);
    }

    // Read the window_id from the current opcode's first parameter byte.
    // get_opcode_param_byte(0) replicates FFNx's get_field_parameter<byte>(0):
    //   script[field_curr_script_position[current_entity_id] + 1]
    // Source: FFNx voice.cpp opcode_voice_message line 397.
    const uint8_t window_id = FF7Addr::get_opcode_param_byte(0);

    // Read the dialog_id from the second parameter. This identifies WHICH dialog
    // in the field's text section is being shown. It is stable for the lifetime
    // of this dialog and changes when the script advances to the next MESSAGE.
    // Source: FFNx voice.cpp opcode_voice_message line 398 (get_field_parameter<byte>(1)).
    const uint8_t dialog_id = FF7Addr::get_opcode_param_byte(1);

    if (window_id >= 8) {
        // Out-of-range: either get_opcode_param_byte is reading wrong memory, or
        // this entity uses a banked/variable window_id outside the 0–7 range.
        // Deduplicated by value to avoid flooding the log during repeated bad reads.
        // s_last_bad starts at 0xFE (not 0xFF) so that window_id=0xFF is always
        // logged on first occurrence — 0xFF is a plausible sentinel that the game
        // might use, and initialising to 0xFF would silently suppress it forever.
        static uint8_t s_last_bad = 0xFE;
        if (window_id != s_last_bad) {
            char dbg[80];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] MSG win_id OOB: 0x%02X -- dialog silently skipped!", window_id);
            Log::Write(dbg);
            s_last_bad = window_id;
        }
    } else {
        // Read the current dialog text pointer BEFORE calling the chain.
        // On the FIRST call for a new dialog (when dialog_id just changed),
        // this value is stale from the previous dialog because
        // field_text_box_window_create_631586 hasn't run yet (it runs inside
        // s_old_message()). We use it for the state machine's primary path
        // (which has a 1-frame delay anyway), and the fallback checks it for
        // validity before speaking.
        const char* raw_text = FF7Addr::get_dialog_text_ptr(window_id);

        // ------------------------------------------------------------------
        // STATE MACHINE: detect starting, paging, and closing transitions.
        //
        // The state byte at opcode_message_loop_code[24 * window_id] describes
        // which phase of the dialog update loop the window is in.
        //
        // We read state BEFORE calling s_old_message() — the state transitions
        // happen inside the call. So what we see here is the state from the
        // PREVIOUS frame's update. The current_state reflects what the
        // PREVIOUS frame's s_old_message() left the state machine in.
        // This 1-frame delay is intentional and consistent with the PRIMARY
        // state machine speak path: on the frame where the state transitions
        // from 0→N, current_state (just set by the previous frame) = N,
        // and last_state (saved at end of previous hook call) = 0 → "starting".
        // ------------------------------------------------------------------
        const uint8_t current_state = FF7Addr::get_dialog_state(window_id);
        const uint8_t last_state    = s_window[window_id].last_opcode;

        const bool starting = ((last_state == 0 || last_state == 7) &&
                               current_state != 0 && current_state != 7);
        const bool paging   = (last_state == 14 && current_state == 2) ||
                              (last_state == 4  && current_state == 8);
        const bool closing  = (last_state != 7 && current_state == 7);

        // Log all state transitions for diagnostic visibility.
        if (current_state != last_state) {
            const char* tag = starting ? "START" : paging ? "PAGE" :
                              closing  ? "CLOSE" : "skip";
            char state_log[80];
            _snprintf_s(state_log, sizeof(state_log), _TRUNCATE,
                "[FF7Access] MSG win=%u %u->%u [%s]",
                window_id, last_state, current_state, tag);
            Log::Write(state_log);
        }

        // ------------------------------------------------------------------
        // PRIMARY SPEAK: state machine "starting" — fires for win=0, win=1.
        //
        // WHY THIS IS THE PRIMARY PATH:
        //   For win=0 (standard lifecycle) and win=1 (counting sequence), the
        //   state machine reliably transitions through state 0 between dialogs.
        //   The "starting" condition (last==0||7 → current≠0,7) fires exactly
        //   once per new dialog, at the correct moment. The text pointer is
        //   valid at this point (set by the previous frame's s_old_message()).
        //
        // WHY WE CHECK dialog_id != last_dialog_id HERE:
        //   On the frame where state transitions to 0 (dialog closing), the
        //   FALLBACK path below fires first (state=0 → starting=false, dialog_id
        //   is already the new dialog's id → DLGID path speaks and sets
        //   last_dialog_id). On the NEXT frame, the state transitions 0→N, so
        //   starting becomes true. Without the last_dialog_id guard, PRIMARY would
        //   speak the same dialog a second time. The guard prevents this: if DLGID
        //   already spoke this dialog_id, PRIMARY skips. If DLGID did NOT speak it
        //   (e.g., the text was unavailable on that frame), PRIMARY speaks instead.
        // ------------------------------------------------------------------
        if (starting && Config::Get().speak_dialog &&
            dialog_id != s_window[window_id].last_dialog_id) {
            if (is_readable_ptr(raw_text)) {
                const std::wstring decoded = FF7Text::Decode(raw_text);
                if (!decoded.empty()) {
                    char dbg[80];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] MSG win=%u id=%u [START] speaking", window_id, dialog_id);
                    Log::Write(dbg);
                    TTS::Speak(decoded, /*interrupt=*/true);
                    // Sync fallback tracker: this dialog is now spoken.
                    s_window[window_id].last_dialog_id = dialog_id;
                } else {
                    char dbg[80];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] MSG win=%u [START] decoded empty (raw[0]=0x%02X)",
                        window_id, (uint8_t)raw_text[0]);
                    Log::Write(dbg);
                }
            } else {
                char dbg[80];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] MSG win=%u [START] text ptr null/invalid", window_id);
                Log::Write(dbg);
            }
        }
        // ------------------------------------------------------------------
        // FALLBACK SPEAK: dialog_id changed — fires for all windows where
        // the state machine does not produce a "starting" transition first.
        //
        // WHY THIS CATCHES WHAT THE STATE MACHINE MISSES:
        //   For win=2 (Barret "C'mon newcomer", Jessie's lines, mission
        //   briefing), opcode_message_loop_code[24*2] NEVER changes — the
        //   "starting" condition therefore never fires. For win=0 and win=1,
        //   this path fires one frame BEFORE "starting" (on the state=0 frame,
        //   where starting=false). The PRIMARY guard above then skips the START
        //   speak if last_dialog_id was already updated here.
        //
        // TEXT SOURCE SELECTION:
        //   1. get_field_dialog_text(dialog_id): reads from the static field text
        //      section (section 8 of the field file buffer). Gives complete text
        //      at any time, independent of typewriter animation state. Preferred.
        //   2. Fallback: DIALOG_TEXT_PTRS[window_id] (volatile typewriter pointer).
        //      Used only when the field text section is unavailable (field not yet
        //      loaded, dialog_id out of range for this field, or wrong section index).
        //      Less reliable (may be mid-animation or stale from a previous scene)
        //      but prevents dialogs from being silently dropped when method 1 fails.
        // ------------------------------------------------------------------
        else if (dialog_id != s_window[window_id].last_dialog_id &&
                 Config::Get().speak_dialog) {

            // ---- One-time field buffer diagnostic ----
            // Logs the buffer base and script section address once per session.
            // Confirmed: dialog text is embedded in section 0 (the script section).
            // get_field_dialog_text() correctly skips section 0 and returns nullptr
            // for all other sections, so the rawptr path handles all dialogs.
            static bool s_buf_diag_logged = false;
            if (!s_buf_diag_logged) {
                s_buf_diag_logged = true;
                const char* const buf =
                    *reinterpret_cast<const char* const*>(FF7Addr::FIELD_FILE_BUFFER);
                const char* const script_data =
                    *reinterpret_cast<const char* const*>(FF7Addr::FIELD_SCRIPT_PTR);
                if (buf) {
                    char diag[120];
                    _snprintf_s(diag, sizeof(diag), _TRUNCATE,
                        "[FF7Access] field buf=0x%X script_data=0x%X (text embedded in script section)",
                        (uint32_t)buf, (uint32_t)script_data);
                    Log::Write(diag);
                } else {
                    Log::Write("[FF7Access] field buf=null at first DLGID");
                }
            }

            // ---- Text source selection ----
            const char* static_text = FF7Addr::get_field_dialog_text(dialog_id);
            const char* text_to_use = static_text;
            const char* source_tag  = "sect";

            if (!text_to_use) {
                // Field text section unavailable. Fall back to volatile typewriter ptr.
                //
                // BOUNDS CHECK: valid dialog text pointers are always within the
                // loaded field file buffer. Any pointer outside this range (e.g.,
                // the TUTOR window's rawptr pointing to field script bytecode, or
                // a stale pointer from a previous field) is garbage. Validating
                // against the buffer bounds prevents reading binary script data as
                // if it were dialog text and producing garbled TTS output.
                const char* const field_buf =
                    *reinterpret_cast<const char* const*>(FF7Addr::FIELD_FILE_BUFFER);
                const bool in_field_buf = (field_buf != nullptr)
                    && (raw_text >= field_buf)
                    && (raw_text <  field_buf + 512u * 1024u);

                if (in_field_buf && is_readable_ptr(raw_text)
                    && (uint8_t)raw_text[0] != 0xFF) {
                    text_to_use = raw_text;
                    source_tag  = "rawptr";
                    // Log the offset so we can identify which section this falls in.
                    char ptr_diag[100];
                    _snprintf_s(ptr_diag, sizeof(ptr_diag), _TRUNCATE,
                        "[FF7Access] DIAG rawptr: win=%u id=%u buf_off=0x%X",
                        window_id, dialog_id, (uint32_t)(raw_text - field_buf));
                    Log::Write(ptr_diag);
                }
            }

            if (text_to_use) {
                const std::wstring decoded = FF7Text::Decode(text_to_use);
                if (!decoded.empty()) {
                    char dbg[100];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] MSG win=%u id=%u [DLGID/%s] speaking",
                        window_id, dialog_id, source_tag);
                    Log::Write(dbg);
                    TTS::Speak(decoded, /*interrupt=*/true);
                    s_window[window_id].last_dialog_id = dialog_id;
                } else {
                    char dbg[100];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] MSG win=%u id=%u [DLGID/%s] decoded empty",
                        window_id, dialog_id, source_tag);
                    Log::Write(dbg);
                    // Do not update last_dialog_id — retry next frame.
                }
            } else {
                // Both methods failed. Log so we can diagnose which fields or
                // dialog_ids are affected.
                char dbg[80];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] MSG win=%u id=%u [DLGID] no text (sect+rawptr both fail)",
                    window_id, dialog_id);
                Log::Write(dbg);
            }
        }
        // ------------------------------------------------------------------
        // PAGE ADVANCE: speak the current page's text when the player pages.
        // ------------------------------------------------------------------
        else if (paging && Config::Get().speak_dialog) {
            // Page advance: speak immediately, the text pointer is valid at this point.
            if (is_readable_ptr(raw_text)) {
                const std::wstring decoded = FF7Text::Decode(raw_text);
                if (!decoded.empty()) {
                    TTS::Speak(decoded, /*interrupt=*/true);
                }
            }
            s_window[window_id].page_count++;
        }
        // ------------------------------------------------------------------
        // DIALOG CLOSE: silence TTS and reset tracking for next dialog.
        // ------------------------------------------------------------------
        else if (closing) {
            // Reset last_dialog_id so the same dialog_id is detected as "new"
            // if it is shown again (e.g., the same NPC is talked to twice).
            s_window[window_id].last_dialog_id = 0xFF;
            TTS::Silence();
        }

        s_window[window_id].last_opcode = current_state;
    }

    // Chain unconditionally: FFNx voice handler (or FF7 original) must always fire.
    return s_old_message();
}

// ---------------------------------------------------------------------------
// Hook: ASK opcode (0x48)
//
// Called every frame while a choice-menu dialog is open.
//
// v1 behavior: speak the full ASK dialog text (question + all options) once
// when the menu first appears. Uses the same dialog_id tracking as hook_message.
// Per-option TTS on cursor movement is deferred to v2.
//
// ASK WINDOW_ID IS AT PARAMETER INDEX 1 (not 0):
//   FFNx voice.cpp opcode_voice_ask (line 462): get_field_parameter<byte>(1).
//   ASK param layout: param[0]=bank, param[1]=window_id, param[2]=dialog_id.
//
// ASK DIALOG_ID IS AT PARAMETER INDEX 2:
//   FFNx voice.cpp opcode_voice_ask (line 463): get_field_parameter<byte>(2).
// ---------------------------------------------------------------------------
static int __cdecl hook_ask(int unk)
{
    // window_id is at ASK parameter index 1. Source: FFNx voice.cpp line 462.
    const uint8_t window_id = FF7Addr::get_opcode_param_byte(1);
    // dialog_id is at ASK parameter index 2. Source: FFNx voice.cpp line 463.
    const uint8_t dialog_id = FF7Addr::get_opcode_param_byte(2);

    if (window_id >= 8) {
        static uint8_t s_last_bad = 0xFE;  // not 0xFF — see MSG hook comment
        if (window_id != s_last_bad) {
            char dbg[80];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] ASK win_id OOB: 0x%02X -- choice menu silently skipped!", window_id);
            Log::Write(dbg);
            s_last_bad = window_id;
        }
    } else {
        const char* raw_text = FF7Addr::get_dialog_text_ptr(window_id);

        // State machine for close detection and log visibility.
        const uint8_t current_state = FF7Addr::get_dialog_state(window_id);
        const uint8_t last_state    = s_window[window_id].last_opcode;

        const bool starting = ((last_state == 0 || last_state == 7) &&
                               current_state != 0 && current_state != 7);
        const bool closing  = (last_state != 7 && current_state == 7);

        if (current_state != last_state) {
            const char* tag = starting ? "START" : closing ? "CLOSE" : "skip";
            char state_log[80];
            _snprintf_s(state_log, sizeof(state_log), _TRUNCATE,
                "[FF7Access] ASK win=%u %u->%u [%s]",
                window_id, last_state, current_state, tag);
            Log::Write(state_log);
        }

        // PRIMARY: state machine detected menu open (reliable when it fires).
        // Guard with dialog_id != last_dialog_id: the DLGID fallback (below) fires
        // one frame before PRIMARY on the state=0 frame. Without this guard,
        // PRIMARY would speak the same ASK dialog a second time.
        if (starting && Config::Get().speak_choices &&
            dialog_id != s_window[window_id].last_dialog_id) {
            if (is_readable_ptr(raw_text)) {
                const std::wstring decoded = FF7Text::Decode(raw_text);
                if (!decoded.empty()) {
                    char dbg[80];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] ASK win=%u id=%u [START] speaking", window_id, dialog_id);
                    Log::Write(dbg);
                    std::wstring announcement = L"Choose: ";
                    announcement += decoded;
                    TTS::Speak(announcement, /*interrupt=*/true);
                    s_window[window_id].last_dialog_id = dialog_id;
                }
            }
        }
        // FALLBACK: dialog_id changed. Try static field text section first;
        // fall back to volatile typewriter pointer if unavailable.
        else if (dialog_id != s_window[window_id].last_dialog_id &&
                 Config::Get().speak_choices) {
            const char* static_text = FF7Addr::get_field_dialog_text(dialog_id);
            const char* text_to_use = static_text;
            const char* source_tag  = "sect";
            if (!text_to_use) {
                const char* const field_buf =
                    *reinterpret_cast<const char* const*>(FF7Addr::FIELD_FILE_BUFFER);
                const bool in_field_buf = (field_buf != nullptr)
                    && (raw_text >= field_buf)
                    && (raw_text <  field_buf + 512u * 1024u);
                if (in_field_buf && is_readable_ptr(raw_text)
                    && (uint8_t)raw_text[0] != 0xFF) {
                    text_to_use = raw_text;
                    source_tag  = "rawptr";
                }
            }
            if (text_to_use) {
                const std::wstring decoded = FF7Text::Decode(text_to_use);
                if (!decoded.empty()) {
                    char dbg[100];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] ASK win=%u id=%u [DLGID/%s] speaking",
                        window_id, dialog_id, source_tag);
                    Log::Write(dbg);
                    std::wstring announcement = L"Choose: ";
                    announcement += decoded;
                    TTS::Speak(announcement, /*interrupt=*/true);
                    s_window[window_id].last_dialog_id = dialog_id;
                }
            }
        }
        else if (closing) {
            s_window[window_id].last_dialog_id = 0xFF;
            TTS::Silence();
        }

        s_window[window_id].last_opcode = current_state;
    }

    return s_old_ask(unk);
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

bool Install()
{
    if (s_installed) return true;

    // Resolve runtime addresses (opcode table, dialog state array, etc.).
    // Returns false if the game hasn't finished initializing yet.
    if (!FF7Addr::Resolve()) return false;

    // --- MESSAGE hook (opcode 0x40) ---
    //
    // Save the current table entry (FFNx's handler, if FFNx loaded before us)
    // and replace it with our hook. The table entry is a DWORD-sized function
    // pointer at address: &execute_opcode_table[0x40].
    const uint32_t msg_entry_addr =
        reinterpret_cast<uint32_t>(FF7Addr::execute_opcode_table) + 0x40 * sizeof(uint32_t);

    s_old_message = reinterpret_cast<int (__cdecl*)()>(
        *reinterpret_cast<uint32_t*>(msg_entry_addr));
    patch_dword(msg_entry_addr, reinterpret_cast<uint32_t>(&hook_message));

    // --- ASK hook (opcode 0x48) ---
    //
    // Same pattern as MESSAGE. The ASK dispatcher entry is at table index 0x48.
    const uint32_t ask_entry_addr =
        reinterpret_cast<uint32_t>(FF7Addr::execute_opcode_table) + 0x48 * sizeof(uint32_t);

    s_old_ask = reinterpret_cast<int (__cdecl*)(int)>(
        *reinterpret_cast<uint32_t*>(ask_entry_addr));
    patch_dword(ask_entry_addr, reinterpret_cast<uint32_t>(&hook_ask));

    s_installed = true;
    Log::Write("[FF7Access] Hooks installed (MESSAGE+ASK opcode table).");
    return true;
}

void Uninstall()
{
    if (!s_installed) return;
    if (!FF7Addr::execute_opcode_table) return;

    // Restore MESSAGE entry.
    const uint32_t msg_entry_addr =
        reinterpret_cast<uint32_t>(FF7Addr::execute_opcode_table) + 0x40 * sizeof(uint32_t);
    if (s_old_message) {
        patch_dword(msg_entry_addr, reinterpret_cast<uint32_t>(s_old_message));
    }

    // Restore ASK entry.
    const uint32_t ask_entry_addr =
        reinterpret_cast<uint32_t>(FF7Addr::execute_opcode_table) + 0x48 * sizeof(uint32_t);
    if (s_old_ask) {
        patch_dword(ask_entry_addr, reinterpret_cast<uint32_t>(s_old_ask));
    }

    s_installed = false;
}

} // namespace Hooks
