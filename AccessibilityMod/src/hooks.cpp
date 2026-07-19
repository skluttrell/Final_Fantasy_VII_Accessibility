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
// log_raw_bytes: Dump the first 18 raw bytes of a dialog text pointer as hex.
//
// Pairing this with every "MSG ... speaking" log entry lets us trace any NVDA
// utterance to its exact log line: look up each hex byte in the FF7 character
// table (ff7_text.cpp kExtendedChars / byte+0x20 formula) to reconstruct the
// decoded text. Examples:
//   EB → Barret speaker prefix
//   27 45 54 00 → G e t (space) → "Get..."
//   4F 42 54 41 → O b t a → "Obta..." (Obtained óPotion)
//
// path_tag: label embedded in the log line, e.g. "START/sect" or "DLGID/rawptr".
// Called only when decoded is non-empty, so text[0] != 0xFF is guaranteed.
// ---------------------------------------------------------------------------
static void log_raw_bytes(const char* path_tag, const char* text)
{
    char hex[72] = {}; int n = 0;
    for (int i = 0; i < 18; ++i) {
        const uint8_t b = reinterpret_cast<const uint8_t*>(text)[i];
        if (b == 0xFF) break;
        n += _snprintf_s(hex + n, (int)sizeof(hex) - n, _TRUNCATE, "%02X ", b);
    }
    if (n > 0) hex[n - 1] = '\0'; // trim trailing space
    char line[140];
    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[FF7Access] MSG raw(%s): %s", path_tag, hex);
    Log::Write(line);
}

// ---------------------------------------------------------------------------
// log_field_header_if_changed: Log the 16-byte ff7_field_script_header once
// per field load.
//
// Field changes are detected by comparing FIELD_FILE_BUFFER against the last
// logged address. A new field always allocates a new buffer (different pointer),
// so pointer equality is a reliable change detector.
//
// Called from the DLGID path (dialog_id change detection) — a field change
// always precedes the first dialog of any new field, so the header is logged
// at most one frame before the first dialog speak event.
// ---------------------------------------------------------------------------
static void log_field_header_if_changed()
{
    static const char* s_last_buf = nullptr;
    const char* const buf =
        *reinterpret_cast<const char* const*>(FF7Addr::FIELD_FILE_BUFFER);
    const char* const sd =
        *reinterpret_cast<const char* const*>(FF7Addr::FIELD_SCRIPT_PTR);
    if (!buf || buf == s_last_buf) return;
    s_last_buf = buf;

    if (sd) {
        const uint8_t* h = reinterpret_cast<const uint8_t*>(sd);
        char diag[220];
        _snprintf_s(diag, sizeof(diag), _TRUNCATE,
            "[FF7Access] FIELD buf=0x%X sd=0x%X "
            "hdr=[%02X %02X %02X %02X | %02X %02X | %02X %02X | %02X %02X %02X %02X %02X %02X %02X %02X]",
            (uint32_t)buf, (uint32_t)sd,
            h[0],  h[1],  h[2],  h[3],  // unknown1 (WORD), nEntities, nModels
            h[4],  h[5],                 // wStringOffset (WORD)
            h[6],  h[7],                 // nAkaoOffsets (WORD)
            h[8],  h[9],  h[10], h[11], h[12], h[13], h[14], h[15]); // scale + padding
        Log::Write(diag);
    } else {
        char diag[72];
        _snprintf_s(diag, sizeof(diag), _TRUNCATE,
            "[FF7Access] FIELD buf=0x%X sd=null", (uint32_t)buf);
        Log::Write(diag);
    }
}

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

    // Set when a new dialog_id is detected; cleared after rawptr is read and spoken.
    //
    // WHY ONE-FRAME DELAY:
    //   DIALOG_TEXT_PTRS[window_id] is written by field_text_box_window_create_631586,
    //   which runs INSIDE s_old_message() — at the END of our hook. On the frame where
    //   dialog_id first changes, the rawptr still holds the previous dialog's pointer.
    //   We set pending_speak=true and defer the read to the NEXT frame, by which time
    //   s_old_message() has already updated the rawptr to the correct dialog text.
    bool pending_speak = false;

    // v2.30.3: the full decoded text spoken so far for THIS dialog. FF7's
    // rawptr holds the COMPLETE multi-page message (page breaks 0xE8/0xE9
    // included), and Decode reads all pages as one string — so the START
    // speak already covers everything. The paging state machine then spoke
    // the whole message AGAIN on each page advance, so long dialogs
    // re-read content when the player pressed to continue (player report
    // 2026-07-19). We now speak only the part not already spoken: on a
    // page advance whose decoded text equals what we already said, nothing
    // is spoken; if the text grew (streamed load), only the new suffix is.
    // Cleared on new dialog and on close.
    std::wstring last_spoken;
};
static WindowState s_window[8];

// Whether our hooks are currently installed.
static bool s_installed = false;

// GetTickCount() timestamp of the most recent MESSAGE/ASK hook invocation.
// The field VM calls these handlers every frame while a dialog window is
// open, so recency of this tick is a reliable "some dialog is open" signal
// (see Hooks::LastDialogActivityTick in hooks.h for why the state-byte array
// cannot be used instead). DWORD write is atomic on x86 (4-byte aligned);
// volatile stops the compiler caching it across the two threads involved
// (game main thread writes, WallBumpThread reads).
static volatile DWORD s_last_dialog_tick = 0;

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
// is_valid_dialog_rawptr: Check that a DIALOG_TEXT_PTRS pointer is safe to
// decode as dialog text.
//
// We accept rawptrs from ANY section of the field file, not just section 0.
// dialog_id in MESSAGE opcodes is entity-relative: different entity scripts
// can use the same dialog_id to reference text in different field sections.
// The engine sets DIALOG_TEXT_PTRS[window_id] directly to the correct section's
// text for the currently-executing entity, so restricting to section 0 bounds
// would incorrectly reject valid text from other sections.
//
// WHY NO wStringOffset BOUNDS:
//   Previous versions used script_data+wStringOffset as a lower bound to reject
//   entity bytecode. That check is unnecessary here because by the time this
//   function is called (the frame AFTER dialog_id changed), s_old_message() has
//   already updated the rawptr to the actual dialog string — it won't be pointing
//   at bytecode. The one-frame pending delay (see pending_speak in WindowState)
//   eliminates the stale-rawptr problem that originally motivated the bounds check.
// ---------------------------------------------------------------------------
static bool is_valid_dialog_rawptr(const char* raw_text)
{
    if (!raw_text) return false;

    // Must be within the loaded field file buffer (any section).
    const char* const field_buf =
        *reinterpret_cast<const char* const*>(FF7Addr::FIELD_FILE_BUFFER);
    if (!field_buf) return false;
    if (raw_text < field_buf || raw_text >= field_buf + 512u * 1024u) return false;

    // Memory must be committed/readable, and the string non-empty.
    if (!is_readable_ptr(raw_text)) return false;
    if ((uint8_t)raw_text[0] == 0xFF) return false;

    return true;
}

// ---------------------------------------------------------------------------
// Hook: MESSAGE opcode (0x40)
//
// Called every game frame while a MESSAGE dialog window is open.
// FF7's field script VM calls execute_opcode_table[0x40]() on each frame
// until the player dismisses the dialog.
//
// ----- DETECTION STRATEGY (v1.5): PENDING RAWPTR -----
//
// TRIGGER: dialog_id parameter changed (fires for ALL windows, no state machine split).
//   On the trigger frame, set pending_speak=true and update last_dialog_id.
//   Do NOT speak yet — the rawptr is stale until s_old_message() runs (end of hook).
//
// SPEAK: next frame, pending_speak=true → read rawptr → speak if valid.
//
// WHY RAWPTR ONLY (no section lookup):
//   dialog_id is entity-relative. Two different entity scripts can both use
//   dialog_id=N to reference different text in different field file sections.
//   get_field_dialog_text() indexes section 0's table at wStringOffset, which
//   returns the wrong text when the active entity's dialog lives in another section.
//   Observed: Field 2 id=6 → section 0 has "Obtained óPotion!", Barret's entity
//   has "Get down here, Merc!" in a different section. The rawptr is the only
//   authoritative source — the engine sets it to the correct section's text.
//
// PAGING trigger: state machine 14→2 or 4→8 transition.
//
// CLOSE trigger: state machine →7. Clears pending and resets dialog_id tracking.
//
// Calling convention: __cdecl (confirmed from FFNx's opcode_voice_message).
// ---------------------------------------------------------------------------
// v2.30.3: speak only the part of `decoded` not already covered by `already`
// (the text spoken so far this dialog), then record `already = decoded`.
// Kills the paging duplication: on a page advance whose text equals what we
// already said, nothing is spoken; if the message grew (streamed load), only
// the new suffix is. Diverging text (a genuinely new page that doesn't extend
// the old) is spoken in full.
static void speak_incremental(const std::wstring& decoded,
                              std::wstring& already, bool interrupt)
{
    std::wstring to_speak;
    if (!already.empty() && decoded.size() >= already.size() &&
        decoded.compare(0, already.size(), already) == 0)
        to_speak = decoded.substr(already.size());   // grew (or identical -> "")
    else
        to_speak = decoded;                           // fresh or diverged
    already = decoded;
    const auto first = to_speak.find_first_not_of(L' ');
    if (first == std::wstring::npos)
        return;                                       // nothing new to say
    TTS::Speak(to_speak.substr(first), interrupt);
}

static int __cdecl hook_message()
{
    // v2.30.2: dialog-activity is stamped BELOW, only for a REAL text dialog
    // (valid rawptr), NOT on every call. WHY THE CHANGE: this hook is on the
    // message-window UPDATE LOOP, which runs every frame while ANY field
    // window is open — including the countdown-clock special window (WSPCL)
    // shown during a timed escape. The old unconditional stamp therefore
    // kept s_last_dialog_tick fresh every frame for the whole escape, which
    // permanently suppressed the wall + proximity tones (player report
    // 2026-07-19; the log's MSG heartbeat proved this loop ran ~30/sec with
    // ZERO dialog transitions during the escape — a steady non-text window).
    // A real MESSAGE dialog has valid rawptr text; the numeric clock does
    // not, so the stamp is now gated on that (plus OOB banked dialogs, which
    // the clock is not — its window_id is in-range 0-7).

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
        // v2.30.2: a banked/variable window_id is still a REAL dialog opcode
        // executing (field frozen) — keep the tones silent. The clock is
        // never OOB (log shows in-range 0-7), so this can't re-admit it.
        s_last_dialog_tick = GetTickCount();
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

        // v2.30.2: stamp dialog-activity ONLY when this window actually holds
        // message text — that is what a walking-suppressing dialog is. The
        // countdown-clock window fails this (numeric WSPCL, no message text
        // at its slot), so it no longer freezes the wall/proximity tones.
        const bool has_dialog_text = is_valid_dialog_rawptr(raw_text);
        if (has_dialog_text)
            s_last_dialog_tick = GetTickCount();

        // Diagnostic (throttled): reveals the clock window's signature during
        // a timed escape — window_id, state, and whether we stamped — so the
        // next timed sequence confirms the fix (or names a residual).
        static uint32_t s_diag_count = 0;
        if ((++s_diag_count % 180) == 0) {
            char diag[96];
            _snprintf_s(diag, sizeof(diag), _TRUNCATE,
                "[FF7Access] MSG steady win=%u state=%u text=%d",
                window_id, current_state, has_dialog_text ? 1 : 0);
            Log::Write(diag);
        }

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
        // NEW DIALOG: set pending flag, do not speak yet.
        //
        // The rawptr (DIALOG_TEXT_PTRS[window_id]) is stale on this frame —
        // s_old_message() hasn't run yet (called at the bottom of this hook).
        // We defer reading until next frame when rawptr is guaranteed fresh.
        // ------------------------------------------------------------------
        if (dialog_id != s_window[window_id].last_dialog_id &&
            Config::Get().speak_dialog) {
            log_field_header_if_changed();
            s_window[window_id].pending_speak  = true;
            s_window[window_id].last_dialog_id = dialog_id;
            s_window[window_id].last_spoken.clear();   // v2.30.3: fresh dialog
            char dbg[80];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] MSG win=%u id=%u [DLGID] pending",
                window_id, dialog_id);
            Log::Write(dbg);
        }
        // ------------------------------------------------------------------
        // PENDING SPEAK: rawptr is fresh — s_old_message() ran last frame.
        //
        // raw_text was captured at the top of this hook call, AFTER last frame's
        // s_old_message() already updated DIALOG_TEXT_PTRS[window_id] to the
        // new dialog's text. Read it now. If still invalid, retry next frame.
        // ------------------------------------------------------------------
        else if (s_window[window_id].pending_speak && Config::Get().speak_dialog) {
            if (is_valid_dialog_rawptr(raw_text)) {
                const std::wstring decoded = FF7Text::Decode(raw_text);
                if (!decoded.empty()) {
                    char dbg[80];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] MSG win=%u id=%u [PENDING] speaking",
                        window_id, s_window[window_id].last_dialog_id);
                    Log::Write(dbg);
                    log_raw_bytes("PENDING", raw_text);
                    speak_incremental(decoded, s_window[window_id].last_spoken,
                                      /*interrupt=*/true);
                } else {
                    char dbg[80];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] MSG win=%u id=%u [PENDING] decoded empty",
                        window_id, s_window[window_id].last_dialog_id);
                    Log::Write(dbg);
                }
                s_window[window_id].pending_speak = false;
            }
            // else: rawptr not ready; retry next frame
        }
        // ------------------------------------------------------------------
        // PAGE ADVANCE: speak only text not already read (v2.30.3). FF7's
        // rawptr holds the whole message, so START already read every page;
        // speak_incremental says nothing when the page's text matches what
        // was spoken, and only the new tail if the message grew — no more
        // re-reading the message when the player presses to continue.
        // ------------------------------------------------------------------
        else if (paging && Config::Get().speak_dialog) {
            if (is_readable_ptr(raw_text)) {
                const std::wstring decoded = FF7Text::Decode(raw_text);
                if (!decoded.empty())
                    speak_incremental(decoded, s_window[window_id].last_spoken,
                                      /*interrupt=*/true);
            }
            s_window[window_id].page_count++;
        }
        // ------------------------------------------------------------------
        // DIALOG CLOSE: silence TTS and reset tracking for next dialog.
        // ------------------------------------------------------------------
        else if (closing) {
            // Reset last_dialog_id to the CURRENT dialog_id (not 0xFF).
            // WHY NOT 0xFF: resetting to 0xFF caused double-speak — on the frame
            // immediately after CLOSE, the opcode still shows the just-closed
            // dialog_id. With last_dialog_id=0xFF, dialog_id=1 != 0xFF fires DLGID
            // again, speaking "Welcome to Project Echo-S." twice. Setting
            // last_dialog_id=dialog_id prevents that re-fire while still allowing
            // a new dialog (different id) to be detected on the very next frame.
            s_window[window_id].pending_speak  = false;
            s_window[window_id].last_dialog_id = dialog_id;
            s_window[window_id].last_spoken.clear();   // v2.30.3
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
    // Stamp dialog activity (same rationale as hook_message): an ASK choice
    // window is open this frame, so wall-bump tones must be suppressed.
    s_last_dialog_tick = GetTickCount();

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

        // NEW DIALOG: set pending flag. Same one-frame delay as hook_message —
        // rawptr is stale until s_old_ask() runs at the bottom of this hook.
        if (dialog_id != s_window[window_id].last_dialog_id &&
            Config::Get().speak_choices) {
            s_window[window_id].pending_speak  = true;
            s_window[window_id].last_dialog_id = dialog_id;
            char dbg[80];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] ASK win=%u id=%u [DLGID] pending", window_id, dialog_id);
            Log::Write(dbg);
        }
        // PENDING SPEAK: rawptr is fresh — s_old_ask() ran last frame.
        else if (s_window[window_id].pending_speak && Config::Get().speak_choices) {
            if (is_valid_dialog_rawptr(raw_text)) {
                const std::wstring decoded = FF7Text::Decode(raw_text);
                if (!decoded.empty()) {
                    char dbg[80];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] ASK win=%u id=%u [PENDING] speaking",
                        window_id, s_window[window_id].last_dialog_id);
                    Log::Write(dbg);
                    log_raw_bytes("ASK/PENDING", raw_text);
                    std::wstring announcement = L"Choose: ";
                    announcement += decoded;
                    TTS::Speak(announcement, /*interrupt=*/true);
                } else {
                    char dbg[80];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] ASK win=%u id=%u [PENDING] decoded empty",
                        window_id, s_window[window_id].last_dialog_id);
                    Log::Write(dbg);
                }
                s_window[window_id].pending_speak = false;
            }
            // else: rawptr not ready; retry next frame
        }
        else if (closing) {
            // Same fix as hook_message: set to dialog_id (not 0xFF) to prevent
            // one-frame re-fire of the just-closed ASK on the state=7 frame.
            s_window[window_id].pending_speak  = false;
            s_window[window_id].last_dialog_id = dialog_id;
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

// See hooks.h for full rationale. Reading a volatile DWORD is atomic on x86;
// 0 means no dialog opcode has executed yet this session.
unsigned long LastDialogActivityTick()
{
    return s_last_dialog_tick;
}

} // namespace Hooks
