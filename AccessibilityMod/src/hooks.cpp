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
#include <vector>

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
    // v2.30.7: was capped at 18 bytes -- nowhere near enough to hand-decode
    // a real multi-line message or a multi-option ASK choice (both
    // 2026-07-20 bug reports needed the FULL text to diagnose, and the
    // truncated dumps in that session's log left several bytes short of
    // where the actual bug lived). 256 covers effectively every FF7
    // dialog/choice string without approaching the 4096-byte decode cap.
    char hex[800] = {}; int n = 0;
    for (int i = 0; i < 256; ++i) {
        const uint8_t b = reinterpret_cast<const uint8_t*>(text)[i];
        if (b == 0xFF) break;
        n += _snprintf_s(hex + n, (int)sizeof(hex) - n, _TRUNCATE, "%02X ", b);
    }
    if (n > 0) hex[n - 1] = '\0'; // trim trailing space
    char line[840];
    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[FF7Access] MSG raw(%s): %s", path_tag, hex);
    Log::Write(line);
}

// v2.30.7: dump each decoded line/page's full text, one log line per entry,
// so a mismatch between our split and the game's own line numbering is
// directly visible (no hand-decoding hex against the encoding table).
static void log_lines(const char* path_tag, const std::vector<std::wstring>& lines)
{
    for (size_t i = 0; i < lines.size(); ++i) {
        char line[300];
        _snprintf_s(line, sizeof(line), _TRUNCATE,
            "[FF7Access] %s[%zu]: '%ls'", path_tag, i, lines[i].c_str());
        Log::Write(line);
    }
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

// Saved opcode table entry for STTIM (0x38, "set timer" -- writes the
// countdown-escape clock). Calling convention matches MESSAGE: __cdecl, no
// parameters, handler reads its h/m/s script args directly.
static int (__cdecl* s_old_sttim)() = nullptr;

// v2.30.8: true once a LIVE STTIM opcode call has been observed THIS
// PROCESS RUN. Plain volatile write/read is sufficient -- this is a
// monotonic "once true, stays true for the rest of the session" latch, not
// a value that needs read-modify-write atomicity, and LONG reads/writes
// are naturally atomic on x86.
//
// WHY THIS EXISTS: COUNTDOWN_TIMER_SECONDS (ff7_addresses.h) is savemap
// state, so it SURVIVES a save/load -- already flagged as a risk when
// that address was found (see its doc comment: "Being savemap state, the
// timer persists in saves"). Player report 2026-07-20: loading a save
// taken well after an escape had already completed (with time left on
// the clock, so the value never reached 0) made TimerThread treat that
// STALE, still-nonzero value as a BRAND NEW timer the instant it next
// ticked down a second -- announcing "Timer started" in the slums, nowhere
// near an active escape. The value alone can't distinguish "a real
// countdown just began" from "leftover data from a previous playthrough
// segment that happens to still be counting down in the background,
// invisible in vanilla FF7 since its on-screen clock window is long
// closed." A live STTIM call is the one signal that unambiguously means
// the former -- TimerThread (proxy.cpp) gates its "just started"
// detection on this being true.
static volatile LONG s_sttim_seen = 0;

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

    // v2.30.4 (revised v2.30.7): the decoded PAGES of the current dialog
    // (one entry per on-screen page — see FF7Text::DecodeMessagePages),
    // and the index of the next
    // one to speak. START speaks pages[0] and sets next_page=1; each PAGE
    // transition speaks pages[next_page++]. This is the field this struct's
    // page_count field was originally reserved for (see the v1 header
    // comment at the top of this file) — the whole message is decoded once
    // at START either way (FF7's rawptr holds it all), but now only ONE
    // page's worth is spoken per screen instead of the entire message at
    // once (player report 2026-07-20: speaking everything at window-open
    // sounds like repeating, because the display is still catching up).
    std::vector<std::wstring> pages;
    size_t next_page = 0;

    // v2.30.19: positional page tracking for STATE-STATIC windows (win=3
    // style — the state byte never moves, so neither the discrete
    // 14->2/4->8 PAGE transitions nor the counter-style from-idle reruns
    // ever fire; a multi-page dialog spoke page 1 and went silent —
    // 2026-07-23 hideout log, Barret's 4-page "Yeah, you're strong."
    // speech + both TV-broadcast pages the screenshots showed unspoken).
    // The one observable those windows still have is the TYPEWRITER
    // pointer (DIALOG_TEXT_PTRS[win]) advancing through the message
    // bytes: page_offsets holds each page's raw byte offset (from
    // DecodeMessagePages), msg_base the pointer captured at decode; when
    // the live pointer's offset reaches a later page's start, the display
    // has turned to it — speak that page from cache. state_static starts
    // true per dialog and is cleared by ANY observed state transition, so
    // the positional path can never double-fire against the state-driven
    // paths (win=0/1 windows always transition within a frame or two).
    std::vector<size_t> page_offsets;
    const char*         msg_base = nullptr;
    bool                state_static = true;

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

    // v2.30.4: ASK-only. One entry per choice LINE (FF7Text::DecodeLines --
    // splits on every newline, unlike pages[] above which only splits on
    // page breaks; ASK's answers are conventionally one line each), and the
    // option index we most recently announced (-1 = none yet).
    //
    // v2.30.4/6 both DELIBERATELY seeded this to the starting option (0,
    // then FIRST_LINE) so the OPTION CURSOR block wouldn't "re-announce"
    // the option already folded into the "Choose: ..." intro speech. v2.30.9:
    // that suppression is the bug, not a feature -- the intro reads the
    // whole window (name + lead-in + every option) as one run-on sentence,
    // so the DEFAULT-highlighted option never gets a clean, isolated
    // announcement, only a mid-sentence mention. Player report 2026-07-20
    // ("first choice spoken at the bottom... arrow back up to it, not
    // spoken at all") is exactly this: with only 2 options and the cursor
    // starting at the top (no legal "up" move), the player never heard
    // anything but that one buried mention. Leaving this at -1 lets the
    // OPTION CURSOR block fire once immediately after the intro, the same
    // way every subsequent cursor move already does -- see hook_ask.
    // Unused by hook_message. Cleared on new dialog and on close, same as
    // pages[] above.
    std::vector<std::wstring> ask_lines;
    int ask_last_option = -1;

    // v2.30.13: this ASK's FIRST_LINE opcode param (the cursor's clamp
    // floor / canonical starting line) and the RAW mirror value captured
    // at the PENDING frame, BEFORE this window's update loop has
    // necessarily rewritten it. WHY: the per-window pixel mirror
    // (ASK_CURSOR_PIXEL_Y) keeps the PREVIOUS ASK's resting position
    // until the new window starts accepting input (~0.5-1.3s after open
    // in the 2026-07-22 logs) -- announcing that stale value spoke the
    // WRONG option at open, then re-announced when the game initialized
    // the real cursor (player report: "spoke one of the choices multiple
    // times"). The first announce is therefore suppressed while the
    // mirror still equals the captured stale baseline, UNLESS it equals
    // first_line (then it's correct regardless -- the game clamps the
    // cursor into [first,last] and starts there for a fresh variable).
    // Residual accepted: a re-asked dialog whose script var preserved a
    // mid-range cursor equal to the stale baseline skips its initial
    // announce (first keypress recovers) -- indistinguishable from
    // staleness without more state, and strictly better than speaking a
    // wrong option.
    uint8_t ask_first_line      = 0;
    int     ask_mirror_baseline = -1;

    // v2.30.5/6: MESSAGE-only. True while this window's dialog state byte
    // has already been observed holding steady long enough to count as
    // "waiting for the confirm button" (see the WAIT TONE block in
    // hook_message). Armed once per hold so the tone fires only on the
    // edge into waiting, not every frame the hold continues; disarmed the
    // moment the state changes again (next typewriter tick, page turn, or
    // a fresh dialog).
    bool wait_tone_armed = false;

    // v2.30.6: GetTickCount() of this window's last dialog-state CHANGE.
    // The wait tone needs to know how long the CURRENT value has been held,
    // not just whether it moved since last frame — see the WAIT TONE
    // block's comment for why a single-frame "unchanged" check false-fired
    // (player report 2026-07-20: multiple/early beeps, presses not
    // registering for 2-3 tries).
    DWORD state_change_tick = 0;

    // v2.30.15: true once this window's CLOSE actions have run for the
    // current stay at state 7 (cleared whenever the state leaves 7). CLOSE
    // is now committed only on the SECOND consecutive frame at 7 — win=1's
    // dense per-tick counter PASSES THROUGH 7 on its way up (5->7->9, one
    // frame each), and the old "current==7" test fired a FALSE CLOSE there:
    // TTS::Silence() cut the just-started speech off ~270ms in and wiped
    // ask_lines, muting the whole choice (2026-07-23 log, 7th Heaven bar +
    // Sector 5 shop dialogs — every win=1 dialog was affected). Discrete
    // windows (win=0/2) genuinely PARK at 7 during the close animation, so
    // requiring a second consecutive frame there only delays their close
    // actions by one frame (~33ms, imperceptible); a counter that never
    // repeats a value can never satisfy it.
    bool close_handled = false;

    // v2.30.16: GetTickCount() of the most recent hook call for this
    // window (0 = never called). The MESSAGE/ASK opcode executes EVERY
    // frame while its dialog is on screen and NOT AT ALL in between, so
    // the first call after a quiet gap IS a fresh dialog opening — an
    // open-detection signal that works for EVERY window style, including
    // the win=2/3 "state byte never moves" windows that have no idle edge
    // for the v2.30.15 re-arm to catch (2026-07-23 second log: a win=3
    // dialog re-opened with valid text, same id, NO state transitions —
    // and stayed silent; that was the "last conversation didn't repeat").
    DWORD last_hook_tick = 0;

    // v2.30.16: GetTickCount() of this window's last PENDING speak.
    // Guards the v2.30.15 from-idle re-arm against a double-speak the
    // same log exposed: a window whose state byte is still parked at 0
    // when the dialog opens can complete DLGID+PENDING (speak!) BEFORE
    // the 0->1 edge arrives — the edge then re-armed and re-spoke the
    // same dialog 200ms later (win=1 id=43, 10:58:16.146 and .345). The
    // re-arm now also requires the last speak to be comfortably old.
    DWORD last_speak_tick = 0;
};
static WindowState s_window[8];

// ---------------------------------------------------------------------------
// reset_windows_if_field_changed: clear per-window dialog tracking when the
// player crosses to a new field. Called at the top of hook_message and
// hook_ask, before any dialog_id comparison.
//
// WHY (v2.30.11, 2026-07-21 log-diagnosed): dialog_id is a FIELD-LOCAL
// script parameter — two different fields can reuse the same id for
// completely unrelated dialogs. s_window[].last_dialog_id survived field
// changes, so a dialog on the new field whose id happened to equal the
// LAST id seen on that window slot on a PREVIOUS field was treated as
// "same dialog still open" and silently skipped: no intro speech, no
// choice tone, no ask_lines (which also mutes the ASK cursor announces).
// Confirmed case (session log 2026-07-21 20:14): the Aeris flower-girl
// scene's second choice ran win=0 with (inferred) id=3 while win=0's
// stale last_dialog_id was 3 from a MESSAGE two fields earlier — the ASK
// opened, ran its whole state machine (START..CLOSE logged), and said
// nothing. The same collision could silence a MESSAGE equally.
//
// Field-change detection = FIELD_FILE_BUFFER pointer comparison, the same
// reliable signal log_field_header_if_changed already uses (a new field
// always allocates a new buffer). The reset therefore runs on the first
// MESSAGE/ASK opcode executed on the new field, before that opcode's own
// dialog_id comparison — no dialog can already be open at that instant
// (this call IS the new field's first dialog opcode), so clearing every
// slot is safe by construction.
// ---------------------------------------------------------------------------
static void reset_windows_if_field_changed()
{
    static const char* s_last_field_buf = nullptr;
    const char* const buf =
        *reinterpret_cast<const char* const*>(FF7Addr::FIELD_FILE_BUFFER);
    if (!buf || buf == s_last_field_buf) return;
    const bool first_ever = (s_last_field_buf == nullptr);
    s_last_field_buf = buf;
    if (first_ever) return;   // process start: slots are already pristine

    for (WindowState& w : s_window) {
        w.last_opcode     = 0;
        w.pages.clear();
        w.next_page       = 0;
        w.last_dialog_id  = 0xFF;   // sentinel: "none spoken yet" (see struct)
        w.pending_speak   = false;
        w.ask_lines.clear();
        w.ask_last_option = -1;
        w.ask_first_line  = 0;
        w.ask_mirror_baseline = -1;
        w.wait_tone_armed = false;
        w.state_change_tick = 0;
        w.close_handled   = false;
        w.last_hook_tick  = 0;
        w.last_speak_tick = 0;
        w.page_offsets.clear();
        w.msg_base        = nullptr;
        w.state_static    = true;
    }
    Log::Write("[FF7Access] FIELD changed: window dialog tracking reset.");
}

// ---------------------------------------------------------------------------
// rearm_if_reopened_after_gap (v2.30.16): the general fresh-dialog detector
// for same-id re-talks, called at the top of BOTH hooks' in-range paths.
//
// The MESSAGE/ASK opcode executes EVERY frame while its dialog is on screen
// and NOT AT ALL between dialogs (the field script blocks on the opcode,
// then moves past it). So the first hook call for a window after a quiet
// gap is, by construction, a brand-new dialog opening — regardless of
// dialog_id and regardless of window style. This is what makes it strictly
// more general than the v2.30.15 from-idle STATE re-arm: the win=2/3-style
// windows whose state byte never moves produce no idle edge at all, and
// the 2026-07-23 second log showed exactly that failure — a win=3 dialog
// re-opened (valid text, wait tone armed) with the same id and NO state
// transitions, and stayed silent ("the last conversation didn't repeat").
//
// It also cannot double-fire the way the state re-arm could (same log,
// win=1 id=43 spoken twice 200ms apart): the gap exists only once per
// reopen — every subsequent call updates last_hook_tick and sees no gap.
//
// kOpcodeGapMs = 500: an open dialog's opcode runs every frame (~33ms), so
// anything approaching 500ms of silence means the opcode ENDED. Kept well
// under the fastest realistic dismiss-and-retalk cycle. A dialog that
// resumes after a mid-dialog interruption longer than this (e.g. a battle
// transition freezing the field) re-arms and re-speaks — for a blind
// player, restoring context after a battle is a feature, not a bug.
//
// The clock/gil special windows (WSPCL etc.) run their update loop
// continuously for their whole lifetime, so they never present a gap and
// never spuriously re-arm.
// ---------------------------------------------------------------------------
static void rearm_if_reopened_after_gap(uint8_t window_id, const char* hook_tag)
{
    constexpr DWORD kOpcodeGapMs = 500;
    const DWORD now  = GetTickCount();
    WindowState& w   = s_window[window_id];
    const DWORD prev = w.last_hook_tick;
    w.last_hook_tick = now;
    if (prev == 0) return;                    // first call ever / after reset
    if ((now - prev) <= kOpcodeGapMs) return; // opcode running continuously
    if (w.pending_speak) return;              // a dialog is already pended
    if (w.last_dialog_id != 0xFF) {
        w.last_dialog_id = 0xFF;
        char dbg[96];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] %s win=%u reopened after %lums gap (re-armed)",
            hook_tag, window_id, static_cast<unsigned long>(now - prev));
        Log::Write(dbg);
    }
}

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

// v2.30.5: edge-triggered "please beep" signals for the two dialog audio
// cues. hook_message/hook_ask run on the GAME's main thread every frame —
// Beep() blocks for its whole duration, so calling it directly from here
// would stall the game itself (same reasoning as every other tone in this
// mod: WallBumpThread and the proximity/wander chirps in proxy.cpp all poll
// a background thread instead of beeping inline). These are LONGs (not
// bool) because InterlockedExchange requires a 32-bit operand; set with a
// plain volatile write (0/1 is atomic on x86), consumed with
// InterlockedExchange(&flag, 0) so the polling thread's read-and-clear can't
// race a fresh set from the hook and drop it.
static volatile LONG s_dialog_wait_pending   = 0; // "waiting for the confirm button"
static volatile LONG s_dialog_choice_pending = 0; // "a choice was just presented"

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
// speak_page: speak s_window[window_id].pages[next_page] (if in range and
// non-empty) via Tolk, then advance next_page. Shared by the PENDING (START)
// and PAGE-advance paths below — both just say "speak whatever page comes
// next", they differ only in WHEN they fire.
static void speak_page(WindowState& win, bool interrupt)
{
    if (win.next_page >= win.pages.size())
        return;                                   // no more pages decoded than shown
    const std::wstring& text = win.pages[win.next_page++];
    if (!text.empty())
        TTS::Speak(text, interrupt);
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

    // v2.30.11: dialog_ids are field-local — drop all stale per-window
    // tracking the moment a new field's first dialog opcode runs, or a
    // cross-field id collision silences it (see the helper's doc comment).
    reset_windows_if_field_changed();

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

        // v2.30.16: general same-id reopen detection (all window styles) —
        // must run before the DLGID comparison below.
        rearm_if_reopened_after_gap(window_id, "MSG");

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

        // v2.30.5: captured BEFORE the DLGID/PENDING/PAGE/CLOSE chain below
        // (which may clear pending_speak on THIS frame) — the WAIT TONE
        // block needs to know whether the intro was still pending at the
        // START of this hook call, not after, so it never fires on the
        // very same frame text starts being announced (see that block).
        const bool was_pending = s_window[window_id].pending_speak;

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
        // v2.30.15: CLOSE commits only on the SECOND consecutive frame at 7
        // — win=1's dense counter passes THROUGH 7 (5->7->9) and the old
        // "current==7" test false-closed there, silencing every win=1
        // dialog ~270ms in (see WindowState::close_handled). Discrete
        // windows park at 7 for the whole close animation, so their close
        // actions just land one frame (~33ms) later than before.
        // !pending_speak: if a NEW dialog's id arrived during the 7-hold
        // (DLGID pended it last frame), the deferred commit must not run —
        // it would clear that pending speak; the DLGID branch already did
        // the cleanup the close would have done.
        const bool closing  = (last_state == 7 && current_state == 7 &&
                               !s_window[window_id].close_handled &&
                               !s_window[window_id].pending_speak);

        // Log all state transitions for diagnostic visibility. Entering 7
        // is tagged "close?" — it only becomes a real CLOSE if the state
        // holds 7 next frame (the commit logs its own line).
        if (current_state != last_state) {
            const char* tag = starting ? "START" : paging ? "PAGE" :
                              (current_state == 7) ? "close?" : "skip";
            char state_log[80];
            _snprintf_s(state_log, sizeof(state_log), _TRUNCATE,
                "[FF7Access] MSG win=%u %u->%u [%s]",
                window_id, last_state, current_state, tag);
            Log::Write(state_log);
            // v2.30.19: any transition observed during an open dialog
            // proves this window has a MOVING state byte — its paging is
            // owned by the state-driven paths, and the positional page
            // check below must stand down. (A transition on the DLGID
            // frame itself doesn't count: the DLGID branch below runs
            // after this and resets state_static for the new dialog.)
            if (!s_window[window_id].pending_speak &&
                !s_window[window_id].pages.empty())
                s_window[window_id].state_static = false;
        }

        // v2.30.17: FROM-IDLE EDGE, two meanings now told apart by whether
        // cached pages remain unspoken.
        //
        // Counter-style windows (win=1) re-run their ENTIRE state cycle
        // for every PAGE of a multi-page dialog: rest -> 0 -> climb ->
        // rest, same dialog_id throughout, no 14->2/4->8 transitions ever
        // (those belong to the discrete style). The v2.30.15/16 re-arm
        // misread each page rerun as a fresh dialog and re-decoded the
        // rawptr — but that pointer is the live TYPEWRITER pointer, and on
        // a page rerun the game starts consuming it IMMEDIATELY (no
        // window-open delay), so the deferred PENDING read lost the first
        // ~3 characters: the 2026-07-23 11:13 log shows the same 3-page
        // dialog decoded as '"I should have known."' (complete, first
        // open), then ''s always pushing...' (lost `"He`), then
        // 'was worried."' (lost `"I `) — the player heard "was worried"
        // for '"I was worried."'.
        //
        // The first decode already cached EVERY page (rawptr holds the
        // whole message at open, v2.30.4), so a page rerun must speak the
        // NEXT CACHED page — same pacing the discrete windows get from
        // their 14->2/4->8 PAGE transitions — never re-decode.
        //
        // The >600ms last-speak guard tells the page rerun apart from the
        // 0->1 edge of the dialog's OWN opening cycle (~170ms after the
        // PENDING speak, while page 1 is still on screen — the v2.30.16
        // double-speak, observed again at 10:58:16 as 200ms): a real page
        // advance needs the player to have had the page on screen (wait
        // tone alone needs 300ms+ to arm before they can even hear it).
        //
        // When NO unspoken pages remain, the old meaning applies: a
        // same-id RE-TALK on a window whose opcode never paused (no gap
        // for the primary v2.30.16 detector) — re-arm the DLGID sentinel,
        // guarded by the longer 1500ms since-last-speak window.
        if (last_state == 0 && current_state != 0 && current_state != 7 &&
            !s_window[window_id].pending_speak) {
            WindowState& w = s_window[window_id];
            const DWORD since_speak = GetTickCount() - w.last_speak_tick;
            if (w.next_page < w.pages.size()) {
                if (since_speak > 600 && Config::Get().speak_dialog) {
                    char pg[96];
                    _snprintf_s(pg, sizeof(pg), _TRUNCATE,
                        "[FF7Access] MSG win=%u counter-style PAGE %zu/%zu",
                        window_id, w.next_page + 1, w.pages.size());
                    Log::Write(pg);
                    speak_page(w, /*interrupt=*/true);
                    w.last_speak_tick = GetTickCount();
                }
            } else if (since_speak > 1500) {
                w.last_dialog_id = 0xFF;
            }
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
            s_window[window_id].pages.clear();          // v2.30.4: fresh dialog
            s_window[window_id].next_page = 0;
            s_window[window_id].page_offsets.clear();   // v2.30.19
            s_window[window_id].msg_base = nullptr;
            s_window[window_id].state_static = true;
            // v2.30.5: some windows' state byte never reaches CLOSE (win=2/3
            // — see the STATE MACHINE comment above), so DLGID is the only
            // reliable "this is a fresh dialog" edge for them; reset here too
            // or a window that never closes would only ever get ONE wait
            // tone for its very first dialog, then none for the rest of the
            // session (wait_tone_armed would stay stuck true).
            s_window[window_id].wait_tone_armed = false;
            // v2.30.6: also restart the hold timer here for the same
            // windows — their state byte never changes at all (always 0),
            // so state_change_tick would otherwise stay stuck at session
            // start and the fallback debounce (see the WAIT TONE block)
            // would trivially already be "held" long enough on dialog 2+,
            // skipping its intended delay.
            s_window[window_id].state_change_tick = GetTickCount();
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
        //
        // v2.30.4 (revised v2.30.7): FF7's rawptr holds the WHOLE multi-
        // page message the instant the window opens (there's no "page 2
        // doesn't exist yet" state), so we decode all of it right here —
        // but only SPEAK the first page. The rest sit cached in
        // s_window[].pages, one page spoken per later PAGE-advance event,
        // so TTS stays paced to what's actually on screen instead of
        // reading the whole message up front (player report 2026-07-20).
        // FF7Text::DecodeMessagePages groups lines into ~4-line pages
        // (FF7's on-screen box capacity) AND still honors any explicit
        // page-break byte as a forced early page close — see its doc
        // comment for why a pure hard-break-only split (this mod's first
        // attempt) went silent on dialogs that soft-wrap with no such byte
        // present (player report 2026-07-20).
        // ------------------------------------------------------------------
        else if (s_window[window_id].pending_speak && Config::Get().speak_dialog) {
            if (is_valid_dialog_rawptr(raw_text)) {
                s_window[window_id].pages = FF7Text::DecodeMessagePages(
                    raw_text, &s_window[window_id].page_offsets);
                s_window[window_id].msg_base = raw_text;   // v2.30.19
                char dbg[80];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] MSG win=%u id=%u [PENDING] speaking (%zu pages)",
                    window_id, s_window[window_id].last_dialog_id,
                    s_window[window_id].pages.size());
                Log::Write(dbg);
                log_raw_bytes("PENDING", raw_text);
                log_lines("MSG PAGE", s_window[window_id].pages);
                speak_page(s_window[window_id], /*interrupt=*/true);
                s_window[window_id].pending_speak = false;
                s_window[window_id].last_speak_tick = GetTickCount(); // v2.30.16
            }
            // else: rawptr not ready; retry next frame
        }
        // ------------------------------------------------------------------
        // PAGE ADVANCE: speak the next cached page (v2.30.4). The message was
        // already fully decoded at START (see above) -- this just paces one
        // more page of it out to TTS per advance, instead of re-decoding (and
        // previously, re-speaking) the whole rawptr again.
        // ------------------------------------------------------------------
        else if (paging && Config::Get().speak_dialog) {
            speak_page(s_window[window_id], /*interrupt=*/true);
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
            // (Same-id RE-TALKS are handled by the v2.30.15 from-idle re-arm
            // above, which fires only when the window later reopens from 0.)
            s_window[window_id].pending_speak  = false;
            s_window[window_id].last_dialog_id = dialog_id;
            s_window[window_id].pages.clear();          // v2.30.4
            s_window[window_id].next_page = 0;
            s_window[window_id].wait_tone_armed = false; // v2.30.5
            s_window[window_id].close_handled = true;    // v2.30.15: once per stay at 7
            char close_log[64];
            _snprintf_s(close_log, sizeof(close_log), _TRUNCATE,
                "[FF7Access] MSG win=%u CLOSE committed", window_id);
            Log::Write(close_log);
            TTS::Silence();
        }
        // v2.30.15: leaving state 7 re-arms close detection for the next stay.
        if (current_state != 7)
            s_window[window_id].close_handled = false;

        // ------------------------------------------------------------------
        // POSITIONAL PAGE ADVANCE (v2.30.19): the page-turn signal for
        // STATE-STATIC windows (win=3 style — state byte parked, no
        // transitions ever, so neither the 14->2/4->8 paths nor the
        // counter-style from-idle rerun can fire). The typewriter pointer
        // is the one observable left: it walks this same byte stream, and
        // entering page N's byte range means the display turned to page N.
        // Speaks from the CACHE (never re-decodes — the pointer is
        // mid-message by definition here). +2 slack on the offsets: the
        // parked position between pages may sit ON the page-break byte
        // boundary; requiring the pointer 2 bytes INTO the new page's
        // content rejects that ambiguity at the cost of one frame.
        // ------------------------------------------------------------------
        if (!s_window[window_id].pending_speak &&
            s_window[window_id].state_static &&
            s_window[window_id].msg_base &&
            s_window[window_id].next_page < s_window[window_id].pages.size() &&
            s_window[window_id].page_offsets.size() ==
                s_window[window_id].pages.size() &&
            is_valid_dialog_rawptr(raw_text) &&
            Config::Get().speak_dialog) {
            const ptrdiff_t rel = raw_text - s_window[window_id].msg_base;
            if (rel > 0 && rel < 4096) {
                // Furthest page whose content the display has entered —
                // a mashing player skips intermediates, matching what a
                // sighted player experiences.
                size_t target = static_cast<size_t>(-1);
                for (size_t i = s_window[window_id].next_page;
                     i < s_window[window_id].page_offsets.size(); ++i) {
                    if (static_cast<size_t>(rel) >=
                        s_window[window_id].page_offsets[i] + 2)
                        target = i;
                }
                if (target != static_cast<size_t>(-1)) {
                    char pg[112];
                    _snprintf_s(pg, sizeof(pg), _TRUNCATE,
                        "[FF7Access] MSG win=%u positional PAGE %zu/%zu (rel=%ld)",
                        window_id, target + 1,
                        s_window[window_id].pages.size(),
                        static_cast<long>(rel));
                    Log::Write(pg);
                    s_window[window_id].next_page = target;
                    speak_page(s_window[window_id], /*interrupt=*/true);
                    s_window[window_id].last_speak_tick = GetTickCount();
                    // Re-arm the wait tone for the NEW page with a fresh
                    // debounce window: state-static windows never get the
                    // state-transition resets that re-arm it on the other
                    // window styles, so without this a win=3 multi-page
                    // dialog chimed only for its first page (and with only
                    // the armed-flag cleared, the stale held-time would
                    // re-fire the tone instantly, mid-typing).
                    s_window[window_id].wait_tone_armed = false;
                    s_window[window_id].state_change_tick = GetTickCount();
                }
            }
        }

        // v2.30.6: track how long the CURRENT state value has been held —
        // the wait tone below needs this, not just "did it change since
        // last frame" (see that block for why).
        if (current_state != last_state)
            s_window[window_id].state_change_tick = GetTickCount();

        // ------------------------------------------------------------------
        // WAIT TONE (v2.30.5, retuned v2.30.6): a short high tone once the
        // game is genuinely sitting there waiting for the player to press
        // the confirm button.
        //
        // v2.30.5 fired on ANY state value that had merely "stopped
        // changing this frame" — WRONG, confirmed by play report
        // 2026-07-20 (multiple/early beeps, presses not registering for
        // 2-3 tries). The actual session log explained why: win=0's state
        // byte parks at value 2 for the ENTIRE typing duration (~900ms
        // observed) — it is NOT a fine per-character counter for this
        // window, so "unchanged for one frame" was true almost from the
        // first frame of typing, long before the real wait. The genuine
        // wait only begins when state jumps to one of a small set of
        // TERMINAL values — 14 or 4 (the exact values `paging` above
        // already treats as "about to page") or 6 (observed: win=0 holds
        // at 6 before its 6→7 close, i.e. the "about to close" wait uses a
        // DIFFERENT terminal value than the page-wait). Other windows
        // (win=1 in the 2026-07-19 log) instead count states up densely,
        // changing almost every frame while typing, and settle on some
        // arbitrary DATA-DEPENDENT value once done (17, 34, 60 — never a
        // fixed constant) — those can't be whitelisted by value, so they
        // fall through to a longer debounce instead. This is genuinely two
        // different window behaviors (small discrete state machine vs.
        // dense per-tick counter), not one bug with one number to tune.
        //
        // So: three tiers, keyed off how long current_state has been held
        // (state_change_tick, updated above) and what value it currently is:
        //   - kWaitStates {4,6,14}: confirmed terminal values -- fire after
        //     a SHORT hold (~2-3 polls). Not zero-delay, because win=1's
        //     climb passes THROUGH 14 transiently (one poll) on its way up;
        //     requiring it to still be held on the next poll is what tells
        //     "genuinely parked here" apart from "just passing through".
        //   - kNeverWaitStates {1,2}: confirmed NON-terminal (opening
        //     animation / actively typing, per win=0's own evidence) —
        //     never fire here no matter how long held; time alone can't
        //     tell "still typing a long message" from "done waiting", only
        //     the value can.
        //   - anything else (0, 3, 5, 7-handled-elsewhere, 8, and win=1's
        //     climbing values, and win=2/3's permanent 0): fall through to
        //     a LONG debounce, long enough that win=1's ~33ms-per-poll
        //     climb never sits still that long while still counting, short
        //     enough to feel responsive once a window truly has settled.
        //
        // was_pending (captured before the chain ran) still guards against
        // firing on the very frame the intro just started being announced.
        // Edge-triggered via wait_tone_armed. Independent of speak_dialog
        // (voice-acting-mod players get no other "ready for input" cue).
        // ------------------------------------------------------------------
        if (Config::Get().dialog_wait_tone && has_dialog_text && !was_pending) {
            constexpr DWORD kWaitConfirmMs     = 80;   // ~2-3 polls
            constexpr DWORD kFallbackDebounceMs = 300; // longer than any
                                                        // observed per-poll
                                                        // climb step (~33ms)
            const DWORD held_ms = GetTickCount() - s_window[window_id].state_change_tick;
            const bool is_wait_state =
                (current_state == 4 || current_state == 6 || current_state == 14);
            const bool is_never_wait_state =
                (current_state == 1 || current_state == 2);

            const bool should_fire =
                is_never_wait_state ? false :
                is_wait_state       ? (held_ms >= kWaitConfirmMs) :
                                       (held_ms >= kFallbackDebounceMs);

            if (should_fire) {
                if (!s_window[window_id].wait_tone_armed) {
                    s_window[window_id].wait_tone_armed = true;
                    InterlockedExchange(&s_dialog_wait_pending, 1);
                    // v2.30.15: the tone was previously invisible in the
                    // log, which made the 2026-07-23 "chime doesn't fire
                    // for all dialogs" report undiagnosable — no way to
                    // tell "tone never armed" from "tone armed but
                    // inaudible/drowned out". One line per arm settles it.
                    char tone_log[96];
                    _snprintf_s(tone_log, sizeof(tone_log), _TRUNCATE,
                        "[FF7Access] MSG win=%u wait tone (state=%u held=%lums)",
                        window_id, current_state,
                        static_cast<unsigned long>(held_ms));
                    Log::Write(tone_log);
                }
            } else {
                s_window[window_id].wait_tone_armed = false;
            }
        } else {
            s_window[window_id].wait_tone_armed = false;
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
//
// v2.30.4: also announce the highlighted OPTION line as the player moves the
// cursor, via the scan-confirmed ASKMENU_OPTION global (see its doc comment
// in ff7_addresses.h — live-scan-confirmed, not statically verified). The
// intro ("Choose: " + full text) is unchanged and still speaks first.
//
// v2.30.4 shipped this ASSUMING the cursor starts at option 0 (line[0] of
// FF7Text::DecodeLines' split) -- WRONG, confirmed by play report
// 2026-07-20 ("only one will speak and it is the first choice but... at
// the end of the choice set instead of the beginning"). Root cause found
// by disassembling field_opcode_ask_update_loop_6310A1 further
// (ff7_ask_lines_static.py): the ASK opcode carries FIRST_LINE/LAST_LINE
// parameters (indices 3/4, right after dialog_id) that the game's own
// cursor-move handlers clamp the option to -- the choice text routinely
// has leading QUESTION line(s) before the selectable options begin, so
// the true starting/minimum option is FIRST_LINE, not 0. v2.30.6 reads it
// from the opcode instead of assuming.
//
// ASK PARAMETER LAYOUT (byte offsets from the opcode, confirmed by
// disassembling the ASK handler 0x618E83 -- ff7_ask_cursor_static.py and
// ff7_ask_lines_static.py, both 2026-07-19/20):
//   +2 window_id   (param index 1 -- FFNx voice.cpp opcode_voice_ask line 462)
//   +3 dialog_id   (param index 2 -- FFNx voice.cpp opcode_voice_ask line 463)
//   +4 first_line  (param index 3 -- lower clamp bound for the option cursor)
//   +5 last_line   (param index 4 -- upper clamp bound for the option cursor)
// ---------------------------------------------------------------------------
static int __cdecl hook_ask(int unk)
{
    // Stamp dialog activity (same rationale as hook_message): an ASK choice
    // window is open this frame, so wall-bump tones must be suppressed.
    s_last_dialog_tick = GetTickCount();

    // v2.30.11: same field-change reset as hook_message — an ASK can be the
    // new field's first dialog opcode too (see the helper's doc comment).
    reset_windows_if_field_changed();

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

        // v2.30.16: general same-id reopen detection, same as hook_message —
        // must run before is_new_ask_dialog is computed below.
        rearm_if_reopened_after_gap(window_id, "ASK");

        // State machine for close detection and log visibility.
        const uint8_t current_state = FF7Addr::get_dialog_state(window_id);
        const uint8_t last_state    = s_window[window_id].last_opcode;

        const bool starting = ((last_state == 0 || last_state == 7) &&
                               current_state != 0 && current_state != 7);
        // v2.30.15: two-consecutive-frame CLOSE commit, same as
        // hook_message — win=1's dense counter passes THROUGH 7 and the
        // old test false-closed there, wiping ask_lines (muting the whole
        // 7th Heaven choice, 2026-07-23 log) and silencing the intro
        // mid-word. See WindowState::close_handled. !pending_speak guard:
        // same new-dialog-during-7-hold race as hook_message's.
        const bool closing  = (last_state == 7 && current_state == 7 &&
                               !s_window[window_id].close_handled &&
                               !s_window[window_id].pending_speak);

        if (current_state != last_state) {
            const char* tag = starting ? "START" :
                              (current_state == 7) ? "close?" : "skip";
            char state_log[80];
            _snprintf_s(state_log, sizeof(state_log), _TRUNCATE,
                "[FF7Access] ASK win=%u %u->%u [%s]",
                window_id, last_state, current_state, tag);
            Log::Write(state_log);
        }

        // v2.30.15: same-id RE-ARM on the from-idle edge, same as
        // hook_message — a re-asked choice with an unchanged dialog_id
        // (re-talking to the same NPC) must present as new. See the
        // hook_message re-arm comment for the full reasoning, including
        // the v2.30.16 last-speak-age guard (double-speak protection) and
        // why the gap re-arm above is now the primary reopen detector.
        if (last_state == 0 && current_state != 0 && current_state != 7 &&
            !s_window[window_id].pending_speak &&
            (GetTickCount() - s_window[window_id].last_speak_tick) > 1500) {
            s_window[window_id].last_dialog_id = 0xFF;
        }

        // v2.30.5: a new dialog_id on the ASK opcode IS "a choice was just
        // presented" — fire the double tone off this directly, independent
        // of speak_choices, same reasoning as the wait tone's independence
        // from speak_dialog: a player who has voice-over covering choice
        // TEXT still gets no other cue that a choice screen just opened.
        const bool is_new_ask_dialog = (dialog_id != s_window[window_id].last_dialog_id);
        if (is_new_ask_dialog && Config::Get().dialog_choice_tone) {
            InterlockedExchange(&s_dialog_choice_pending, 1);
        }

        // NEW DIALOG: set pending flag. Same one-frame delay as hook_message —
        // rawptr is stale until s_old_ask() runs at the bottom of this hook.
        if (is_new_ask_dialog &&
            Config::Get().speak_choices) {
            s_window[window_id].pending_speak  = true;
            s_window[window_id].last_dialog_id = dialog_id;
            s_window[window_id].ask_lines.clear();      // v2.30.4: fresh choice
            s_window[window_id].ask_last_option = -1;
            s_window[window_id].ask_first_line  = 0;          // v2.30.13
            s_window[window_id].ask_mirror_baseline = -1;     // v2.30.13
            char dbg[80];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] ASK win=%u id=%u [DLGID] pending", window_id, dialog_id);
            Log::Write(dbg);
        }
        // PENDING SPEAK: rawptr is fresh — s_old_ask() ran last frame.
        else if (s_window[window_id].pending_speak && Config::Get().speak_choices) {
            if (is_valid_dialog_rawptr(raw_text)) {
                // v2.30.13: decode the lines FIRST — the intro is now built
                // from them (context lines only), not from a flat Decode()
                // of the whole window. WHY THE RESTRUCTURE (player request
                // 2026-07-22): the old intro read the ENTIRE window —
                // name, question, AND every option — as one utterance,
                // which (a) ran the question straight into the option
                // announces with no audible break, and (b) spoke option
                // text that the cursor announces then repeated ("each
                // choice once" expectation). Now the intro speaks only
                // the lines BEFORE first_line (speaker name + question);
                // the highlighted option follows as its own QUEUED
                // utterance (see the OPTION CURSOR block's interrupt
                // choice), so the TTS engine's natural utterance boundary
                // provides the pause between question and choice, and
                // each option is heard exactly once — when highlighted.
                // v2.30.6: split into per-line text for the option-cursor
                // announces below, AND read the ASK opcode's own FIRST_LINE
                // parameter (index 3, the byte right after dialog_id) to
                // know where the cursor actually starts.
                //
                // WHY NOT ASSUME 0 (v2.30.4's bug): disassembling
                // field_opcode_ask_update_loop_6310A1 (ff7_ask_lines_static.py,
                // 2026-07-20) proved the opcode carries FOUR script bytes, not
                // two — window_id(+2)/dialog_id(+3) as already known, PLUS
                // FIRST_LINE(+4)/LAST_LINE(+5): the cursor-move handlers
                // explicitly clamp the current option to
                // [FIRST_LINE, LAST_LINE] (0x631311-0x63136F). The game's
                // choice text routinely has one or more leading QUESTION
                // lines before the selectable options begin, so the cursor's
                // starting (and minimum) value is FIRST_LINE, not 0 — v2.30.4
                // assumed 0, which fired the wrong line and only on the
                // first Down/Up press instead of tracking every move (player
                // report 2026-07-20: "only one will speak and it is the
                // first choice but... at the end of the choice set instead
                // of the beginning").
                //
                // ask_lines[N] should already line up with the game's own
                // line N (FF7Text::DecodeLines splits on the identical
                // newline bytes the game itself renders as line breaks), so
                // no other index transform is needed — just the correct
                // starting baseline.
                s_window[window_id].ask_lines = FF7Text::DecodeLines(raw_text);
                const uint8_t first_line = FF7Addr::get_opcode_param_byte(3);
                const uint8_t last_line  = FF7Addr::get_opcode_param_byte(4);
                s_window[window_id].ask_first_line = first_line;
                // v2.30.13: capture the mirror's CURRENT raw value as the
                // stale baseline — this is the last moment before option
                // tracking starts, and the game's update loop may not have
                // rewritten the mirror for THIS window yet (see the
                // WindowState::ask_mirror_baseline doc comment).
                s_window[window_id].ask_mirror_baseline =
                    FF7Addr::get_ask_cursor_line(window_id);
                // v2.30.9: do NOT seed ask_last_option from first_line here --
                // that suppressed the very first OPTION CURSOR announce (see
                // the WindowState::ask_last_option doc comment). Leave it at
                // the -1 the is_new_ask_dialog branch already set, so the
                // OPTION CURSOR block below fires once for the starting
                // option, exactly like every later cursor move.

                // v2.30.13: intro = "Choose:" + CONTEXT lines only (the
                // lines before first_line — speaker name and question).
                // The options themselves are no longer in the intro; the
                // highlighted one follows as its own queued utterance.
                std::wstring announcement = L"Choose:";
                size_t ctx_end = static_cast<size_t>(first_line);
                if (ctx_end > s_window[window_id].ask_lines.size())
                    ctx_end = s_window[window_id].ask_lines.size();
                for (size_t i = 0; i < ctx_end; ++i) {
                    if (s_window[window_id].ask_lines[i].empty()) continue;
                    announcement += L' ';
                    announcement += s_window[window_id].ask_lines[i];
                }
                char dbg[96];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] ASK win=%u id=%u [PENDING] speaking (ctx=%zu) baseline=%d",
                    window_id, s_window[window_id].last_dialog_id, ctx_end,
                    s_window[window_id].ask_mirror_baseline);
                Log::Write(dbg);
                log_raw_bytes("ASK/PENDING", raw_text);
                TTS::Speak(announcement, /*interrupt=*/true);

                char lines_dbg[96];
                _snprintf_s(lines_dbg, sizeof(lines_dbg), _TRUNCATE,
                    "[FF7Access] ASK win=%u lines=%zu first_line=%u last_line=%u",
                    window_id, s_window[window_id].ask_lines.size(),
                    first_line, last_line);
                Log::Write(lines_dbg);
                // v2.30.7: dump every line's actual TEXT (not just the
                // count) -- the raw-index-vs-text mismatch class of bug
                // (v2.30.10) is only diagnosable when the log shows what
                // each split line actually holds.
                log_lines("ASK", s_window[window_id].ask_lines);
                s_window[window_id].pending_speak = false;
                s_window[window_id].last_speak_tick = GetTickCount(); // v2.30.16
            }
            // else: rawptr not ready; retry next frame
        }
        else if (closing) {
            // Same fix as hook_message: set to dialog_id (not 0xFF) to prevent
            // one-frame re-fire of the just-closed ASK on the state=7 frame.
            // (Same-id RE-ASKS are handled by the v2.30.15 from-idle re-arm.)
            s_window[window_id].pending_speak  = false;
            s_window[window_id].last_dialog_id = dialog_id;
            s_window[window_id].ask_lines.clear();      // v2.30.4
            s_window[window_id].ask_last_option = -1;
            s_window[window_id].ask_first_line  = 0;          // v2.30.13
            s_window[window_id].ask_mirror_baseline = -1;     // v2.30.13
            s_window[window_id].close_handled = true;         // v2.30.15
            char close_log[64];
            _snprintf_s(close_log, sizeof(close_log), _TRUNCATE,
                "[FF7Access] ASK win=%u CLOSE committed", window_id);
            Log::Write(close_log);
            TTS::Silence();
        }
        // v2.30.15: leaving state 7 re-arms close detection (see hook_message).
        if (current_state != 7)
            s_window[window_id].close_handled = false;

        // ------------------------------------------------------------------
        // OPTION CURSOR (v2.30.4, cursor source replaced v2.30.12):
        // announce the highlighted line on change. Runs every frame once
        // the intro has spoken (pending_speak cleared) — the cursor can
        // move on any frame, not just on a state transition, so this is
        // independent of the branches above.
        //
        // v2.30.12: reads the per-WINDOW cursor mirror (get_ask_cursor_line
        // — pixel-Y word the update loop rewrites every accepting frame),
        // NOT the old ASKMENU_OPTION global. That global turned out to be
        // the ASK opcode's per-DIALOG script variable: dialogs whose
        // bank/address params name a different variable left it stale and
        // frozen — the 2026-07-22 soldier fight-or-flee choice read 0
        // (with first_line=2, so it spoke the 'Cloud:' name line) and then
        // never tracked a single cursor move, while every Aeris choice
        // (sharing the scanned dialog's variable) worked. Full derivation
        // in ff7_addresses.h at ASK_CURSOR_PIXEL_Y.
        // get_ask_cursor_line returns -1 on a transient invalid read;
        // bounding to ask_lines' size keeps any residual bad value a
        // silent no-op, not a crash or garbage speech.
        // ------------------------------------------------------------------
        if (!s_window[window_id].pending_speak && !closing &&
            Config::Get().speak_choices && !s_window[window_id].ask_lines.empty()) {
            const int option = FF7Addr::get_ask_cursor_line(window_id);
            const bool first_announce =
                (s_window[window_id].ask_last_option == -1);
            // v2.30.13 stale-baseline suppression: until the first
            // announce, a mirror reading that still equals the value
            // captured at the PENDING frame is presumed to be the
            // PREVIOUS ASK's leftover (the update loop hasn't rewritten
            // it for this window yet) — unless it equals first_line,
            // which is correct regardless of freshness. See the
            // WindowState::ask_mirror_baseline doc comment; the
            // 2026-07-22 log showed exactly this (stale 3 announced as
            // 'Later!' at the soldier choice's open, then re-announced
            // as the real cursor arrived ~900ms later).
            const bool presumed_stale = first_announce &&
                option == s_window[window_id].ask_mirror_baseline &&
                option != static_cast<int>(s_window[window_id].ask_first_line);
            if (option >= 0 && !presumed_stale &&
                option != s_window[window_id].ask_last_option &&
                static_cast<size_t>(option) < s_window[window_id].ask_lines.size()) {
                char dbg[96];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] ASK win=%u option %d->%d%s",
                    window_id, s_window[window_id].ask_last_option, option,
                    first_announce ? " (queued)" : "");
                Log::Write(dbg);
                const std::wstring& line = s_window[window_id].ask_lines[option];
                if (!line.empty()) {
                    // v2.30.13: the FIRST announce QUEUES (interrupt=false)
                    // so it plays after the "Choose: <question>" intro
                    // finishes instead of killing it — the utterance
                    // boundary is what gives the player-requested pause
                    // between the question and the highlighted choice.
                    // Subsequent cursor moves interrupt as before (snappy
                    // response while flipping through options).
                    TTS::Speak(line, /*interrupt=*/!first_announce);
                }
                s_window[window_id].ask_last_option = option;
            }
        }

        s_window[window_id].last_opcode = current_state;
    }

    return s_old_ask(unk);
}

// ---------------------------------------------------------------------------
// Hook: STTIM opcode (0x38) — "set timer"
//
// Fires once, the instant a countdown-escape timer is (re)started. See
// s_sttim_seen's doc comment above for why TimerThread (proxy.cpp) needs
// this instead of just watching COUNTDOWN_TIMER_SECONDS's value: that
// memory is savemap state and can hold a stale, still-ticking leftover
// value from an earlier session that has nothing to do with a live escape.
//
// No script parameters are read here — STTIM's own h/m/s args go straight
// into COUNTDOWN_TIMER_SECONDS by the ORIGINAL handler (which we always
// chain to unconditionally, same as every other hook in this file); we
// only need to know THAT it fired, not decode its arguments ourselves.
// ---------------------------------------------------------------------------
static int __cdecl hook_sttim()
{
    s_sttim_seen = 1;
    Log::Write("[FF7Access] STTIM opcode fired -- countdown timer armed for this session.");
    return s_old_sttim();
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

    // --- STTIM hook (opcode 0x38) ---
    //
    // Same pattern as MESSAGE. Gives TimerThread (proxy.cpp) a live
    // "a countdown just (re)started" signal — see s_sttim_seen's doc
    // comment for why the savemap value alone isn't trustworthy on its own.
    const uint32_t sttim_entry_addr =
        reinterpret_cast<uint32_t>(FF7Addr::execute_opcode_table) + 0x38 * sizeof(uint32_t);

    s_old_sttim = reinterpret_cast<int (__cdecl*)()>(
        *reinterpret_cast<uint32_t*>(sttim_entry_addr));
    patch_dword(sttim_entry_addr, reinterpret_cast<uint32_t>(&hook_sttim));

    s_installed = true;
    Log::Write("[FF7Access] Hooks installed (MESSAGE+ASK+STTIM opcode table).");
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

    // Restore STTIM entry.
    const uint32_t sttim_entry_addr =
        reinterpret_cast<uint32_t>(FF7Addr::execute_opcode_table) + 0x38 * sizeof(uint32_t);
    if (s_old_sttim) {
        patch_dword(sttim_entry_addr, reinterpret_cast<uint32_t>(s_old_sttim));
    }

    s_installed = false;
}

// See hooks.h for full rationale. Reading a volatile DWORD is atomic on x86;
// 0 means no dialog opcode has executed yet this session.
unsigned long LastDialogActivityTick()
{
    return s_last_dialog_tick;
}

// See hooks.h for full rationale. InterlockedExchange atomically reads the
// flag and clears it in one step, so a fresh set from the game thread
// between this thread's read and its clear can never be silently dropped.
bool ConsumeDialogWaitTone()
{
    return InterlockedExchange(&s_dialog_wait_pending, 0) != 0;
}

bool ConsumeDialogChoiceTone()
{
    return InterlockedExchange(&s_dialog_choice_pending, 0) != 0;
}

// See s_sttim_seen's doc comment above and hooks.h for full rationale.
// Deliberately NOT a consume/test-and-clear — this is a sticky "has this
// happened at all yet this process run" latch, not an edge event.
bool SttimSeen()
{
    return s_sttim_seen != 0;
}

} // namespace Hooks
