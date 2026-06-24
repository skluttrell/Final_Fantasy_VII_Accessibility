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
 * ----- DIALOG STATE MACHINE -----
 *
 *   MESSAGE and ASK opcode handlers are called every game frame while their
 *   respective windows are open. The state byte at
 *   opcode_message_loop_code[24 * window_id] tracks each window's lifecycle:
 *
 *     last_state == 0, current != 0   → dialog starting (speak text now)
 *     last == 14, current == 2        → page advance (speak new page)
 *     last == 4,  current == 8        → page advance (alternate ATB path)
 *     current == 7                    → dialog closing (silence TTS)
 *
 *   Source: FFNx/src/voice.cpp — is_dialog_starting, is_dialog_paging,
 *           is_dialog_closing conditions in opcode_voice_message.
 *
 * ----- ASK (v1) DESIGN -----
 *
 *   Speaks the full ASK dialog text (question + all option lines) once when
 *   the dialog first appears. The player hears all available choices upfront.
 *   Per-option TTS on cursor movement is deferred to v2 (see note above).
 *
 *   ASK opcode parameter layout (FF7 field script spec):
 *     param[0] = bank, param[1] = address_in_bank,
 *     param[2] = window_id, param[3] = dialog_id,
 *     param[4] = first_option, param[5] = last_option
 *   NOTE: verify window_id index during testing — spec sources are not unanimous.
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
    uint8_t last_opcode = 0;  // State byte from the previous frame
    uint8_t page_count  = 0;  // Pages shown so far (reserved for future use)
};
static WindowState s_window[8];

// Whether our hooks are currently installed.
static bool s_installed = false;

// ---------------------------------------------------------------------------
// Hook: MESSAGE opcode (0x40)
//
// Called every game frame while a MESSAGE dialog window is open.
// FF7's field script VM calls execute_opcode_table[0x40]() on each frame
// until the player dismisses the dialog.
//
// We detect state transitions to know when to speak:
//   - Dialog starting: read and speak the full dialog text.
//   - Page advance:    read and speak the new page's text.
//   - Dialog closing:  silence ongoing TTS.
//
// Calling convention: __cdecl (confirmed from FFNx's opcode_voice_message).
// ---------------------------------------------------------------------------
static int __cdecl hook_message()
{
    // Read the parameters for this MESSAGE invocation from the field script VM's
    // execution context. This replicates get_field_parameter<byte>(0/1) from
    // FFNx/src/field.h. The script pointer and position are maintained by the
    // VM between calls, so these values are valid here before chaining.
    const uint8_t window_id = FF7Addr::get_opcode_param_byte(0);
    const uint8_t dialog_id = FF7Addr::get_opcode_param_byte(1);
    (void)dialog_id; // Reserved for voice file detection in a future version.

    // Guard: clamp window_id to the valid range.
    // Corrupted scripts could theoretically produce out-of-range IDs.
    if (window_id >= 8) {
        return s_old_message();
    }

    // Read the current dialog state for this window from the game's state array.
    // This is the state set by last frame's original handler — the current frame's
    // handler hasn't run yet (we chain to it below).
    const uint8_t current_state = FF7Addr::get_dialog_state(window_id);
    const uint8_t last_state    = s_window[window_id].last_opcode;

    // Detect dialog lifecycle transitions (from voice.cpp is_dialog_* helpers).
    const bool starting = (last_state == 0 && current_state != 0);
    const bool paging   = (last_state == 14 && current_state == 2) ||
                          (last_state == 4  && current_state == 8);
    const bool closing  = (last_state != 7 && current_state == 7);

    if ((starting || paging) && Config::Get().speak_dialog) {
        // Get the encoded text pointer for this window from the game's pointer array.
        const char* raw_text = FF7Addr::get_dialog_text_ptr(window_id);
        if (raw_text) {
            const std::wstring decoded = FF7Text::Decode(raw_text);
            if (!decoded.empty()) {
                // Interrupt on starting (new dialog is higher priority than anything
                // currently being spoken). On paging, also interrupt — the player
                // explicitly advanced, so they want the new text immediately.
                TTS::Speak(decoded, /*interrupt=*/true);
            }
        }
        if (paging) {
            s_window[window_id].page_count++;
        }
    }
    else if (closing) {
        // The player dismissed the dialog. Stop any ongoing speech — the dialog
        // text is no longer relevant and we don't want TTS still reading it
        // as the next scene starts.
        TTS::Silence();
    }

    // Save the current state for next frame's transition detection.
    s_window[window_id].last_opcode = current_state;

    // Chain to the previously-installed handler (FFNx voice handler or FF7 original).
    // This is unconditional — we never swallow this call.
    return s_old_message();
}

// ---------------------------------------------------------------------------
// Hook: ASK opcode (0x48)
//
// Called every frame while a choice-menu dialog is open.
//
// v1 behavior: speak the full ASK dialog text on dialog start. The text
// includes the question (if any) and all option lines separated by newlines.
// This gives the blind user all the information they need to make a choice.
//
// Per-option TTS (speak only the currently-highlighted option as the cursor
// moves) is deferred to v2. It requires patching the CALL to
// field_opcode_ask_update_loop_6310A1 inside FF7's ORIGINAL opcode_ask
// function at offset +0x8E. That approach is unsafe here because FFNx has
// already replaced execute_opcode_table[0x48] with its own handler by the
// time our hooks install — so s_old_ask points to FFNx's compiled function,
// not FF7's opcode_ask, and the +0x8E offset into FFNx's code is meaningless.
// ---------------------------------------------------------------------------
static int __cdecl hook_ask(int unk)
{
    // ASK parameter layout (FF7 field script spec):
    //   param[0] = bank, param[1] = address_in_bank,
    //   param[2] = window_id, param[3] = dialog_id,
    //   param[4] = first_option, param[5] = last_option
    // Window_id is therefore at index 2 (unlike MESSAGE where it is at index 0).
    // VERIFY DURING TESTING: some spec documents list different orderings.
    const uint8_t window_id = FF7Addr::get_opcode_param_byte(2);

    if (window_id >= 8) {
        return s_old_ask(unk);
    }

    const uint8_t current_state = FF7Addr::get_dialog_state(window_id);
    const uint8_t last_state    = s_window[window_id].last_opcode;

    const bool starting = (last_state == 0 && current_state != 0);
    const bool closing  = (last_state != 7 && current_state == 7);

    if (starting && Config::Get().speak_choices) {
        const char* raw_text = FF7Addr::get_dialog_text_ptr(window_id);
        if (raw_text) {
            const std::wstring decoded = FF7Text::Decode(raw_text);
            if (!decoded.empty()) {
                // Prepend "Choose:" so the user immediately knows a decision is
                // needed, distinguishing ASK from passive MESSAGE narration.
                std::wstring announcement = L"Choose: ";
                announcement += decoded;
                TTS::Speak(announcement, /*interrupt=*/true);
            }
        }
    }
    else if (closing) {
        TTS::Silence();
    }

    s_window[window_id].last_opcode = current_state;

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
    OutputDebugStringA("[FF7Access] Hooks installed (MESSAGE+ASK opcode table).\n");
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
