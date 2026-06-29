/*
 * ff7_addresses.cpp -- Runtime address resolution for FF7 2013 Steam.
 *
 * The Resolve() function walks two address chains from known anchor functions
 * to locate the structures we need to patch:
 *
 *   Chain 1 → execute_opcode_table:
 *     FIELD_INIT_EVENT (0x60BACF)
 *       +0x80  → relative CALL → execute_opcode function
 *       +0x10D → absolute DWORD ref → execute_opcode_table pointer
 *
 *   Chain 2 → opcode_message_loop_code:
 *     OPCODE_MSG_UPDATE_LOOP (0x630D50)
 *       +0x12  → absolute DWORD ref → opcode_message_loop_code pointer
 *
 * These chains exactly replicate the discovery sequence in FFNx/src/ff7_data.h
 * lines 496, 500, and 540. The anchor addresses are confirmed fixed for all
 * known distributions of the 2013 Steam exe.
 *
 * We perform plausibility checks on each resolved address to catch cases where
 * the game is not yet initialized (the field module loads lazily) or where the
 * running exe is a different version than expected.
 */

#include "ff7_addresses.h"
#include "log.h"
#include <cstdio>

namespace FF7Addr {

// ---------------------------------------------------------------------------
// Definitions for the extern variables declared in ff7_addresses.h
// ---------------------------------------------------------------------------

// The 256-entry opcode dispatch table. Populated by Resolve().
uint32_t* execute_opcode_table = nullptr;

// Per-window dialog state array, 24-byte stride per slot. Populated by Resolve().
// Although FFNx declares this as WORD*, we treat it as uint8_t* because the state
// byte we care about is the first byte of each 24-byte slot, and BYTE* arithmetic
// with stride 24 directly addresses it. Access: opcode_message_loop_code[24 * window_id].
uint8_t* opcode_message_loop_code = nullptr;

// Set to true once Resolve() has verified all addresses.
bool resolved = false;

// ---------------------------------------------------------------------------
// Resolve: Walk address chains and validate all runtime structures.
// ---------------------------------------------------------------------------

bool Resolve()
{
    if (resolved) return true;

    // -----------------------------------------------------------------------
    // Chain 1: Locate execute_opcode_table
    //
    // Step 1a: Read the relative CALL at FIELD_INIT_EVENT + 0x80.
    //          This is the call to the execute_opcode dispatch function.
    //          Source: ff7_data.h line 496:
    //            execute_opcode = get_relative_call(field_init_event_60BACF, 0x80)
    // -----------------------------------------------------------------------
    const uint32_t execute_opcode = read_relative_call(FIELD_INIT_EVENT, 0x80);

    // Sanity: must be a plausible FF7 code segment address.
    // The 2013 Steam exe maps its code between roughly 0x401000 and 0x900000.
    if (execute_opcode < 0x401000 || execute_opcode > 0x9FFFFF) {
        Log::Write("[FF7Access] Resolve failed: execute_opcode address out of range.");
        return false;
    }

    // Step 1b: Read the absolute DWORD at execute_opcode + 0x10D.
    //          This is a MOV/LEA instruction that references the opcode table.
    //          Source: ff7_data.h line 500:
    //            execute_opcode_table = (uint32_t*)get_absolute_value(execute_opcode, 0x10D)
    const uint32_t table_ptr = read_abs_ref_at(execute_opcode, 0x10D);

    // Sanity: must be a plausible data segment address.
    if (table_ptr < 0x400000 || table_ptr > 0xF0000000UL) {
        Log::Write("[FF7Access] Resolve failed: execute_opcode_table pointer out of range.");
        return false;
    }

    // Step 1c: Verify the table's MESSAGE entry (opcode 0x40) is populated AND that
    //          FFNx has finished reading from it before we overwrite it.
    //
    // THE RACE CONDITION THIS CHECK PREVENTS:
    //   FFNx's common_create_window (common.cpp:989) calls ff7_init_hooks, which
    //   calls ff7_find_externals. That function reads execute_opcode_table[0x40] to
    //   locate opcode_message, then walks the function's machine code via
    //   get_relative_call(opcode_message, 0x3B) to find dependent addresses.
    //
    //   After ff7_init_hooks returns, common_create_window calls voice_init()
    //   (common.cpp:1027), which unconditionally patches table[0x40] to FFNx's
    //   own opcode_voice_message handler (in AF3DN.P, ~0x69xxxxxx).
    //
    //   If we install our hook (setting table[0x40] to our version.dll function)
    //   BEFORE voice_init() runs, then ff7_find_externals may still be in progress
    //   (or may read the table in a second pass). It will find our hook function
    //   (0x705Axxxx, inside version.dll) and try to walk its code via
    //   get_relative_call. Our naked JMP stub contains 0xF800 at offset +0x3B —
    //   not a recognizable CALL instruction — so FFNx logs a WARNING, computes a
    //   garbage address, then crashes in get_absolute_value dereferencing that garbage.
    //
    // CORRECT INSTALLATION ORDER:
    //   1. ff7_find_externals reads table[0x40] (sees FF7 original, ~0x630D50)
    //   2. voice_init() patches table[0x40] to opcode_voice_message (~0x69xxxxxx)
    //   3. We install: table[0x40] = our hook, saving the FFNx handler as previous
    //
    // DETECTION: once voice_init() has patched the entry, msg_handler moves from
    //   the FF7 exe range (0x401000–0x9FFFFF) into a DLL range (> 0x9FFFFF). We
    //   use GetModuleHandleA("AF3DN.P") to confirm FFNx is present, then require
    //   the entry to be outside the FF7 exe range before proceeding.
    //
    // WITHOUT FFNx: voice_init() never runs, so the table keeps the FF7 original
    //   handler forever. We skip the FFNx check and accept the original value.
    const uint32_t msg_handler = reinterpret_cast<const uint32_t*>(table_ptr)[0x40];

    if (msg_handler < 0x401000) {
        // Zero or near-zero — field module not yet loaded, table not populated.
        // Also rejects PE header addresses (0x400000–0x400FFF) which are not code.
        return false;
    }

    // If FFNx (AF3DN.P) is running, wait until voice_init() has patched table[0x40].
    // voice_init() sets the entry to opcode_voice_message in AF3DN.P, which resides
    // above 0x9FFFFF. While the entry is still in the FF7 exe range (0x401000–0x9FFFFF),
    // ff7_find_externals may still be active — installing our hook now is the crash.
    if (GetModuleHandleA("AF3DN.P") != nullptr && msg_handler <= 0x9FFFFF) {
        // FFNx is loaded but voice_init() has not yet run. Retry in 50ms.
        // This window is very short: voice_init() runs in the same common_create_window
        // call that triggered ff7_find_externals, so this condition clears quickly.
        return false;
    }

    execute_opcode_table = reinterpret_cast<uint32_t*>(table_ptr);

    // -----------------------------------------------------------------------
    // Chain 2: Locate opcode_message_loop_code
    //
    // Read the absolute DWORD at OPCODE_MSG_UPDATE_LOOP + 0x12.
    // This is a MOV/LEA inside field_opcode_message_update_loop_630D50 that
    // references the start of the dialog state array.
    // Source: ff7_data.h line 540:
    //   opcode_message_loop_code = (WORD*)get_absolute_value(
    //       field_opcode_message_update_loop_630D50, 0x12)
    // -----------------------------------------------------------------------
    const uint32_t state_ptr = read_abs_ref_at(OPCODE_MSG_UPDATE_LOOP, 0x12);

    if (state_ptr < 0x400000 || state_ptr > 0xF0000000UL) {
        Log::Write("[FF7Access] Resolve failed: opcode_message_loop_code pointer out of range.");
        // Roll back the opcode table pointer so the next Resolve() call retries.
        execute_opcode_table = nullptr;
        return false;
    }

    opcode_message_loop_code = reinterpret_cast<uint8_t*>(state_ptr);

    resolved = true;
    Log::Write("[FF7Access] Address resolution succeeded.");
    return true;
}

// ---------------------------------------------------------------------------
// validate_offset_table: Sanity-check a candidate string offset table.
//
// Confirms that the first few offset entries are monotonically non-decreasing
// starting from offsets[0] (== first_off == num_dialogs * 2). This
// distinguishes a genuine dialog offset table from coincidental binary data
// (e.g., entity bytecodes) that happens to pass the first_off range check.
//
// WHY 4 ENTRIES: checking offsets[1..3] gives very high false-positive
// rejection at near-zero cost. A table with random bytes at index 1 that
// happen to be < first_off would also fail index 2 most of the time.
// Checking more than 4 gives diminishing returns and adds loop overhead.
// ---------------------------------------------------------------------------
static bool validate_offset_table(const uint16_t* offsets, uint16_t num_dialogs)
{
    const int check_n = (num_dialogs < 4) ? (int)num_dialogs : 4;
    uint16_t prev = offsets[0]; // == first_off, already range-checked by caller
    for (int j = 1; j < check_n; ++j) {
        if (offsets[j] < prev) return false;
        prev = offsets[j];
    }
    return true;
}

// ---------------------------------------------------------------------------
// get_field_dialog_text: Implementation — see ff7_addresses.h for the full
// contract, parameters, and design rationale.
// ---------------------------------------------------------------------------
const char* get_field_dialog_text(uint8_t dialog_id)
{
    const char* const buf = *reinterpret_cast<const char* const*>(FIELD_FILE_BUFFER);
    if (!buf) return nullptr;

    const char* const script_data = *reinterpret_cast<const char* const*>(FIELD_SCRIPT_PTR);

    // ── PRIMARY: script section via wStringOffset ──────────────────────────
    // The dialog offset table lives at script_data + wStringOffset.
    if (script_data) {
        const uint16_t wStringOffset =
            *reinterpret_cast<const uint16_t*>(script_data + 4);

        // wStringOffset sanity: must be past the 6-byte header minimum and
        // within a reasonable range (no field script section exceeds 60 KB).
        if (wStringOffset >= 6u && wStringOffset <= 60000u) {
            const uint16_t* const offsets =
                reinterpret_cast<const uint16_t*>(script_data + wStringOffset);

            // offsets[0] == num_dialogs * 2: must be even, in [2, 2048].
            const uint16_t first_off = offsets[0];
            if (first_off >= 2u && first_off <= 2048u && (first_off & 1u) == 0u) {
                const uint16_t num_dialogs = first_off / 2u;

                if (dialog_id < num_dialogs &&
                    validate_offset_table(offsets, num_dialogs)) {
                    const uint16_t text_off = offsets[dialog_id];
                    if (text_off >= first_off) {
                        const char* const text =
                            reinterpret_cast<const char*>(offsets) + text_off;
                        // 0xFF = empty string; skip rather than return garbage.
                        if (*reinterpret_cast<const uint8_t*>(text) != 0xFFu) {
                            return text;
                        }
                    }
                }
            }
        }
    }

    // ── FALLBACK: search other field file sections ─────────────────────────
    // Some dialogs (observed: Field 2 "Get down here, Merc!" for id=6) live
    // in a section OTHER than the primary script section. When the primary
    // lookup fails (dialog_id >= num_dialogs in section 0, or wStringOffset
    // is invalid), we scan all 9 sections for an offset table that covers
    // dialog_id. The script section is excluded because its leading uint16
    // (nEntities or unknown1) could coincidentally look like a valid offset
    // table and return entity bytecodes as if they were dialog text.
    for (int si = 0; si < 9; ++si) {
        const uint32_t sect_off =
            *reinterpret_cast<const uint32_t*>(buf + 6 + si * 4);
        if (sect_off < 0x2Au || sect_off > 512u * 1024u) continue;

        const char* const sect = buf + sect_off + 4; // past the 4-byte size DWORD
        if (script_data && sect == script_data) continue; // skip script section

        const uint16_t* const offsets = reinterpret_cast<const uint16_t*>(sect);
        const uint16_t first_off = offsets[0];
        if (first_off < 2u || first_off > 2048u || (first_off & 1u) != 0u) continue;

        const uint16_t num_dialogs = first_off / 2u;
        if (dialog_id >= num_dialogs) continue;
        if (!validate_offset_table(offsets, num_dialogs)) continue;

        const uint16_t text_off = offsets[dialog_id];
        if (text_off < first_off) continue;

        // Log which section the dialog came from. This fires at most once per
        // dialog encounter (hooks.cpp only calls us on dialog_id changes).
        // Knowing the section index tells us which field file layout is in use
        // and confirms the primary section didn't cover this dialog_id.
        {
            char diag[80];
            _snprintf_s(diag, sizeof(diag), _TRUNCATE,
                "[FF7Access] FF7Addr: id=%u found in fallback section %d",
                (unsigned)dialog_id, si);
            Log::Write(diag);
        }
        return sect + text_off;
    }

    return nullptr;
}

} // namespace FF7Addr
