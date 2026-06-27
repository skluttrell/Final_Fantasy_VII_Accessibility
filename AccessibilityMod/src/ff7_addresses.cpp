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

} // namespace FF7Addr
