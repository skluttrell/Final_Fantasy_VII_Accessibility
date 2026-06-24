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
        OutputDebugStringA("[FF7Access] Resolve failed: execute_opcode address out of range.\n");
        return false;
    }

    // Step 1b: Read the absolute DWORD at execute_opcode + 0x10D.
    //          This is a MOV/LEA instruction that references the opcode table.
    //          Source: ff7_data.h line 500:
    //            execute_opcode_table = (uint32_t*)get_absolute_value(execute_opcode, 0x10D)
    const uint32_t table_ptr = read_abs_ref_at(execute_opcode, 0x10D);

    // Sanity: must be a plausible data segment address.
    if (table_ptr < 0x400000 || table_ptr > 0xF0000000UL) {
        OutputDebugStringA("[FF7Access] Resolve failed: execute_opcode_table pointer out of range.\n");
        return false;
    }

    // Step 1c: Verify the table's MESSAGE entry (opcode 0x40) points somewhere
    //          plausible. If the field module hasn't initialized yet, this entry
    //          will be 0 or an invalid address. We use this to detect "not ready."
    const uint32_t msg_handler = reinterpret_cast<const uint32_t*>(table_ptr)[0x40];
    if (msg_handler < 0x401000 || msg_handler > 0x9FFFFF) {
        // This is the most common early-call case: timeGetTime fired before the
        // field module populated the opcode table. Return false so the caller
        // will retry on the next timeGetTime call.
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
        OutputDebugStringA("[FF7Access] Resolve failed: opcode_message_loop_code pointer out of range.\n");
        // Roll back the opcode table pointer so the next Resolve() call retries.
        execute_opcode_table = nullptr;
        return false;
    }

    opcode_message_loop_code = reinterpret_cast<uint8_t*>(state_ptr);

    resolved = true;
    OutputDebugStringA("[FF7Access] Address resolution succeeded.\n");
    return true;
}

} // namespace FF7Addr
