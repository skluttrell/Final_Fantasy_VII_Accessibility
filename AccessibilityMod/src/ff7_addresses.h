/*
 * ff7_addresses.h -- Absolute and dynamically-derived memory addresses for
 *                    Final Fantasy VII 2013 Steam Edition.
 *
 * The 2013 Steam exe is functionally identical to the 1.02 US retail build.
 * All addresses here have been confirmed from two sources:
 *
 *   FFNx/src/externals_102_us.h  -- hardcoded anchors used by FFNx
 *   FFNx/src/ff7_data.h           -- dynamic discovery chains (the authoritative
 *                                    reference for how to find any runtime address)
 *   FFNx/src/ff7.h                -- structure definitions with commented addresses
 *   FFNx/src/field.h              -- get_field_parameter implementation
 *   FFNx/src/voice.cpp            -- dialog state machine, opcode hook pattern
 *
 * IMPORTANT: This module must be compiled for x86 (32-bit). All pointer
 * arithmetic assumes a flat 32-bit address space. Building as x64 will
 * produce wrong casts and corrupt game memory.
 *
 * ----- How the dynamic discovery works -----
 *
 * FFNx locates most runtime structures by walking relative CALL instruction
 * chains from known anchor functions. An anchor function's absolute address is
 * embedded in FFNx's naming convention: "field_init_event_60BACF" lives at
 * 0x60BACF. From there, two helper operations are used:
 *
 *   read_relative_call(base, offset):
 *     Reads the E8 xx xx xx xx relative CALL at (base+offset).
 *     Returns the absolute target address:
 *       target = base + offset + 5 + *(int32_t*)(base + offset + 1)
 *
 *   read_absolute_ref(base, offset):
 *     Reads a 4-byte absolute address that an instruction MOVs/LEAs from
 *     at (base+offset+N) where N varies by instruction encoding.
 *     For a simple "MOV eax, [imm32]": N=2, data is *(uint32_t*)(base+offset+2)
 *     For a "PUSH imm32":              N=1, data is *(uint32_t*)(base+offset+1)
 *     The exact N for each resolved value is taken from ff7_data.h.
 *
 * We replicate the chains here in a simplified form appropriate for our
 * single-purpose use case.
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

namespace FF7Addr {

// ---------------------------------------------------------------------------
// SECTION 1: Hardcoded absolute anchors (from externals_102_us.h and ff7.h)
//
// These values are fixed for the 2013 Steam exe. They are our entry points
// for all dynamic discovery below.
// ---------------------------------------------------------------------------

// The base address of the 4340-byte savemap region. This mirrors the save
// file layout and contains persistent game state: HP/MP, position, flags.
// Source: ff7_externals.savemap = (savemap*)0xDBFD38 in externals_102_us.h
constexpr uint32_t SAVEMAP_BASE = 0xDBFD38;

// Global menu objects container. The cursor positions for main menu screens
// live somewhere in this structure; exact offsets require further RE.
// Source: ff7_externals.menu_objects = (menu_objects*)0xDC0FC0
constexpr uint32_t MENU_OBJECTS = 0xDC0FC0;

// The function that constructs and shows a dialog window. We do not hook this
// directly for TTS (we hook the opcode instead), but it is a useful anchor
// for locating other dialog-related structures.
// Source: common_externals.build_dialog_window = 0x6E97E0
constexpr uint32_t BUILD_DIALOG_WINDOW = 0x6E97E0;

// Array of pointers to the current dialog text for each window slot.
// text = *(const char**)(DIALOG_TEXT_PTRS + window_id * 4)
// FF7 supports up to 8 simultaneous dialog windows (window IDs 0–7).
// Each element is a DWORD holding the address of an encoded FF7 string,
// or zero if that window slot is unused.
//
// IMPORTANT — VOLATILE TYPEWRITER POINTER:
//   This pointer advances byte-by-byte as the typewriter animation progresses.
//   Reading it mid-dialog gives partial text starting at the current typewriter
//   position, not the beginning of the dialog. For the complete static text,
//   use get_field_dialog_text(dialog_id) which reads from the static text section.
// Source: ff7_externals.current_dialog_string_pointer // 0xCBF578 in ff7.h
constexpr uint32_t DIALOG_TEXT_PTRS = 0xCBF578;

// Pointer to the decompressed field file buffer.
// The 4-byte value AT this address IS the buffer base address (single dereference).
// buf = *(char**)FIELD_FILE_BUFFER
//
// The buffer contains the raw decompressed field file with this layout:
//   buf+0  : uint32 padding (0x00000000)
//   buf+4  : uint16 num_sections (= 9 for field files)
//   buf+6  : uint32[9] section_offsets — each is a byte offset from buf start
//   Each section: uint32 section_size | uint8 section_data[]
//   Dialog text section index: unknown — confirmed NOT section 7 (background)
//   or section 8 (triggers). get_field_dialog_text() searches all sections.
//
// Source: ff7_externals.field_file_buffer = (byte*)0xCFF594 in externals_102_us.h
//         FF7_FIELD_OFFSET=0x2A, FF7_FIELD_NUM_SECTIONS=9 in ff7/file.cpp
constexpr uint32_t FIELD_FILE_BUFFER = 0xCFF594;

// Pointer-to-pointer to the current field's script byte array.
// *(byte**)FIELD_SCRIPT_PTR == the start of the script data buffer.
// Field opcode parameters are read relative to the current entity's
// execution position within this buffer.
// Source: ff7_externals.field_script_ptr // 0xCBF5E8 in ff7_data.h
constexpr uint32_t FIELD_SCRIPT_PTR = 0xCBF5E8;

// Array of WORD values: the current byte-offset into the script buffer
// for each entity (one per entity slot, up to 64 entities).
// Indexed by the current entity ID.
// Source: ff7_externals.field_curr_script_position // 0xCC0CF8 in ff7_data.h
constexpr uint32_t FIELD_CURR_SCRIPT_POS = 0xCC0CF8;

// The ID (0–63) of the field entity whose script is currently executing.
// Used to index FIELD_CURR_SCRIPT_POS to find the current script position.
// Source: ff7_externals.current_entity_id // 0xCC0964 in ff7_data.h
constexpr uint32_t CURRENT_ENTITY_ID = 0xCC0964;

// ---------------------------------------------------------------------------
// Named anchor functions whose absolute addresses are known from FFNx's
// naming convention. These are the starting points for dynamic discovery.
// ---------------------------------------------------------------------------

// The field module's event initializer. Contains a CALL at +0x80 to the
// opcode dispatch function (execute_opcode), from which the opcode table
// is derived.
// Source: field_init_event_60BACF → address from name
constexpr uint32_t FIELD_INIT_EVENT = 0x60BACF;

// The update loop for the MESSAGE opcode (0x40). Contains at offset +0x12
// an absolute reference to the dialog state byte array (opcode_message_loop_code).
// Source: field_opcode_message_update_loop_630D50 → address from name
constexpr uint32_t OPCODE_MSG_UPDATE_LOOP = 0x630D50;

// The hook target for ASK option tracking.
// The ASK opcode handler (opcode_ask) calls this function at offset +0x8E.
// We replace that CALL with a CALL to our own option-change detector.
// Source: field_opcode_ask_update_loop_6310A1 → address from name
constexpr uint32_t OPCODE_ASK_UPDATE_LOOP = 0x6310A1;

// Battle action text display. We replace this function's entry with a JMP
// to our handler to announce battle actions via TTS.
// Source: display_battle_action_text_42782A → address from name
constexpr uint32_t DISPLAY_BATTLE_ACTION_TEXT = 0x42782A;

// World map MESSAGE handler. The world map module does NOT use the same
// opcode table as field maps; its message rendering is called via different
// code paths. We patch those call sites to intercept world map dialog.
// Source: world_opcode_message_sub_75EE86 → address from name
constexpr uint32_t WORLD_OPCODE_MESSAGE = 0x75EE86;

// World map ASK handler (same situation as WORLD_OPCODE_MESSAGE).
// Source: world_opcode_ask_sub_75EEBB → address from name
constexpr uint32_t WORLD_OPCODE_ASK = 0x75EEBB;

// ---------------------------------------------------------------------------
// SECTION 2: Runtime-resolved addresses
//
// These are populated by FF7Addr::Resolve() during DLL initialization.
// They are derived from the anchors above using the same logic as ff7_data.h.
// ---------------------------------------------------------------------------

// The opcode dispatch table — a uint32_t array of 256 function pointers,
// one per opcode. execute_opcode_table[0x40] = original MESSAGE handler,
// execute_opcode_table[0x48] = original ASK handler.
// We patch these entries to install our hooks.
// Resolved from: FIELD_INIT_EVENT → +0x80 relative call → execute_opcode func
//            then: execute_opcode → +0x10D absolute ref → table pointer
extern uint32_t* execute_opcode_table;

// Dialog state tracking array. 24-byte stride per window slot.
// opcode_message_loop_code[24 * window_id] = the dialog state byte for window N.
//
// State values (from voice.cpp is_dialog_* helpers):
//   0        → window closed / just opening (before first page)
//   0→nonzero → dialog starting (speak text now)
//   14→2      → page advance (speak next page text)
//   4→8       → page advance (alternate paging state pair)
//   any→7    → dialog closing (silence TTS)
//
// This is a BYTE array addressed as uint8_t*; stride is 24 bytes per slot.
// Resolved from: OPCODE_MSG_UPDATE_LOOP → +0x12 absolute ref
extern uint8_t* opcode_message_loop_code;

// Flag indicating whether Resolve() has completed successfully.
extern bool resolved;

// ---------------------------------------------------------------------------
// SECTION 3: Helper functions for dynamic address discovery
// ---------------------------------------------------------------------------

/*
 * read_relative_call: Follow a relative CALL instruction at (base + offset).
 *
 * A relative CALL is encoded as:  E8 [rel32]
 * where rel32 is a signed 4-byte displacement relative to the next instruction.
 * The target = (base + offset + 5) + rel32
 *
 * This is the read_relative_call operation from ff7_data.h.
 * It does NOT modify game memory; it only reads.
 */
inline uint32_t read_relative_call(uint32_t base, uint32_t offset)
{
    // Read the signed 32-bit displacement immediately after the E8 opcode byte.
    // The E8 is at (base + offset), the displacement is at (base + offset + 1).
    int32_t rel = *reinterpret_cast<const int32_t*>(base + offset + 1);
    // Target = address of the byte AFTER the CALL (base+offset+5) plus displacement.
    return static_cast<uint32_t>(base + offset + 5 + rel);
}

/*
 * read_abs_ref_at: Read a 4-byte absolute address embedded in code at a
 * known byte offset from a base address.
 *
 * This covers instruction encodings like:
 *   MOV eax, [imm32]   ; opcode A1, address at +1
 *   PUSH imm32          ; opcode 68, address at +1
 *   MOV eax, imm32      ; opcode B8, address at +1
 *   CMP eax, [imm32]    ; opcode 3B 05, address at +2
 *
 * The exact byte_offset used for each resolved address is taken from
 * ff7_data.h's get_absolute_value() calls, which encode the per-instruction
 * offset implicitly. We hardcode the specific offsets we need here.
 */
inline uint32_t read_abs_ref_at(uint32_t addr, uint32_t byte_offset)
{
    return *reinterpret_cast<const uint32_t*>(addr + byte_offset);
}

/*
 * Resolve: Walk the dynamic discovery chains and populate execute_opcode_table
 * and opcode_message_loop_code.
 *
 * Must be called after the game has finished initializing (the opcode table
 * is only populated once the field module's init function has run).
 * The background init thread (proxy.cpp) polls this until it returns true.
 *
 * Returns true if all addresses were resolved successfully.
 * Returns false if any pointer looks invalid (game not yet initialized,
 * or wrong exe version).
 */
bool Resolve();

/*
 * get_opcode_param_byte: Read one parameter byte from the currently-executing
 * field script opcode.
 *
 * When an opcode handler is called, the field script VM has positioned the
 * script pointer at the opcode byte. Parameters follow immediately after.
 * index=0 → first parameter (script[curr_pos + 1])
 * index=1 → second parameter (script[curr_pos + 2])
 *
 * This replicates field.h's get_field_parameter<byte>(id):
 *   byte* script = **(byte***)FIELD_SCRIPT_PTR;
 *   uint8_t entity = *(uint8_t*)CURRENT_ENTITY_ID;
 *   uint16_t pos   = ((uint16_t*)FIELD_CURR_SCRIPT_POS)[entity];
 *   return script[pos + 1 + index];
 *
 * Only valid while inside an opcode hook function (i.e., called from the
 * field script VM's dispatch loop).
 */
inline uint8_t get_opcode_param_byte(int index)
{
    // Dereference the pointer-to-pointer to get the script data buffer.
    const uint8_t* script = *reinterpret_cast<const uint8_t* const*>(FIELD_SCRIPT_PTR);
    // Get the current entity (0..63).
    const uint8_t entity_id = *reinterpret_cast<const uint8_t*>(CURRENT_ENTITY_ID);
    // Get that entity's current execution offset into the script buffer.
    const uint16_t script_pos = reinterpret_cast<const uint16_t*>(FIELD_CURR_SCRIPT_POS)[entity_id];
    // Skip past the opcode byte (+1) and index to the parameter.
    return script[script_pos + 1 + index];
}

/*
 * get_dialog_state: Return the dialog state byte for a given window slot.
 *
 * Equivalent to FFNx's get_dialog_opcode(window_id):
 *   return opcode_message_loop_code[24 * window_id];
 *
 * The state byte drives the dialog state machine:
 *   0 → closed/opening (before any text is shown)
 *   Non-zero (via 0→N transition) → dialog started (speak the text)
 *   14→2 or 4→8 → page advanced (speak the next page text)
 *   →7 → closing (silence TTS)
 *
 * Only valid after Resolve() has returned true.
 */
inline uint8_t get_dialog_state(uint8_t window_id)
{
    // The stride between window slots is 24 bytes. The state byte is
    // the first byte of each slot.
    return opcode_message_loop_code[24 * window_id];
}

/*
 * get_dialog_text_ptr: Return the volatile typewriter pointer to the encoded
 * FF7 dialog text for the given window slot, or nullptr if the slot is unused.
 *
 * WARNING: This pointer advances byte-by-byte as the typewriter animation
 * progresses. Reading it mid-dialog yields partial text. Prefer
 * get_field_dialog_text(dialog_id) for complete, static dialog text.
 *
 * Equivalent to accessing ff7_externals.current_dialog_string_pointer[window_id].
 */
inline const char* get_dialog_text_ptr(uint8_t window_id)
{
    return *reinterpret_cast<const char* const*>(DIALOG_TEXT_PTRS + window_id * sizeof(uint32_t));
}

/*
 * get_field_dialog_text: Return a pointer to the complete static FF7-encoded
 * text for dialog_id from the current field's text section. Returns nullptr if
 * the field buffer is not loaded, dialog_id is out of range, or no section
 * matching the text-section format can be found.
 *
 * WHY THIS SEARCHES ALL SECTIONS:
 *   The text section index is not fixed. Diagnostic logging confirmed that
 *   sections 7 and 8 are the background and trigger sections respectively —
 *   neither is the text section. The actual text section appears to be at a
 *   lower index (likely 0–6). By searching all 9 sections and applying format
 *   validation, we identify the correct section at runtime without hardcoding.
 *
 * TEXT SECTION FORMAT (any section that passes validation):
 *   uint16[num_dialogs] offsets  — each is a byte offset from section_data start
 *   text_data[]
 *   offsets[0] == num_dialogs * 2  (size of the offset table in bytes)
 *   All subsequent offsets must be >= offsets[0] (no overlap with offset table).
 *
 * Source: FF7 field file format; FFNx ff7/file.cpp (FF7_FIELD_OFFSET=0x2A);
 *         FFNx kernel2_get_text: text = section_data + ((uint16_t*)section_data)[id]
 */
inline const char* get_field_dialog_text(uint8_t dialog_id)
{
    // Dereference FIELD_FILE_BUFFER to get the base of the decompressed field file.
    const char* const buf = *reinterpret_cast<const char* const*>(FIELD_FILE_BUFFER);
    if (!buf) return nullptr;

    // Identify the script section so we can skip it. The script section starts with
    // uint16 entity_count, which might coincidentally look like a valid first_off.
    // field_script_ptr at FIELD_SCRIPT_PTR holds the absolute address of script data
    // (after the 4-byte size DWORD), so sect == script_data means "this is the script".
    const char* const script_data = *reinterpret_cast<const char* const*>(FIELD_SCRIPT_PTR);

    // Search all 9 sections for the one that matches the text-section format.
    // Section i offset entry: *(uint32_t*)(buf + 6 + i*4)
    // Section i data: buf + section_offset + 4  (skip the 4-byte size prefix)
    for (int si = 0; si < 9; ++si) {
        const uint32_t sect_off =
            *reinterpret_cast<const uint32_t*>(buf + 6 + si * 4);

        // Section offset must be at least past the 42-byte file header and within 512 KB.
        if (sect_off < 0x2Au || sect_off > 512u * 1024u) continue;

        const char* const sect = buf + sect_off + 4; // skip 4-byte size DWORD

        // Skip the script section: its uint16 entity_count could coincidentally
        // fall in our validation range, returning bytecode as if it were dialog text.
        if (script_data && sect == script_data) continue;

        // Text section validation:
        //   offsets[0] == num_dialogs * 2 — must be even, 2–2048 (1–1024 dialogs).
        const uint16_t first_off = *reinterpret_cast<const uint16_t*>(sect);
        if (first_off < 2u || first_off > 2048u || (first_off & 1u) != 0u) continue;

        const uint16_t num_dialogs = first_off / 2u;
        if (dialog_id >= num_dialogs) continue;

        // Additional validation: the next few offsets must be >= first_off
        // (text cannot overlap the offset table) and must be monotonically non-decreasing.
        // Checking 4 entries is enough to distinguish the text section from binary data.
        bool valid = true;
        const int check_n = (num_dialogs < 4) ? num_dialogs : 4;
        uint16_t prev = first_off;
        for (int j = 1; j < check_n && valid; ++j) {
            const uint16_t off_j =
                reinterpret_cast<const uint16_t*>(sect)[j];
            if (off_j < prev) valid = false;
            prev = off_j;
        }
        if (!valid) continue;

        const uint16_t text_off = reinterpret_cast<const uint16_t*>(sect)[dialog_id];
        if (text_off < first_off) continue; // Text would overlap the offset table.

        return sect + text_off;
    }

    return nullptr;
}

} // namespace FF7Addr
