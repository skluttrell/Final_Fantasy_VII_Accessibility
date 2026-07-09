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
//   position, not the beginning of the dialog.
//
// CORRECT USAGE: read this pointer ONE FRAME AFTER the dialog_id changes (the
//   pending_speak pattern in hooks.cpp). The engine's s_old_message() writes the
//   correct value during the same frame the MESSAGE opcode executes; reading one
//   frame later captures the fully-initialized pointer.
//
// DO NOT use get_field_dialog_text(dialog_id) as an alternative. That function
//   reads from section 0's offset table, but dialog_id is entity-relative — two
//   different entities can share dialog_id=6 for completely different text. For
//   any entity that is not the section-0 entity, it returns the wrong string.
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
//   Dialog text is embedded in section 0 (script section), accessed via the
//   wStringOffset field of ff7_field_script_header at script_data+4.
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

// The numeric ID of the currently loaded field map (0 = none/title/world/battle).
// Changes whenever the player transitions to a new field location.
// Useful as a "player is in a named field" indicator: non-zero while in a
// field map, zero (or unchanged) during title screen, world map, and battle.
// Source: 7th Heaven mod manager 7thHeaven.var "FieldID" variable (confirmed
//         by 7H source reading this as a signed 16-bit value via Marshal.ReadInt16)
constexpr uint32_t FIELD_ID = 0xCC15D0;

// Title screen cursor position. Valid only while the title screen is displayed.
//   0 = NEW GAME cursor position
//   1 = CONTINUE cursor position
// Confirmed by ff7_title_poll.py / ff7_title_verify.py (2026-06-30):
//   single address in 0xDD segment, changed exactly once per Up/Down press,
//   verified as clean 0↔1 toggle in sync with cursor movement.
// Located 0x2B2C bytes after the name-entry cursor column (0xDD46F8).
// During field/menu/battle modes this address holds unrelated BSS data —
// the polling thread guards against this by only speaking for values 0 or 1.
constexpr uint32_t TITLE_CURSOR = 0x00DD6F24;

// Main-menu cursor position. Valid while the in-game overlay menu is open.
// Holds the 0-indexed row currently highlighted in the main menu list:
//   0=Item  1=Magic  2=Equip  3=Status  4=Order  5=Limit
//   6=???   (unlockable, identity TBD)
//   7=Config
//   8=???   (unlockable, identity TBD)
//   9=Save  10=Quit
//
// Confirmed by ff7_menu_cursor_isolate.py / ff7_menu_cursor_verify.py (2026-07-01):
//   The isolate script took two snapshot passes both inside the already-open menu
//   (so field scripts were frozen for both phases) — Phase A with cursor stationary,
//   Phase B with cursor moving — then subtracted to find addresses that ONLY changed
//   during cursor movement.  This eliminated all field-script variables and animation
//   counters.  0x00DC1154 emerged as the sole high-confidence candidate (count=37,
//   last=9=Save across two independent game launches with different PIDs).
//
// Earlier false candidate 0x00CC1B42 was a field-script variable: it changed during
// field gameplay (triggering false TTS) and froze when the menu opened (so cursor
// movement wasn't tracked).  0x00DC1154 does the opposite — stays constant during
// field gameplay and changes exactly once per Up/Down press inside the menu.
//
// When the menu is closed the byte retains its last cursor position.  Gate all
// TTS on MENU_OPEN (below) — do not use FIELD_ID for this purpose.
constexpr uint32_t MENU_CURSOR = 0x00DC1154;

// Overlay-active flag.  Set to 1 whenever a full-screen overlay is displayed
// over the field, 0 during normal field gameplay, title screen, and world map.
//
// IMPORTANT — this flag covers MORE than just the main menu:
//   - In-game main menu (Item / Magic / Equip … / Quit)  ← what we want
//   - Post-battle results screen (EXP, AP, gil, treasure) ← also sets this
//   The FIELD_ID gate in MenuCursorThread (field_id == 0 → skip) is what
//   prevents false announces from the title screen; the post-battle screen
//   occurs during the battle module where FIELD_ID is 0, so it is filtered
//   by the same gate.  No separate handling is needed for the post-battle
//   screen as long as the FIELD_ID gate remains in place.
//
// Confirmed by ff7_menu_open_scan.py (2026-07-01): symmetric A→B→A scan with
// three snapshots (field closed → menu open → field closed) found 7 clean
// 0→1→0 candidates.  0x00DC12DC is 0x188 bytes after MENU_CURSOR in the same
// DC-region menu-state block, making it the most structurally coherent choice.
// Other clean candidates (all verified 0→1→0): 0x00DC12F0, 0x00DC1328,
// 0x00CFFB7C, 0x00CFFB8C, 0x00DC3D00, 0x00DC3D04.
//
// Used by MenuCursorThread to:
//   (a) suppress the false "Item" announce that occurs at new-game load when
//       MENU_CURSOR reads 0 from a BSS-zeroed address before any menu opens;
//   (b) re-announce the current cursor position whenever the menu (re)opens,
//       even if the cursor hasn't moved since the menu was last closed.
constexpr uint32_t MENU_OPEN = 0x00DC12DC;

// Config sub-menu row cursor. Holds the 0-indexed row currently highlighted
// inside the Config sub-menu (accessible from main menu row 7):
//   0=Window color  1=Sound      2=Controller   3=Cursor
//   4=ATB           5=Battle speed  6=Battle message  7=Field message
//   8=Camera angle  9=Magic order
//
// Confirmed by ff7_config_menu_scan.py (Phase A/B isolate scan, 2026-07-02):
//   Both snapshot phases ran inside the already-open Config sub-menu (field
//   script frozen for both).  Phase A idle-baseline (12s, cursor stationary)
//   captured background noise; Phase B navigation (35s, Up/Down through all
//   10 rows) captured row-change events.  0x00DC10F0 was the sole nav-only
//   candidate in range 0–9 (count=33, last=8=Camera angle).
//
// Verified by ff7_config_menu_verify.py (2026-07-02): clean sequential count
//   0→1→2→...→9→0→1→... in exact sync with Down presses, reverses cleanly
//   with Up presses.  No false positives observed during field gameplay.
//
// NOTE — CONFIG_OPEN proxy: no dedicated "config sub-menu is open" flag was
//   found.  All symmetric-toggle candidates from the Phase C scan fired when
//   the MAIN MENU opened (identical to MENU_OPEN 0x00DC12DC).  ConfigMenuThread
//   therefore gates on MENU_CURSOR == 7 (the Config row) as a proxy: while in
//   the config sub-menu MENU_CURSOR is frozen at 7 and CONFIG_ROW changes;
//   while on the Config row in the main menu (not yet in sub-menu) MENU_CURSOR
//   is also 7 but CONFIG_ROW does not change.
constexpr uint32_t CONFIG_ROW = 0x00DC10F0;

// Config sub-menu setting value addresses.
// Confirmed 2026-07-02 via ff7_config_values_scan.py (isolate scan, subtracted
// idle noise from nav-phase changes to find row-exclusive addresses) and
// ff7_config_values_verify.py (live per-address monitoring while navigating
// each row with Left/Right).  All five live in the DC0E config struct.
//
// SLIDER ENCODING (DC0E10, DC0E11, DC0E24):
//   Raw byte 0–255 where 0=fastest and 255=slowest.  The game displays this
//   as a graphical bar; there is no separate "display value" address.
//
// PACKED BYTE ENCODING (DC0E12, DC0E13):
//   Two settings share one byte.  Extract each field with bitwise ops (below).
//   The remaining bits are constant during normal config navigation; they appear
//   to be set by other config rows not yet decoded (Window color, Sound,
//   Controller).  Mask only the bits documented here; do not treat the byte
//   as a single index.

// Row 5 — Battle speed slider.  Raw byte 0–255: 0=Fast, 255=Slow.
// Exclusive to row 5: confirmed unchanged on all other rows during verify.
constexpr uint32_t CONFIG_SPEED_BATTLE = 0x00DC0E10;

// Row 6 — Battle message speed slider.  Raw byte 0–255: 0=Fast, 255=Slow.
// Exclusive to row 6.
constexpr uint32_t CONFIG_SPEED_MSG = 0x00DC0E11;

// Rows 3+4 — packed byte encoding Cursor (bit 4) and ATB (bits 7:6).
//
//   Cursor  = (val >> 4) & 1
//     0 = Initial   1 = Memory
//
//   ATB     = (val >> 6) & 3
//     0 = Active    1 = Recommended    2 = Wait
//
// Verified: on row 3 (Cursor), bit 4 toggled between 0 and 1 while bits 7:6
// were stable.  On row 4 (ATB), bits 7:6 stepped 00→01→10 while bit 4 was
// stable.  Bits 3:0 held a constant 0x5 throughout (other packed fields).
constexpr uint32_t CONFIG_PACKED_CURSOR_ATB = 0x00DC0E12;

// Rows 8+9 — packed byte encoding Camera angle (bit 0) and Magic order (bits 4:2).
//
//   Camera angle = val & 1
//     0 = Auto    1 = Fixed
//
//   Magic order  = (val >> 2) & 7
//     0 = No.1   1 = No.2   2 = No.3   3 = No.4   4 = No.5   5 = No.6
//
// There are 6 magic order presets (not 4 as the config menu's visual layout
// implies).  The menu shows the selected preset's internal ordering
// (restore/attack/indirect), not the preset list itself.  Observed values
// 0,4,8,12,16,20 during verify confirm all 6 are reachable (step = 4 = 2²,
// so the index occupies bits 4:2, giving the clean (val>>2)&7 extraction).
//
// Verified: on row 8 (Camera), bit 0 toggled 12↔13 while bits 4:2 were
// stable.  On row 9 (Magic), bits 4:2 stepped through all 6 values while
// bit 0 was stable.  Bits 7:5 and bit 1 held 0 throughout.
constexpr uint32_t CONFIG_PACKED_CAMERA_MAGIC = 0x00DC0E13;

// Row 7 — Field message speed slider.  Raw byte 0–255: 0=Fast, 255=Slow.
// Located at DC0E24 (not DC0E15/DC0E16): the DC0E10–DC0E13 block encodes
// the toggle rows (3,4,8,9) and the two battle-related sliders (5,6), while
// the field-message slider is stored 0x14 bytes further in the struct.
// Exclusive to row 7 during verify; neighbors DC0E0F, DC0E14, DC0E15 were
// unchanged across all rows.
constexpr uint32_t CONFIG_SPEED_FIELD_MSG = 0x00DC0E24;

// Sound sub-menu cursor.  Tracks which volume slider is highlighted inside
// the Sound sub-menu (Config row 1 → Confirm to enter):
//   0 = Music volume slider highlighted
//   1 = FX volume slider highlighted
//
// Confirmed by ff7_sound_cursor_scan.py (2026-07-03): two-pass delta scan
// run twice (Down Music→FX expects +1, Up FX→Music expects -1 — 4 total
// transitions).  Sole confident candidate: appeared in the intersection of
// all 4 transitions.  DC-block address, 0x5C bytes below CONFIG_ROW
// (0x00DC10F0) in the same DC10xx menu-state structure.
//
// Value when Sound sub-menu is NOT open is not confirmed; the cursor byte
// likely retains its last position (Music=0 or FX=1) after closing.
// ConfigMenuThread resets last_sound_cursor on Sound-row exit so the first
// observation after re-entry is always silent, preventing spurious announces.
constexpr uint32_t SOUND_CURSOR = 0x00DC108C;

// ---------------------------------------------------------------------------
// Quit-confirmation dialog (sub-menu of the main menu)
// ---------------------------------------------------------------------------

// Yes/No cursor position inside the Quit confirmation dialog.
//   0 = Yes   1 = No  (No is the default when the dialog opens)
// Confirmed by ff7_quit_dialog_scan.py (2026-07-02): sole candidate from the
// 4-snapshot scan (main menu on Quit → dialog/No → dialog/Yes → dialog/No).
// Address is 0x20 bytes before MENU_OBJECTS (0x00DC0FC0), in the same DC0F
// menu-state structure as QUIT_OPEN below.
constexpr uint32_t QUIT_CURSOR = 0x00DC0FA0;

// Candidate flag for "Quit confirmation dialog is visible."
// Confirmed 0→1 when dialog opens (ff7_quit_dialog_scan.py, 2026-07-02),
// but NOT confirmed to return to 0 when dialog is dismissed with No.
// In practice it appears to stay at 1 after cancellation, which caused
// MenuCursorThread to loop in the quit handler indefinitely, silencing
// the main-menu cursor.  NOT currently used in MenuCursorThread for this
// reason.  Left here for reference in case a future investigation finds a
// reliable open/close flag for this dialog.
// Other clean 0→1 candidate from same scan: 0x00DC0FB8.
constexpr uint32_t QUIT_OPEN = 0x00DC0FB1;  // NOT USED — see note above

// ---------------------------------------------------------------------------
// SECTION 1b: Savemap region layout (confirmed from 7th Heaven source)
//
// SAVEMAP_BASE (0xDBFD38) is the start of a region that includes both the
// traditional savemap and immediately following game-state data. The offsets
// below are confirmed from 7th Heaven's 7thHeaven.var address table, which
// reads these as absolute addresses with no module-base addition (FF7 does
// not use ASLR).
//
// Character blocks: each of the 9 playable characters occupies 0x84 bytes,
// starting at SAVEMAP_BASE + 0x70. Within each block the weapon byte is at
// offset 0x0, armor at 0x1, accessory at 0x2. HP/MP/stats follow the
// standard FF7 savemap character struct layout.
//
// Absolute addresses of each character block (= SAVEMAP_BASE + 0x70 + N*0x84):
//   Cloud     0xDBFDA8   Barret    0xDBFE2C   Tifa      0xDBFEB0
//   Aeris     0xDBFF34   Red XIII  0xDBFFB8   Yuffie    0xDC003C
//   Cait Sith 0xDC00C0   Vincent   0xDC0144   Cid       0xDC01C8
//
// Other confirmed savemap-region addresses (7thHeaven.var):
//   0xDC08DC  PPV (Party Progress Variable) — signed WORD, story progress
//   0xDC08EB  Time played — BYTE
//   0xDC091C  KeyItems1  — DWORD bitfield (32 key item flags)
//   0xDC0920  KeyItems2  — DWORD bitfield (additional key item flags)
//   0xDC09E5  PartyLeader — BYTE, character ID of the current party leader
//   0xDC0BCF  Subtitles  — BYTE, subtitles on/off setting
//   0xDC0BD5  UTS        — BYTE, unlock/tutorial/subtitles options byte
//   0xDC0BD6  Unlocks    — BYTE
//   0xDC0BD7  Music      — BYTE, music on/off setting
// ---------------------------------------------------------------------------

// Character ID of the current party leader (Cloud=0, Barret=1, Tifa=2, …).
// Useful for constructing "Cloud says:" style TTS speaker prefixes.
// Source: 7th Heaven 7thHeaven.var "PartyLeader"
constexpr uint32_t PARTY_LEADER = 0xDC09E5;

// Story progress variable — a signed 16-bit counter advanced by field scripts.
// 7th Heaven uses it to apply different mod configs based on story position.
// Source: 7th Heaven 7thHeaven.var "PPV"
constexpr uint32_t STORY_PROGRESS = 0xDC08DC;

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

// ---------------------------------------------------------------------------
// SECTION 1c: Battle system addresses
//
// All confirmed by ff7_battle_action_scan.py Phase 1 (address derivation)
// and Phase 2 (live monitor across 5 battles, 2026-07-05).  No ASLR; all
// addresses are fixed for every run of the 2013 Steam exe.
//
// g_active_actor_id:
//   A single byte holding the slot index of the actor whose turn is being
//   processed.  Updated by display_battle_action_text_42782A (confirmed:
//   derived from FUNC_ADDR+0x52 via a MOV ESI,[abs32] instruction).
//   Party slots 0–2, enemy slots 4–9; slot 3 is never used.
//   Initialises to 0 at process start and is NEVER reset between battles —
//   it retains the last-acting slot indefinitely.  Use commandID==0 to
//   distinguish "game just started / not in battle" from a real action.
//
// g_battle_model_state:
//   Large per-actor state array.
//   Element address: G_BATTLE_MODEL_STATE + actor_id * BATTLE_MODEL_STATE_STRIDE
//   commandID (uint8_t) at element + BATTLE_COMMAND_ID_OFFSET:
//     0x00 = idle (field map, between battles)
//     0x01 = party Attack command
//     0x14 = party Limit Break command
//     0x20 = enemy AI attack opcode
//   Other values exist for Magic, Item, etc.
//
// g_small_battle_model_state:
//   Small per-actor state array with actionIdx.
//   Element address: G_SMALL_BATTLE_MODEL_STATE + actor_id * BATTLE_SMALL_MODEL_STRIDE
//   actionIdx (uint16_t) at element + BATTLE_ACTION_IDX_OFFSET: 0-based index
//   into kernel2 section 8 (action/ability names).
//
// sub_6D71FA — kernel2 text REQUEST function (NOT a get-and-return):
//   Confirmed by ff7_kernel2_scan.py (2026-07-05) hex dump of original file bytes.
//   Disassembly of the 34-byte function body:
//     PUSH EBP / MOV EBP,ESP
//     MOV DWORD PTR [0x00DC38E8], 1    ; set request_pending flag
//     MOVSX EAX, WORD PTR [EBP+8]      ; read section arg (sign-extend word)
//     MOV [0x00DC38EC], EAX            ; store section
//     MOVSX ECX, WORD PTR [EBP+0xC]   ; read idx arg
//     MOV [0x00DC38F0], ECX            ; store idx
//     POP EBP / RET
//   The function does NOT return a char* — it queues a kernel2 lookup request
//   in the global struct at 0x00DC38E8.  A separate game-engine pass reads the
//   flag, performs the kernel2 lookup, and stores the result elsewhere.
//   DO NOT call this function for direct text retrieval — it returns nothing.
//
//   The earlier "CALL to 0x016E4E3C" finding was a scanner false-positive:
//   the 0xE8 byte at code offset +5 is the low byte of the address 0x00DC38E8
//   embedded inside MOV [0x00DC38E8],1 — not a CALL opcode.
//
// KERNEL2_REQUEST_STRUCT at 0x00DC38E8 (sub_6D71FA writes here):
//   +0x00  DWORD  request_pending  (1 = lookup queued, 0 = idle)
//   +0x04  DWORD  section          (8 = battle action / ability names)
//   +0x08  DWORD  idx              (0-based index into section 8)
//
// TODO: find the actual kernel2 section pointer array to implement direct
// lookup.  Lead: 0x009ADF0C and sub_6892E5 (0x006892E5) referenced by
// display_battle_action_text — see ff7_kernel2_scan.py investigation.
// ---------------------------------------------------------------------------

constexpr uint32_t G_ACTIVE_ACTOR_ID          = 0x00BE1170;
constexpr uint32_t G_BATTLE_MODEL_STATE        = 0x00BE1178;
constexpr uint32_t G_SMALL_BATTLE_MODEL_STATE  = 0x00BF23B8;
// GET_KERNEL_TEXT removed — 0x016E4E3C was a scanner false-positive; calling
// 0x6D71FA (sub_6D71FA) is wrong because it stores params but returns void.
// See KERNEL2_REQUEST_STRUCT below for the request-queue mechanism.
constexpr uint32_t KERNEL2_REQUEST_BASE        = 0x00DC38E8; // struct: pending/section/idx
constexpr uint32_t KERNEL2_CANDIDATE_PTR       = 0x009ADF0C; // ptr to kernel2 data (TBD)

// Struct layout constants for the battle model state arrays.
constexpr uint32_t BATTLE_MODEL_STATE_STRIDE  = 0x1AEC; // bytes per actor, large array
constexpr uint32_t BATTLE_SMALL_MODEL_STRIDE  = 0x74;   // bytes per actor, small array
constexpr uint32_t BATTLE_COMMAND_ID_OFFSET   = 0x23;   // commandID (uint8_t) in large elem
constexpr uint32_t BATTLE_ACTION_IDX_OFFSET   = 0x3E;   // actionIdx (uint16_t) in small elem

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
 * progresses. Reading it mid-dialog yields partial text starting at the current
 * typewriter position. Use the one-frame pending_speak delay (hooks.cpp) to
 * read it after s_old_message() has written the fully-initialized value.
 * DO NOT use get_field_dialog_text(dialog_id) — it reads from the wrong entity
 * section and returns garbled text for any non-section-0 dialog.
 *
 * Equivalent to accessing ff7_externals.current_dialog_string_pointer[window_id].
 */
inline const char* get_dialog_text_ptr(uint8_t window_id)
{
    return *reinterpret_cast<const char* const*>(DIALOG_TEXT_PTRS + window_id * sizeof(uint32_t));
}

/*
 * get_field_dialog_text: Return a pointer to the complete static FF7-encoded
 * text for dialog_id from the current field. Returns nullptr if the field
 * buffer is not loaded or dialog_id is out of range for this field.
 *
 * WHY THE SCRIPT SECTION (PRIMARY):
 *   FF7 PC Steam stores dialog text embedded in section 0 (the field script
 *   section), not in a separate section. This was the root cause of all
 *   garbage TTS output: the old implementation explicitly SKIPPED the script
 *   section, so get_field_dialog_text always returned nullptr, forcing a
 *   fallback to the volatile typewriter pointer (DIALOG_TEXT_PTRS). That
 *   pointer is a live cursor that advances as text is displayed, holds stale
 *   values between dialogs, and can be written by unrelated game operations.
 *
 * HOW wStringOffset WORKS:
 *   The ff7_field_script_header (documented in FFNx src/ff7.h) sits at the
 *   start of script_data (section 0, past its 4-byte size DWORD):
 *     offset 0: WORD unknown1 (not the string offset — unrelated field)
 *     offset 2: char nEntities
 *     offset 3: char nModels
 *     offset 4: WORD wStringOffset  <- byte offset from script_data to the
 *                                       dialog string offset table
 *   At script_data + wStringOffset the format is identical to non-script
 *   text sections (kernel2_get_text format):
 *     uint16_t offsets[num_dialogs] — offsets[0] == num_dialogs * 2
 *     offsets[i] == byte offset from (script_data + wStringOffset) to
 *                   dialog[i]'s text (0xFF-terminated FF7-encoded string)
 *   Source: FFNx src/ff7.h ff7_field_script_header; kernel2_get_text.
 *
 * FALLBACK:
 *   A section-search fallback remains for any field that may use a different
 *   layout (e.g., when a dialog's id exceeds the primary section's table
 *   count, the dialog may live in a different field file section). The script
 *   section is excluded from this search because its leading uint16 could
 *   coincidentally match the offset-table format and return entity bytecodes.
 *
 * Implemented in ff7_addresses.cpp — too large for a header-only inline,
 * and the fallback path includes diagnostic logging via Log::Write.
 */
const char* get_field_dialog_text(uint8_t dialog_id);

} // namespace FF7Addr
