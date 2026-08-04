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

// Global menu objects container. Kept as a REGION ANCHOR only (the QUIT
// dialog bytes 0xDC0FA0/0xDC0FB1 sit just before it in the same DC0F
// menu-state block). The main-menu cursor itself turned out to live
// elsewhere: MENU_CURSOR 0xDC1154 and the rest of the DC10xx-DC13xx menu
// cluster — see §4/§14. (2026-07-23 audit: the original "offsets require
// further RE" note here predated those finds and was stale.)
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

// ASK (choice-menu) cursor -- the FULL story (finalized v2.30.12):
//
// The live selection is a STACK LOCAL in the ASK handler (0x618E83),
// passed by address into the cursor-move update loop (0x6310A1) each
// frame, and synced from/to the ASK opcode's own SCRIPT VARIABLE (the
// bank/address named in the opcode's first parameters) around the call
// -- 0x618E8B reads it in via helper 0x60F750, 0x618F25/0x618F6B write
// it back via 0x60FA7D. There is NO fixed global for it.
//
// ASKMENU_OPTION below (0xCC14D1) is therefore NOT a cursor global --
// it is the script variable of whatever dialog the 2026-07-20 live scan
// happened to run against (ff7_ask_cursor_scan.py, log ..._102217). Any
// dialog whose bank/address params name a different variable leaves it
// STALE AND FROZEN, which is exactly what the 2026-07-22 soldier
// fight-or-flee log showed (option read 0 with first_line=2, then never
// changed) while every Aeris-field choice (evidently sharing the
// scanned variable) tracked perfectly. Kept only as provenance -- DO
// NOT read it for cursor tracking.
constexpr uint32_t ASKMENU_OPTION = 0x00CC14D1;  // per-DIALOG script var, NOT a global

// The reliable, dialog-independent cursor readout instead: the update
// loop MIRRORS the clamped cursor into the ASK per-window struct every
// frame the choice is accepting input (disasm ff7_ask_lines_static.py
// log ..._171327, 0x631384-0x63139C, unconditional in that branch --
// not just on key presses):
//
//   mov  word ptr [0xCFF5DE + window_id*0x30], line*16 + 6
//
// i.e. the highlight's pixel Y offset inside the window: 16 px per text
// line, 6 px top margin. Same struct family as the other per-window ASK
// fields the disasms surfaced (byte 0xCFF5D2+n*0x30 input-armed flag,
// u16 0xCFF5DC+n*0x30 = 5 while choosing, u16 0xCFF5E4+n*0x30 = 7 on
// confirm, u16 0xCFF5E6+n*0x30 state-flag word whose bit 0 gates the
// input branch). Written from the already-clamped line value, so it
// holds first_line*16+6 from the window's first accepting frame onward.
constexpr uint32_t ASK_CURSOR_PIXEL_Y = 0x00CFF5DE;  // u16, +window_id*0x30
constexpr uint32_t ASK_WINDOW_STRIDE  = 0x30;

// get_ask_cursor_line: current 0-based highlighted LINE of an open ASK
// window, or -1 if the pixel word does not currently hold a valid
// resting highlight position (y < 6, or not on a 16-px line boundary --
// callers just skip the announce that frame and re-read the next).
inline int get_ask_cursor_line(uint8_t window_id)
{
    const uint16_t y = *reinterpret_cast<const volatile uint16_t*>(
        ASK_CURSOR_PIXEL_Y + window_id * ASK_WINDOW_STRIDE);
    if (y < 6 || ((y - 6) & 0xF) != 0) return -1;
    return (y - 6) >> 4;
}

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
// Located 0x282C bytes after NAME_ENTRY_CHAR_INDEX (0xDD46F8) in the same
// DD-segment menu-module block. (Earlier versions of this comment said
// 0x2B2C — bad arithmetic carried since v1.9; 0xDD6F24 - 0xDD46F8 = 0x282C.
// 0xDD46F8 itself was also mislabeled "name-entry cursor column" per an Echo
// mod hext patch; live scanning on 2026-07-12 disproved that label — see the
// name-entry section below.)
// During field/menu/battle modes this address holds unrelated BSS data —
// the polling thread guards against this by only speaking for values 0 or 1.
// PROVENANCE UPGRADE (v2.30.38, static disasm 2026-07-27, ff7_title_phase_
// static.py + ff7_title_callers_disasm.py): 0xDD6F24 is the ROW field (+4)
// of a cursor WIDGET at 0xDD6F20, constructed by the same widget ctor
// 0x6F4D30 the shop work mapped (+0 col / +4 row / +0x14 scroll) — built
// with 2 rows x 1 column in the title module's init 0x720E64, updated by
// widget-nav 0x6F4DB2, read by the title draw (cursor Y = base + row*
// stride) and the OK handler (switch: 0=New Game, 1=Continue). This is
// why no direct writer instruction exists for the byte.
constexpr uint32_t TITLE_CURSOR = 0x00DD6F24;

// Title module lifecycle state (dword) — the "is the title menu actually
// on screen" signal the launch-splash bug needed (v2.30.38, 2026-07-27).
// STATIC provenance (disasm windows in title_callers_disasm_20260727 +
// title_state_writers_20260727 logs):
//   The title module's per-frame main is 0x722393. First tick of every
//   title session (guard [0xDD76F8]==0) it resets THIS dword to 0 and
//   runs init 0x720E64 (builds the title cursor widget above); the
//   per-frame draw 0x7212FB then advances it:
//     0  = fading in — logo/splash/pre-title (BSS boot value) or the
//          title backdrop still brightening (fade helper 0x722BB0(-0xF)
//          stepped each frame until done);
//     1  = TITLE MENU INTERACTIVE — fade-in complete (write 0x721325).
//          Holds 1 through the NEW GAME/Continue prompt AND the Continue
//          save-grid (the grid is a title-module subscreen, [0xDD7704]
//          switches); this is the announce-gate value.
//     2  = choice accepted, fading out (writes 0x7221FF/0x72229A);
//     -1 = fade-out done, module exiting (0x72134B) — teardown clears
//          the [0xDD76F8] init guard (0x722441), so EVERY re-entry
//          (cold boot, post-game-over, quit-to-title) re-runs init and
//          re-cycles 0 -> 1. Stays -1 (stale) during gameplay: a ==1
//          gate cannot false-fire outside the title.
//   Values are only ever written by the title module; the boot logo
//   movies play BEFORE the module starts, so the dword is still 0 there
//   — exactly the window where the old FIELD_ID==0-only gate spoke a
//   premature "New Game" over the splash.
constexpr uint32_t TITLE_STATE             = 0x00DD74E0;
constexpr int32_t  TITLE_STATE_INTERACTIVE = 1;

// ---------------------------------------------------------------------------
// Name-entry screen ("Please enter a name") addresses.
//
// All confirmed live 2026-07-12 by investigate/ff7_name_entry_scan.py
// (frozen-context isolate scan: idle baseline, Up/Down-only, Left/Right-only,
// type-only, delete-only phases, subtracted) and ff7_name_entry_verify.py
// (live decode: spoken letters matched the player's actual cursor across a
// full row walk and multiple row changes; buffer readback matched every
// add/delete; the Cloud→Barret screen handoff was captured live, which is
// what exposed the true buffer base and the char-index/active-flag pair).
//
// THE CHARACTER GRID (7 rows x 10 columns, from the in-game layout):
//   row 0: A B C D E F G H I J
//   row 1: K L M N O P Q R S T
//   row 2: U V W X Y Z , . + -
//   row 3: a b c d e f g h i j
//   row 4: k l m n o p q r s t
//   row 5: u v w x y z : ; ' "   <- columns 8-9 not yet visually confirmed
//   row 6: 0 1 2 3 4 5 6 7 8 9
//
// CURSOR EDGE BEHAVIOR (player-observed + live-confirmed 2026-07-12):
// horizontal movement NEVER wraps — pressing Right on the last column JUMPS
// to the side panel (Space/Delete/Select/Default). The only wrapping in the
// whole screen is VERTICAL movement on the panel (index 0 <-> 3, observed
// live and player-confirmed as normal game behavior). Leaving the panel
// with Left restores the previously-occupied grid COLUMN (the game
// remembers it), and entering the panel can CHANGE the ROW value (observed
// row 1 -> 4 at panel entry) — one more reason the TTS thread only ever
// announces where the cursor actually landed, gated by the pane flag below.
//
// SIDE PANEL — RESOLVED 2026-07-12 (was the v2.8 "known gap"):
//   ff7_name_entry_panel_probe.py labeled the buttons by their effect on the
//   name buffer (Space added byte 0x00, Delete removed a char — indices 0
//   and 1 proven; 2=Select and 3=Default inferred from on-screen order and
//   player-confirmed by ear during ff7_name_entry_pane_verify.py).
//   ff7_name_entry_pane_flag_scan.py (A/B/A revert scan over the full
//   static range) found the pane flag at 0x921ED4 — the sole clean boolean
//   candidate — and the live verify tracked six grid<->panel crossings and
//   a dozen panel moves flawlessly. The panel index WRAPS vertically
//   (0 <-> 3 transitions observed).
//
// NAME LENGTH: hard cap of 9 characters. At the cap, Confirm REPLACES the
// 9th character instead of appending (observed live: 'CloudFPZf' ->
// 'CloudFPZp' -> 'CloudFPZz' on successive grid confirms).
// ---------------------------------------------------------------------------

// Grid cursor column (0-9) and row (0-6): adjacent 4-byte-spaced X/Y pair.
//
// READ THESE AS u8 (the low byte only). The 4-byte spacing suggests DWORD
// slots, but every piece of confirming evidence is byte-level: the scan's
// diff only ever saw the LOW byte of each slot change, and the verify
// scripts read single bytes. The three high bytes of each slot are
// UNVERIFIED — if they held constant nonzero data, a u32 read would fail
// the grid bound check (row<7 && col<10) on every poll and silently
// disable the feature. A u8 read matches exactly what was verified.
constexpr uint32_t NAME_ENTRY_COL = 0x00DD4538;
constexpr uint32_t NAME_ENTRY_ROW = 0x00DD453C;

// The name being edited, FF7-encoded (char = byte + 0x20 for the printable
// range), 0xFF-terminated. At least 9 characters of capacity observed live
// ("CloudGHRC"); we read up to 12 (the savemap name field size) and treat
// 0xFF or end-of-window as the terminator.
//
// DISCOVERY NOTE: the first scan reported 0xDD45F5 as the buffer — that was
// only the first byte that CHANGED during the type/delete phases, because
// the default name "Cloud" occupied F0-F4 and never changed. The verify
// run's Cloud→Barret screen handoff rewrote the full string and exposed the
// true base at 0xDD45F0.
constexpr uint32_t NAME_ENTRY_BUFFER     = 0x00DD45F0;
constexpr uint32_t NAME_ENTRY_BUFFER_CAP = 12;

// Which character this naming screen is for: 0=Cloud, 1=Barret (observed;
// presumably follows the standard character IDs for later screens).
// Flipped 0->1 exactly at the Cloud→Barret handoff.
// THIS is the address the Echo mod hext patch mislabeled "cursor column" —
// it never changes during grid navigation.
constexpr uint32_t NAME_ENTRY_CHAR_INDEX = 0x00DD46F8;

// 1 while a naming screen is open, 0 otherwise. All three observed
// transitions matched (Cloud close, Barret open, final exit). Gate together
// with GAME_MODE == GAME_MODE_NAME_ENTRY — either alone could be BSS reuse.
constexpr uint32_t NAME_ENTRY_ACTIVE     = 0x00DD46FC;

// Pane flag: 0 = cursor in the letter grid, 1 = cursor on the side panel.
// Lives OUTSIDE the DD name-entry block (0x92xxxx menu-module data) — found
// by full-static-range A/B/A revert scan (ff7_name_entry_pane_flag_scan.py,
// 2026-07-12), then live-verified across six grid<->panel crossings
// (ff7_name_entry_pane_verify.py). Only valid while the naming-screen gate
// holds; treat as unrelated BSS otherwise.
constexpr uint32_t NAME_ENTRY_PANE_FLAG  = 0x00921ED4;

// Side-panel button index, valid ONLY while NAME_ENTRY_PANE_FLAG == 1:
//   0 = Space   (proven: Confirm added byte 0x00 to the name)
//   1 = Delete  (proven: Confirm removed a character)
//   2 = Select  (on-screen order + player ear-confirmed; closes the screen)
//   3 = Default (on-screen order + player ear-confirmed; restores the name)
// Wraps vertically (0 <-> 3). RETAINS its last value after returning to the
// grid and idles at 0 before first panel entry — it says WHICH button, never
// WHETHER the cursor is on the panel; that is the pane flag's job.
constexpr uint32_t NAME_ENTRY_PANEL_INDEX = 0x00DD4574;
constexpr uint32_t NAME_ENTRY_PANEL_MAX   = 3;

// Caret position within the name, clamped to 0..8 (the 9-char cap minus 1).
// Tracked 5->6->7->8 live as letters were appended to 'Cloud' and pinned at
// 8 once the name was full. Not currently used by the mod (the buffer's
// 0xFF terminator gives the length directly) — documented for completeness.
constexpr uint32_t NAME_ENTRY_CARET      = 0x00DD46F0;

// GAME_MODE (0xCC0D89) value on the naming screen. New live-observed value
// (2026-07-12), joining 0=field, 2=battle, 9=menu.
constexpr uint8_t GAME_MODE_NAME_ENTRY = 6;

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
//   - The NAMING SCREEN (confirmed 2026-07-12: it set MENU_OPEN=1 with
//     FIELD_ID non-zero, making MenuCursorThread falsely announce "Item"
//     over the name-entry TTS; fixed by a GAME_MODE==6 stand-down gate)
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
// SAVE / LOAD menu state (v2.29, ff7_save_menu_scan.py 2026-07-17)
//
// The menu behind main-menu SAVE (in-field) and title-screen Continue: a
// 10-entry file grid ("Save 1".."Save 10"), then a 15-slot list inside the
// chosen file. Found by press-and-revert delta rounds (two rounds
// intersected per cursor — the wrap-immune variant of the SOUND_CURSOR
// method), log save_menu_scan_20260717_114908:
//
//   - GRID cursor: the SINGLE intersected candidate, and LIVE-VERIFIED in
//     the same session — the scan's speak-back pass tracked 0→1→2→3→4→3…
//     exactly as the player moved. 0-based, 0..9, +1 per Right press
//     (5-wide × 2 rows, row-major).
//   - SLOT cursor: the single intersected candidate of the Down/Up rounds.
//     0x3C after the grid cursor — same DC6Axx menu struct. 0-based, 0..14.
//     While the slot list is open the grid cursor HOLDS the selected file
//     index (it appeared in neither slot-round diff), so "which file are
//     these slots from" is read from SAVEMENU_GRID_CURSOR at any time.
//   - PHASE: 0 = file grid, 1 = slot list. Chosen from the 6 A/B/A toggle
//     candidates as the only single-byte 0/1 flag in the DC12xx menu-state
//     block (0xCC bytes before MENU_OPEN). Runner-up candidates from the
//     same scan if this one misbehaves in play: 0xDCA028 (also 0/1) and
//     0xDD7700 (u32, 0 in grid / heap POINTER while the slot list is open —
//     semantically "selected file's loaded data", nonzero-as-flag usable).
//
// GATING (SaveMenuThread): during the whole save-menu session MENU_OPEN
// stayed 1 with MENU_CURSOR frozen at 9 (the Save row) — the same
// frozen-row signature the Config sub-menu shows (see CONFIG_ROW note), so
// save mode gates on FIELD_ID!=0 && MENU_OPEN==1 && MENU_CURSOR==9.
// ⚠ The title-screen CONTINUE menu was ASSUMED to reuse this module —
// LIVE-DISPROVED 2026-07-17 (ff7_continue_menu_verify.py, log
// continue_menu_verify_20260717_120914): all three bytes sat FROZEN
// (grid=0 slot=0 phase=16 = title-module data) through 90 s of Continue-
// grid navigation. The Continue menu keeps its own state; scan pending
// (ff7_continue_menu_scan.py). These addresses serve the IN-FIELD save
// menu only. The slot PREVIEW data is deliberately NOT read from memory:
// the mod parses save\saveNN.ff7 directly (layout derived from the
// player's own file, research doc §5).
// ⚠ TWO play-reported corrections (2026-07-17, same day as the scans):
//
// 1. SAVEMENU_PHASE 0xDC1210 is DISPROVED as a pane flag: in real use it
//    OSCILLATES (player heard the two pane announcements alternating
//    endlessly in the save menu). Its clean 0/1 across the scan's three
//    widely-spaced A/B/A snapshots was luck, not state. Kept only as a
//    warning label — never read it. The pane signal for BOTH menus is
//    LOADMENU_LIST_PTR below (nonzero = slot list open), which both
//    scans observed independently and the shipped Continue menu proved
//    in play.
//
// 2. The "slot cursor" bytes are the VISIBLE-ROW index 0..2, NOT the
//    absolute slot: the list shows 3 slots and scrolls. Both scans
//    pressed Down/Up once from the top — inside the window, where row ==
//    absolute slot, the two are indistinguishable. The SCROLL OFFSET was
//    found by ff7_slot_scroll_probe.py (log slot_scroll_probe_20260717_
//    123245): title instance at slot_cursor+0x10 = 0xDD6DE4, stepping
//    0..12 slot-by-slot down the list and back, while +0x74 runs a
//    scroll-animation tween (transient 0xFFFFFFxx) and +0x80 flags the
//    direction (2=down 1=up 0=idle) — read NEITHER of those. Absolute
//    slot = row + scroll (0..14). The save-menu instance's scroll is
//    INFERRED at the same +0x10 (0xDC6B2C) from the struct echo that
//    has held for every other member — pending play confirmation.
//
// 3. (v2.29.3/.4) The "grid cursor" bytes are the COLUMN 0..4, not a
//    0..9 index: the 5×2 grid keeps its row in a SEPARATE byte at
//    grid+4 — 0 = top row (Save 1-5), 1 = bottom row (Save 6-10).
//    Grid probe run 2026-07-17 (slot_scroll_probe_20260717_171930):
//    column counted 0..4 on BOTH rows while +4 flipped per Down/Up.
//    (The original speak-back "0..9 verified" only ever walked the top
//    row — the same window-blindness as the slot list. And v2.29.3
//    first shipped the row INVERTED by misreading the probe's baseline
//    of 1 as "top": the player was already parked on the BOTTOM row
//    when the probe started. Their play report — Save 6 spoken on the
//    top row — settled it, v2.29.4.) File index = rowbyte*5 + column.
//    Save-menu row byte inferred at the same +4 (0xDC6AE4).
constexpr uint32_t SAVEMENU_GRID_CURSOR = 0x00DC6AE0; // u8 0..4 COLUMN
constexpr uint32_t SAVEMENU_GRID_ROW    = 0x00DC6AE4; // u8 0=top 1=bottom, LIVE-CONFIRMED
                                                      // (field probe 20260717_200802)
constexpr uint32_t SAVEMENU_SLOT_CURSOR = 0x00DC6B1C; // u8 0..2 visible ROW
constexpr uint32_t SAVEMENU_SLOT_SCROLL = 0x00DC6B2C; // u8 0..12, LIVE-CONFIRMED
                                                      // (field probe 20260717_200802;
                                                      // bonus neighbors: 0xDC6B34
                                                      // reads 15 = slot count,
                                                      // 0xDC6B24 reads 3 = visible
                                                      // rows — list metadata, unused)
constexpr uint32_t SAVEMENU_PHASE       = 0x00DC1210; // ⚠ DISPROVED — do not read

// The save menu's widget STATE MACHINE and the "Are you sure you want to
// save?" Yes/No dialog (v2.29.5, ff7_save_confirm_scan.py 2026-07-17,
// log save_confirm_scan_20260717_201751):
//   WIDGET_STATE — observed values: 1 = slot list, 7 = confirm dialog
//   (the scan's SINGLE A/B/A candidate: 1→7 on open, back on Cancel).
//   This is the same byte that was runner-up in the original phase pass
//   (grid→slot list 0→1) — it is the menu's mode variable; only the
//   value 7 is acted on (other values' meanings unsampled).
//   CONFIRM_CURSOR — 0 = Yes, 1 = No; single intersected Down/Up
//   candidate, live speak-back verified; resets to Yes on open. The
//   slot-row byte 0xDC6B1C holds still while the dialog is up (same
//   log), so dialog handling cleanly short-circuits the slot logic.
constexpr uint32_t SAVEMENU_WIDGET_STATE   = 0x00DCA028; // u8, 7 = confirm open
constexpr uint32_t SAVEMENU_CONFIRM_CURSOR = 0x00DC6C6C; // u8 0=Yes 1=No
constexpr uint8_t  SAVEMENU_STATE_CONFIRM  = 7;

// The title-screen CONTINUE menu's OWN instance of the same state
// (ff7_continue_menu_scan.py, log continue_menu_scan_20260717_121456):
// grid cursor LIVE-VERIFIED by the scan's speak-back pass (0→4 and back
// tracking the player); slot cursor the SINGLE intersected Down/Up
// candidate — and exactly +0x3C from the grid cursor, the same struct
// spacing as the save-menu pair (0xDC6AE0→0xDC6B1C), which corroborates
// both. Addresses sit in the TITLE module block (TITLE_CURSOR 0xDD6F24
// neighborhood). No 0/1 phase byte was isolated here (79 toggle
// candidates, mostly churn); instead LOADMENU_LIST_PTR is the pane
// signal: u32, 0 while the file grid shows, a HEAP POINTER (the selected
// file's loaded data) while the slot list is open — it behaved exactly
// the same in BOTH menus' phase passes (save scan: 0→0x237E6008→0;
// continue scan: 0→0x237D20A8→0, with sidekick byte 0xDD7704 flipping
// 0→1, kept as the runner-up flag). Read as nonzero-check only — the
// pointer VALUE is a transient allocation, never dereference it.
constexpr uint32_t LOADMENU_GRID_CURSOR = 0x00DD6D98; // u8 0..4 COLUMN
constexpr uint32_t LOADMENU_GRID_ROW    = 0x00DD6D9C; // u8 0=top 1=bottom (play-corrected v2.29.4)
constexpr uint32_t LOADMENU_SLOT_CURSOR = 0x00DD6DD4; // u8 0..2 visible ROW
constexpr uint32_t LOADMENU_SLOT_SCROLL = 0x00DD6DE4; // u8 0..12, LIVE-CONFIRMED
constexpr uint32_t LOADMENU_LIST_PTR    = 0x00DD7700; // u32 != 0 = slot list open

// ---------------------------------------------------------------------------
// ITEM menu state (v2.31, 2026-07-18)
//
// Sub-screen identity: the main-menu dispatcher (FFNx menu_sub_6CB56A,
// name-embedded VA 0x6CB56A) calls menu_subs_call_table[16] (@0x91AB98,
// operand at dispatcher+0x2EC) indexed by u32 [0xDC12EC] in steady state
// ([0xDC12E8] during the fade-transition frames — both call sites in
// ff7_menu_dispatch_disasm.py, log menu_dispatch_disasm_20260718_113028).
// The ITEM screen is INDEX 1: LIVE-observed constant 1 through the whole
// item-menu scan session (item_menu_scan_20260718_114427) — overriding the
// static caption-evidence guess of index 3, whose 0xDCA7F8 "exclusive
// block" stayed 0 all session (that block belongs to some other screen).
// The same disasm also settled a v2.29 mystery: 0xDC1210 is XOR-toggled
// every dispatcher tick (frame parity), which is WHY it oscillated and got
// DISPROVED as a save-menu phase flag.
//
// Cursor/state block (all single intersected candidates of the guided scan
// item_menu_scan_20260718_114427; list cursor speak-back verified live):
//   ITEMMENU_MODE: the menu's own state machine, exactly like the save
//     menu's widget byte — 0 = top bar (Use/Arrange/Key Items), 1 = item
//     list (both A/B/A toggles landed on THIS one address: 0<->1 on
//     top-bar/list, 1<->2 on list/target). ENTRY STATE IS 1: the menu
//     opens in the item list, Cancel goes UP to the top bar (player-
//     corrected flow, 2026-07-18 — the scan script's docstring had it
//     backwards).
//   ITEMMENU_TOPBAR_CURSOR: 0 = Use, 1 = Arrange, 2 = Key Items.
//   ITEMMENU_LIST_CURSOR: item-list row; the speak-back pass tracked it
//     0..4 over a 3-item inventory, so the cursor DOES move onto empty
//     rows (speak "Empty"). ⚠ WINDOW-vs-ABSOLUTE UNRESOLVED: with 3 items
//     the list cannot scroll (the v2.29.2 save-menu lesson); re-verify +
//     find the expected nearby scroll word once inventory > visible rows.
//   ITEMMENU_TARGET_CURSOR: use-on-whom party cursor, 0..2 top-to-bottom
//     (party slot order — speak via PartySlotLabel).
// Values other than 0/1/2 in ITEMMENU_MODE (Arrange popup? Key Items
// pane?) are NOT yet mapped: the speaker stays silent and debug-logs them
// for harvesting (player had no key items and the Arrange popup was not
// scanned this session).
constexpr uint32_t MENU_DISPATCH_INDEX  = 0x00DC12EC; // u32; 1 = item screen
constexpr uint32_t MENU_DISPATCH_TRANS  = 0x00DC12E8; // u32; transition twin
constexpr uint32_t ITEMMENU_MODE          = 0x00DD19C8; // u8 0/1/2 (see above)
constexpr uint32_t ITEMMENU_TOPBAR_CURSOR = 0x00DD1A18; // u8 0=Use 1=Arrange 2=Key Items
constexpr uint32_t ITEMMENU_LIST_CURSOR   = 0x00DD1A54; // u8 row (window Q open)
constexpr uint32_t ITEMMENU_TARGET_CURSOR = 0x00DD1A8C; // u8 party slot 0..2
constexpr uint32_t ITEMMENU_SCREEN_INDEX  = 1;          // dispatch index of ITEM

// ---------------------------------------------------------------------------
// ORDER "screen" + main-menu focus state (v2.32, 2026-07-18)
//
// The Order screen is NOT a dispatched sub-screen: the dispatcher index
// stays 0 (= the main-menu screen) and the player hears no confirm chime —
// the main-menu screen just moves input focus into the party pane
// (player-observed, then proven by disasm of the main-menu sub
// menu_subs_call_table[0] = 0x6CA346; ff7_order_block_disasm.py, log
// order_block_disasm_20260718_154555). The full confirm handler decoded:
//
//   0x6CA4CD  bit test: u16[0xDC1130] >> MENU_CURSOR & 1 → row DISABLED,
//             activation skipped (the grayed Materia/PHS rows)
//   0x6CA50C  switch(MENU_CURSOR) jump table 0x6CB53E (rows 0..10)
//   0x6CA513  char-select rows: play chime (0x74580A(1)), FOCUS_MODE = 1
//   0x6CA526  ORDER row: FOCUS_MODE = 2, NO SOUND CALL — the missing chime
//             the player noticed is right there in the code
//   0x6CA598  mode-1 confirm: cursor 0xDC118C → chosen slot 0xDC1288
//             (empty slot = error buzz 0x74580A(3)); FOCUS_MODE = 0
//   0x6CA608  mode-2 (Order) confirm: latch 0xDC1320 0→1, first slot saved
//             to 0xDC110C; second confirm: latch→0, same slot = row byte
//             at char_record+0x20 XOR 1 (0xFF front ↔ 0xFE back — matches
//             the guided scan's single toggle candidate 0xDBFDAC = Cloud's
//             record+0x20; the community's +0x1F claim is one byte off),
//             different slot = PARTY_IDS bytes swapped (scan-confirmed).
//   0x919928  static u32 table: character id → record index (the game's
//             own 9=Young Cloud/10=Sephiroth aliasing — mod keeps its
//             equivalent hardcoded map in SavemapCharName)
//
// Cursor/latch were found first by the guided scan (order_menu_scan_
// 20260718_152825: single candidates, cursor speak-back verified); the
// BSS entry-flag probe found NOTHING because it excluded these known
// addresses and the focus byte's A/B/A failed one round (see log
// order_entry_probe_20260718_153813) — the disasm settled it instead.
// FOCUS_MODE semantics are static-derived; live confirm rides the v2.32
// play-test (debug log on transitions).
// v2.30.78: the main menu gates row activation on TWO masks, not one
// (disasm 0x6CA4AB..0x6CA4E7 — the confirm path tests BOTH before the
// row jump table; static session ff7_menu_mask_static/_disasm2.py
// 2026-08-04). Both are rebuilt from the savemap EVERY frame the
// main-menu handler 0x6CA346 runs (build at 0x6CA38C..0x6CA428, after
// the init-once branch), so they are always fresh while the menu is up:
//   MENU_VISIBLE_ROWS  0xDC111C = savemap+0xBC0 u16 ("menu visible/
//     enabled" mask, bit SET = row available) OR 0x0400 (Quit, the
//     PC-only row, is forced on).  THIS is what carries the early-game
//     Materia/PHS story lock: the pre-hideout save has +0xBC0 = 0x02FB
//     = all rows except bit 2 (Materia) and bit 8 (PHS).
//   MENU_DISABLED_ROWS 0xDC1130 = savemap+0xBC2 u16 ("menu locking"
//     mask, bit SET = row refused) AND 0xFBFF (Quit can never lock),
//     then bits 0 (Item) + 6 (Limit) forced on while savemap+0xE13
//     bit 0 is set (a field-script flag; the save-menu module reads
//     +0xE13 too).
// A row activates only when its VISIBLE bit is set AND its DISABLED
// bit is clear.  v2.32..v2.30.77 read only DISABLED_ROWS, which is
// all-zero in the early game — that is why Materia/PHS never spoke
// ", not available" before the hideout scene (user report 2026-08-04).
constexpr uint32_t MENU_VISIBLE_ROWS    = 0x00DC111C; // u16 bitmask, bit N SET = row N available
constexpr uint32_t MENU_DISABLED_ROWS   = 0x00DC1130; // u16 bitmask, bit N SET = row N locked/grayed
constexpr uint32_t MENU_FOCUS_MODE      = 0x00DC1324; // u8: 0=menu bar, 1=char-select pane, 2=Order pane
constexpr uint32_t ORDERMENU_CURSOR     = 0x00DC11C4; // u8 party slot 0..2 (rides empty slots)
constexpr uint32_t ORDERMENU_LATCH      = 0x00DC1320; // u32 1 = first member selected
constexpr uint32_t ORDERMENU_FIRST_SLOT = 0x00DC110C; // s8 slot saved at first confirm
constexpr uint32_t CHARSEL_CURSOR       = 0x00DC118C; // u32 mode-1 pane cursor (Magic/Equip/Status)
constexpr uint32_t CHARSEL_CHOSEN       = 0x00DC1288; // u32 slot chosen in mode 1 (v2.33 status reader)

// STATUS screen (v2.33): a real dispatched sub-screen, unlike Order —
// FFNx's own ff7_data.h names menu_subs_call_table[5] status_menu_sub
// (table[5] = 0x703ABD in our table dump), so the dispatch index IS the
// gate, same shape as the item screen's index 1. Character shown =
// CHARSEL_CHOSEN (the v2.32 mode-1 commit). Savemap record offsets used
// by the reader (all screenshot-verified 2026-07-18, status_record_verify
// log): +0x01 level, +0x0E limit level, +0x1C weapon id, +0x1D armor id,
// +0x1E accessory id (0xFF = none), +0x3C exp u32, +0x80 exp-to-next u32.
// ⚠ record +0x02..+0x07 are BASE stats — the screen shows EFFECTIVE
// (record str 22/mag 20 vs screen 20/24, Cloud's materia at work); the
// effective values come from BATTLE_CHAR_BLOCK (see its v2.33 note).
constexpr uint32_t STATUSMENU_SCREEN_INDEX  = 5;
constexpr uint32_t SAVEMAP_CHAR_LEVEL_OFF   = 0x01;
constexpr uint32_t SAVEMAP_CHAR_LIMITLVL_OFF = 0x0E;
constexpr uint32_t SAVEMAP_CHAR_WEAPON_OFF  = 0x1C;
constexpr uint32_t SAVEMAP_CHAR_ARMOR_OFF   = 0x1D;
constexpr uint32_t SAVEMAP_CHAR_ACCESS_OFF  = 0x1E;
constexpr uint32_t SAVEMAP_CHAR_EXP_OFF     = 0x3C;
constexpr uint32_t SAVEMAP_CHAR_EXPNEXT_OFF = 0x80;

// ---------------------------------------------------------------------------
// SHOP menu (v2.30.28, 2026-07-26) — ALL STATIC-DERIVED in one session
// (investigate/ff7_shop_static.py, log shop_static_20260726_101315; every
// address below read straight off the annotated disasm, cross-anchored to
// FFNx's shop chain: ff7_data.h menu_sub_6CDA83 --0xC1--> 6CBD54 --0x7-->
// 71FF95 --0x84--> menu_shop_loop = 0x71AAA3, verified on disk byte-exact,
// plus the FFNx-documented get_materia_gil call site at shop_loop+0x327B).
//
// HOW A SHOP OPENS: the field MENU opcode switches GAME_MODE (0xCC0D89) and
// the menu module's own dispatcher menu_sub_6CDA83 switches on it via a jump
// table (index bytes 0x6CDBE4, targets 0x6CDBC4, decoded offline):
//   GAME_MODE 6 = name entry (matches the long-confirmed GAME_MODE_NAME_ENTRY)
//   GAME_MODE 7 = PHS,  GAME_MODE 8 = SHOP,  GAME_MODE 9 = main menu
//   (9 = main menu matches the long-confirmed "9 = menu" observation —
//   two independent confirmations that the decode is right.)
// So the mod's whole shop gate is GAME_MODE == 8. The shop id travels as
// the menu PARAM word 0xCC0D8A -> copied to SHOP_ID by the shop init
// (0x719D7A disasm).
constexpr uint8_t  GAME_MODE_SHOP  = 8;
constexpr uint8_t  GAME_MODE_PHS   = 7;   // same jump-table decode; the PHS
                                          // screen from field scripts. Not
                                          // yet hooked — known only so the
                                          // main-menu threads can stand down
                                          // (their MENU_OPEN/cursor bytes go
                                          // stale-but-raised there too).
constexpr uint32_t MENU_PARAM_WORD = 0x00CC0D8A;  // s16 opcode param (shop id)

// The shop loop (0x71AAA3) is a switch on SHOP_STATE (jump table 0x71E193,
// 7 targets, decoded offline). States, identified by what each case draws
// (caption strings + which cursor variables feed the highlight rectangles):
//   0 = greeting + Buy/Sell/Exit bar   ("Welcome!" text-set string)
//   1 = BUY list                        (ware names/prices, gil header)
//   2 = SELL item list                  (savemap items[] 2-column grid)
//   3 = SELL materia list               (savemap materia[] 1-column list)
//   4 = BUY quantity  ("How many")      (qty x unit price total drawn)
//   5 = SELL item quantity ("How many") (qty x price/2 total drawn)
//   6 = sell-type bar (Item / Materia)  (sell prompt text-set string)
constexpr uint32_t SHOP_STATE = 0x0092565C;  // u32 0..6 (see above)

// Shop session globals (shop wrapper 0x71FF95 + init 0x719D7A disasm):
constexpr uint32_t SHOP_ID         = 0x00DD4724; // u32 copy of the param word
constexpr uint32_t SHOP_NAME_IDX   = 0x00DD4728; // u32 = catalog byte +0
constexpr uint32_t SHOP_TEXT_IDX   = 0x00DD472C; // u32 = catalog byte +1
constexpr uint32_t SHOP_FADE_STATE = 0x00DD4734; // u32 1=in 2=out -1=exiting
constexpr uint32_t SHOP_SESSION    = 0x00DD6D78; // u32 1 while shop running
constexpr uint32_t SHOP_QTY        = 0x00DD473C; // u32 "How many" count
                                                 // (set to 1 on qty entry)

// Cursor widgets. The shop builds generic menu list widgets (constructor
// 0x6F4D30 at 0x71A6F5..): struct +0 = COLUMN, +4 = visible ROW, +0x14 =
// SCROLL (rows). Bases below; the ABSOLUTE-index formulas are the ones the
// shop's own confirm handlers compute (buy: 0x71DAF7; sell items: 0x71DC2B
// `col + row*2 + scroll*2`; sell materia: 0x71DD0A `row + scroll`):
constexpr uint32_t SHOP_BAR_CURSOR      = 0x00DD6B48; // u32 0=Buy 1=Sell 2=Exit
constexpr uint32_t SHOP_SELLTYPE_CURSOR = 0x00DD6C98; // u32 0=Item 1=Materia
constexpr uint32_t SHOP_BUY_ROW         = 0x00DD6B84; // u32; ware = row+scroll
constexpr uint32_t SHOP_BUY_SCROLL      = 0x00DD6B94; // u32
constexpr uint32_t SHOP_SELLI_COL       = 0x00DD6BB8; // u32 0/1 (2-col grid)
constexpr uint32_t SHOP_SELLI_ROW       = 0x00DD6BBC; // u32 visible row
constexpr uint32_t SHOP_SELLI_SCROLL    = 0x00DD6BCC; // u32 row scroll
constexpr uint32_t SHOP_SELLM_ROW       = 0x00DD6BF4; // u32; slot = row+scroll
constexpr uint32_t SHOP_SELLM_SCROLL    = 0x00DD6C04; // u32

// The SHOP CATALOG is static exe data (init 0x719D7A + buy-list code):
// record = 0x923418 + shop_id*0x54:
//   +0 u8  shop name index  -> FF7-encoded string 0x922FC8 + idx*0x14
//   +1 u8  greeting-set idx -> FF7-encoded strings 0x923080 + idx*0x1CC
//          (the set's first string is the greeting; later strings in the
//          set are the buy/sell/how-many prompts the states draw)
//   +2 u16 ware count (buy-list bound, compared at 0x71B826)
//   +4 ware[10]: { s16 type (0=item id 0-319, 1=materia id 0-95);
//                  u16 pad; u32 id } — 8 bytes each (0x54 = 4 + 10*8)
constexpr uint32_t SHOP_CATALOG        = 0x00923418;
constexpr uint32_t SHOP_CATALOG_STRIDE = 0x54;
constexpr uint32_t SHOP_NAME_STRINGS   = 0x00922FC8; // stride 0x14
constexpr uint32_t SHOP_GREET_STRINGS  = 0x00923080; // stride 0x1CC

// PRICES: the game keeps one live price table behind a pointer (reads at
// 0x71B8ED item / 0x71B981 materia, and every affordability check):
//   u32 buy price of item id  = [[SHOP_PRICE_TABLE_PTR] + (id&0x1FF)*4]
//   u32 buy price of materia  = [[SHOP_PRICE_TABLE_PTR] + 0x600 + (id&0xFF)*4]
//   item SELL price  = buy >> 1            (drawn at 0x71BD1C, exact)
//   materia SELL     = get_materia_gil 0x71FCF9: AP-mastered (ap field ==
//                      0xFFFFFF) -> base*70, else -> the raw AP count
//                      ("Price through AP" on the sighted screen; base
//                      price 1 = unsellable marker, returns 1)
// Validate the pointer before EVERY read — heap allocation, not static.
constexpr uint32_t SHOP_PRICE_TABLE_PTR = 0x00DD4720;
constexpr uint32_t SHOP_PRICE_MATERIA_OFF = 0x600;

// Sell restriction: bit 0 of the kernel gear record word returned by
// 0x6C50DD (disasm; the sell handler at 0x71DC60 does `and eax,1` and
// refuses the row). The four kernel DATA arrays it indexes (loaded to
// static BSS, stride = kernel record size):
//   items       id 0x00-0x7F: u16[0xDBD16A + id*0x1C]
//   weapons     id 0x80-0xFF: u16[0xDBE75A + (id-0x80)*0x2C]
//   armor      id 0x100-0x11F: u16[0xDBCD00 + (id-0x100)*0x24]
//   accessories id 0x120+   : u16[0xDBCAEE + (id-0x120)*0x10]
constexpr uint32_t KERNEL_ITEM_RESTRICT   = 0x00DBD16A;
constexpr uint32_t KERNEL_WEAPON_RESTRICT = 0x00DBE75A;
constexpr uint32_t KERNEL_ARMOR_RESTRICT  = 0x00DBCD00;
constexpr uint32_t KERNEL_ACCESS_RESTRICT = 0x00DBCAEE;

// ---------------------------------------------------------------------------
// MATERIA menu (v2.30.33, 2026-07-26) — ALL STATIC in one session
// (investigate/ff7_materia_menu_static.py, log materia_menu_static_
// 20260726_125924; the shop-session recipe: full annotated disasm of the
// sub + depth-2 write mining, semantics hand-read off the dump).
//
// The materia menu IS menu_subs_call_table[3] (= 0x70CF0B) — the screen
// the v2.31 caption evidence pointed at all along (its "Arrange" string
// belongs to THIS screen's Check/Arrange bar, and its 0xDCA7F8 exclusive
// block is this screen's state; the row->index pattern Item row0=1 ...
// Status row4=5 also lands Materia row2 = index 3).
//
// The sub is a switch on MATMENU_MODE (jump table 0x70E246, modes 0-0xB;
// transitions read off the case code):
//   0 = Check/Arrange bar (OK on Check -> 4, on Arrange -> 8;
//       RIGHT/Cancel -> 1)
//   1 = equipment slot navigation (LEFT from weapon slot 0 -> 0;
//       OK on an existing slot -> 3)
//   3 = materia list, equipping (OK commits into the slot — the commit
//       at 0x70DC80..0x70DD0C is where the index formula comes from)
//   4 = Check mode (slot browsing, detail pane)
//   5/6/7 = transient (~0x30-byte cases — waits/animations; silent)
//   8 = Arrange popup (Arrange / Exchange / Remove all / Trash — the
//       0x920C63..0x920CA3 string run, widget rows=4)
//   9/10 = arrange-mode list phases (exchange/trash targets)
//   2/11 = empty cases (exit/idle)
// Cursor widgets are the same generic ctor 0x6F4D30 as the shop's
// (+0 col, +4 row, +0x14 scroll).
constexpr uint32_t MATMENU_SCREEN_INDEX  = 3;          // dispatch index
constexpr uint32_t MATMENU_MODE          = 0x00920FA0; // u32 0..0xB
constexpr uint32_t MATMENU_BAR_CURSOR    = 0x00DD12BC; // u32 0=Check 1=Arrange
constexpr uint32_t MATMENU_SLOT_IDX      = 0x00DD12F0; // u32 slot 0..7
constexpr uint32_t MATMENU_SLOT_ROW      = 0x00DD12F4; // u32 0=weapon 1=armor
constexpr uint32_t MATMENU_PARTY_SLOT    = 0x00DD1638; // u32 party slot 0..2
                                                       // (x0x440 into the
                                                       // shared char-data
                                                       // block for slot
                                                       // counts at +0x21)
constexpr uint32_t MATMENU_CHARREC_PTR   = 0x00DCA810; // u32 -> savemap char
                                                       // record (init
                                                       // 0xDBFD8C = Cloud)
                                                       // ⚠ STALE on the
                                                       // page-up/down char
                                                       // flip (2026-08-04
                                                       // play report: every
                                                       // char spoke Cloud's
                                                       // materia). DO NOT
                                                       // read for identity —
                                                       // resolve the char
                                                       // via MATMENU_PARTY_
                                                       // SLOT → SAVEMAP_
                                                       // PARTY_IDS instead
                                                       // (v2.30.79; same
                                                       // class as the
                                                       // v2.30.50 CHARSEL
                                                       // equip bug).
constexpr uint32_t MATMENU_EQUIP_ROW     = 0x00DD1364; // mode-3 list widget
constexpr uint32_t MATMENU_EQUIP_SCROLL  = 0x00DD1374; // idx = row + scroll
constexpr uint32_t MATMENU_ARR_ROW       = 0x00DD14B4; // mode-9/10 list
constexpr uint32_t MATMENU_ARR_SCROLL    = 0x00DD14C4;
constexpr uint32_t MATMENU_POPUP_ROW     = 0x00DD147C; // u32 0..3
constexpr uint32_t MATMENU_CHECK_COL     = 0x00DD1398; // mode-4 slot widget
constexpr uint32_t MATMENU_CHECK_ROW     = 0x00DD139C; // 0=weapon 1=armor
// Char record materia arrays (the shop's equipped-count walker reads the
// same offsets; = FFNx savemap_char layout):
constexpr uint32_t SAVEMAP_CHAR_WMATERIA_OFF = 0x40;   // u32[8] id|ap<<8
constexpr uint32_t SAVEMAP_CHAR_AMATERIA_OFF = 0x60;   // u32[8]

// ---------------------------------------------------------------------------
// EQUIP menu (v2.30.34, 2026-07-26) — ALL STATIC, one session
// (investigate/ff7_equip_menu_static.py + targeted writer sweeps; log
// equip_menu_static_20260726_131256). The equip menu is
// menu_subs_call_table[4] = 0x705D16 — FFNx's own menu_sub_705D16 name,
// AND the row->index pattern (Item row0=1 ... Status row4=5 => Equip
// row3=4). Table[15] holds the same pointer (dupe slot); the gate
// accepts either index defensively.
//
// State (writer sweep + input-handler disasm 0x707040..0x7076xx):
//   ⚠ v2.30.50 PLAY-CORRECTION (Barret "Bronze Bangle" report,
//   2026-08-01): the v2.30.34 reading of 0xDCA4A4 as the category row
//   was WRONG — TWO 0..2-wrapping cursors coexist on this screen and
//   the July session grabbed the wrong one. The ±1-wrap code at
//   0x707079/0x7070C0 that "settled" it reads
//   SAVEMAP_PARTY_IDS[0xDCA4A4] after every step and re-steps on 0xFF
//   (empty slot skip — re-read 2026-08-01): that is a PARTY-MEMBER
//   cycler (the L1/R1 character flip), and the 0x707105 block copies
//   it into CHARSEL_CHOSEN. With a 3-member party both cursors wrap
//   0..2 — indistinguishable by value range; the party-ids skip loop
//   was the overlooked discriminator. The REAL category row is
//   0xDCA5C4: the OK handler (key 0x20 at 0x707175) passes IT to the
//   candidate-list builder (0x707187 → 0x7083ED), and every bounds
//   check compares it against 2 (0x705F20/0x706108/...).
//   EQMENU_LIST_OPEN — 0 = category rows, 1 = candidate list (set at
//                      0x7071C3 on OK, cleared at 0x707346/0x707601)
//   candidate list widget @0xDCA5F8 (generic ctor: +4 row, +0x14
//   scroll); the OK-commit reads candidate =
//   BYTES[0xDCA6A8][row+scroll] (0x707350..0x70735E) — bytes are gear
//   indices WITHIN the current category's kernel namespace, list
//   terminated 0xFF, count at EQMENU_LIST_COUNT (written by the list
//   builder 0x708640).
// Character shown: resolve via EQMENU_PARTY_SLOT → SAVEMAP_PARTY_IDS
// (CHARSEL_CHOSEN only receives the copy on specific key paths —
// v2.30.50; the old CHARSEL-based read spoke the pre-flip character
// after an L1/R1 cycle). Equipped ids live in the savemap record at
// +0x1C/+0x1D/+0x1E (v2.33 offsets).
constexpr uint32_t EQMENU_SCREEN_INDEX  = 4;           // (15 = dupe slot)
constexpr uint32_t EQMENU_PARTY_SLOT   = 0x00DCA4A4;   // u32 0..2 (was mis-
                                                       // named EQMENU_CATEGORY
                                                       // v2.30.34-.49)
constexpr uint32_t EQMENU_CATEGORY     = 0x00DCA5C4;   // u32 0..2 row cursor
                                                       // (0=Wpn 1=Arm 2=Acc)
constexpr uint32_t EQMENU_LIST_OPEN    = 0x00DCA6A0;   // u32 0/1
constexpr uint32_t EQMENU_LIST_ROW     = 0x00DCA5FC;   // u32
constexpr uint32_t EQMENU_LIST_SCROLL  = 0x00DCA60C;   // u32; idx=row+scroll
constexpr uint32_t EQMENU_LIST_COUNT   = 0x00DCA7EC;   // u32 candidates
constexpr uint32_t EQMENU_LIST_BYTES   = 0x00DCA6A8;   // u8[] gear indices
                                                       // (category-relative)

// ---------------------------------------------------------------------------
// LIMIT menu (v2.30.35, 2026-07-26) — ALL STATIC, one session
// (investigate/ff7_limit_menu_static.py + targeted sweeps; log
// limit_menu_static_20260726_132310). The limit menu is
// menu_subs_call_table[7] = 0x70212A (the row->index pattern's fifth
// consecutive confirmation: Limit row 6 -> index 7).
//
// State (draw switch 0x70313A + input region 0x702C40..0x703130):
//   LIMITMENU_MODE       — 0=Set/Check bar, 1..4 = grid/confirm phases
//                          (exact per-value meaning rides the debug log;
//                          the mod tracks BOTH grid cursor pairs mode-
//                          agnostically so a mis-guessed mapping cannot
//                          silence announcements)
//   LIMITMENU_BAR_CURSOR — ×0x50 highlight spacing (Set / Check)
//   Set grid  col/row    — ×0x124 / ×0x89 highlight spacing: the 2x2
//                          LEVEL grid; level = row*2 + col
//   Check grid col/row   — the second grid instance (+0x70 struct echo)
//   LIMITMENU_PARTY_SLOT — party slot 0..2; the sub resolves char via
//                          SAVEMAP_PARTY_IDS + the game's own id->record
//                          table 0x919928 (disasm 0x70216A..0x702186)
// Limit-learned bitmask: charrec +0x22 u16, bit = level*3 + technique
// (the 0x702190 `imul ecx,3 / shl` loop). Technique NAMES = magic text
// entries 128 + block*7 + (level*2 + tech; level-4 single = +6), where
// block = savemap record index with the KERNEL'S Aeris/Tifa swap
// (kernel2 ground truth 2026-07-26: 128 Braver/Cloud, 135 Big Shot/
// Barret, 142 Healing Wind/AERIS, 149 Beat Rush/TIFA, 156 Sled Fang/
// Red XIII). Current limit level = charrec +0x0E (v2.33 offset).
constexpr uint32_t LIMITMENU_SCREEN_INDEX = 7;
constexpr uint32_t LIMITMENU_MODE        = 0x009204D8; // u32 0..4
constexpr uint32_t LIMITMENU_BAR_CURSOR  = 0x00DCA1D0; // u32 0=Set 1=Check
constexpr uint32_t LIMITMENU_SETG_COL    = 0x00DCA198; // u32 0/1
constexpr uint32_t LIMITMENU_SETG_ROW    = 0x00DCA19C; // u32 0/1
constexpr uint32_t LIMITMENU_CHKG_COL    = 0x00DCA208; // u32 0/1
constexpr uint32_t LIMITMENU_CHKG_ROW    = 0x00DCA20C; // u32 0/1
constexpr uint32_t LIMITMENU_PARTY_SLOT  = 0x00DCA3C8; // u32 0..2
constexpr uint32_t SAVEMAP_CHAR_LIMITBITS_OFF = 0x22;  // u16 learned mask

// ---------------------------------------------------------------------------
// MAGIC menu (v2.30.48, 2026-08-01) — the last un-narrated main-menu screen
// besides PHS. ALL STATIC (investigate/ff7_magic_menu_static.py, log
// magic_menu_static_20260801_110149):
//
//   Screen = menu_subs_call_table[2] = 0x710DFA (row->index pattern: Item
//   row 0 = 1, Materia row 2 = 3, Status row 4 = 5 => Magic row 1 = 2).
//
//   THE SPELL LIST IS THE BATTLE LIST: the sub computes
//   [MAGICMENU_PARTY_SLOT]*0x440 + 0xDBA5A0 — and 0xDBA5A0 ==
//   BATTLE_CHAR_BLOCK + BCHAR_OFF_MAGIC_LIST exactly (the [ptr]+offset ==
//   static proof pattern), so the menu shares battle's per-slot magic
//   entries: stride 8, u8 spell id @+0 (0xFF = empty cell), the v2.36
//   layout verbatim. index = col + (row + scroll)*3 (3-column grid, read
//   off the draw loop at sub+0x92C..0x99F).
//
//   MAGICMENU_LIST_* is a STANDARD list widget (ctor 0x6F4D30 family):
//   0xDD1708 +0 col / +4 row / +0x14 scroll — the three fields the sub
//   reads for its index math sit at exactly the canonical offsets.
//
//   MAGIC_MENU_USABLE_TABLE: the renderer's OWN menu-usable classifier —
//   u8[0x714440 + id] (ids 0..0x33) selects a jump-table case (0x714430);
//   cases 0/1/2 draw color 7 (white/usable), case 3 and all ids > 0x33
//   draw color 0 (grayed, battle-only). Read LIVE from the exe image so
//   the spoken "battle only" state mirrors the drawn gray by
//   construction (disk bytes: usable = ids {0,1,2,7,8,0x33}).
//
//   MAGICMENU_MODE (0x921100): the screen's input MODE, dispatched
//   through the jump table at 0x7144CC (8 cases). ⚠ v2.30.52
//   PLAY-CORRECTION — the v2.30.48 guess (0 = spell list, 1 = target)
//   was INVERTED, which is why arrow keys spoke nothing:
//     case 0 (handler 0x7135F8) = CHARACTER-SELECT pane. Its up/down
//       (keys 4/8 via 0x6F53F1) cycle MAGICMENU_PARTY_SLOT 0..2 with
//       the SAVEMAP_PARTY_IDS 0xFF skip — the same party-cycler shape
//       that mis-identified the equip cursor in v2.30.34/.50.
//     case 1 (handler 0x71377F) = THE SPELL LIST: it computes the
//       spell index from the cursor trio and runs the OK press (MP
//       check reads block+0x14 = current MP at [slot*0x440+0xDBA4AC],
//       cost = list entry byte +1) — the definitive "this mode owns
//       the spell grid" evidence, the same what-consumes-it rule that
//       settled the equip category row.
//     -1 seen at screen entry (pre-init), 2/3 written as mode+2 on OK
//       (0x713638/0x713693) = the confirm/target sub-modes.
//   LIVE EVIDENCE (2026-08-01 diag session): mode ran -1 → 0 and STAYED
//   0 while the player pressed up/down eight times; the cursor trio
//   never moved — because those presses were the case-0 character
//   cycler, not the grid.
constexpr uint32_t MAGICMENU_SCREEN_INDEX = 2;
constexpr uint32_t MAGICMENU_PARTY_SLOT   = 0x00DD17E8; // u32 0..2
constexpr uint32_t MAGICMENU_LIST_COL     = 0x00DD1708; // u32 widget +0 (0..2)
constexpr uint32_t MAGICMENU_LIST_ROW     = 0x00DD170C; // u32 widget +4
constexpr uint32_t MAGICMENU_LIST_SCROLL  = 0x00DD171C; // u32 widget +0x14
// ---------------------------------------------------------------------------
// v2.30.54 — THE MAGIC SCREEN IS A THREE-TAB SCREEN. Settled by a live
// delta scan (the mod snapshotted this whole BSS block and logged every
// dword that moved while the player pressed Down three times): the ONLY
// address that moved was MAGICMENU_TAB, stepping 0→1→2→0. Three items,
// wrapping — the Magic / Summon / Enemy Skill tabs. Everything else
// falls out of that:
//   mode (0x921100) = TAB + 2 on OK (0x713638/0x713693), so
//     mode 2 = Magic list, 3 = Summon list, 4 = Enemy Skill list,
//     mode 0 = the tab selector itself, -1 = entering.
//   Each tab has its OWN canonical widget and per-character list base
//   (draw paths 0x710F94 / 0x71186E / 0x711EB8, OK paths 0x7137A9 /
//   0x712C46 / 0x713284):
//     Magic  widget 0xDD1708, base +0x108, THREE columns
//            (index = col + 3·(row+scroll))
//     Summon widget 0xDD1740, base +0x2C8, TWO columns
//            (index = col + 2·(row+scroll) — lea [col + row*2])
//     E.Skill widget 0xDD1778, base +0x348, TWO columns  ← new offset,
//            the third per-character list (0xDBA7E0 - 0xDBA498)
// ⚠ THE COST OF NOT MEASURING: v2.30.48/.52/.53 each guessed a piece of
// this from static reads (a "3-column grid" that was really three tabs;
// a mode inversion; a case-index-vs-stored-value mismatch) and each
// shipped broken. The delta scan answered all of it in one session.
constexpr uint32_t MAGICMENU_TAB          = 0x00DD169C; // u32 0=Magic
                                                        // 1=Summon 2=E.Skill
constexpr uint32_t MAGICMENU_SUM_COL      = 0x00DD1740;
constexpr uint32_t MAGICMENU_SUM_ROW      = 0x00DD1744;
constexpr uint32_t MAGICMENU_SUM_SCROLL   = 0x00DD1754;
constexpr uint32_t MAGICMENU_ESK_COL      = 0x00DD1778;
constexpr uint32_t MAGICMENU_ESK_ROW      = 0x00DD177C;
constexpr uint32_t MAGICMENU_ESK_SCROLL   = 0x00DD178C;
constexpr uint32_t BCHAR_OFF_ESKILL_LIST  = 0x348;      // 8-byte entries
constexpr uint32_t MAGICMENU_MODE         = 0x00921100; // s32 input mode
// LIVE-MEASURED values (2026-08-01 diag session, v2.30.53 — these
// supersede every static guess; the jump-table case indices are NOT
// these numbers, because the OK paths write mode = [0xDD169C] + 2
// (0x713638/0x713693), so the stored value is offset from the case):
//   -1 = screen entering (pre-init)
//    0 = CHARACTER-SELECT pane (party slot moves here)
//    2 = SPELL GRID  ← the cursor trio moves ONLY here (row 0→1→0
//        observed against the player's own arrow presses)
//    3+ = confirm / use-on-whom sub-modes (not yet observed live)
constexpr int32_t  MAGICMENU_MODE_ENTERING  = -1;
constexpr int32_t  MAGICMENU_MODE_TABS      = 0;   // tab selector
// v2.30.59 LIVE-MEASURED: OK on a field-usable spell goes to mode 1 and
// Cancel returns to the list mode (log 2026-08-01: "MAGICM mode 2 -> 1"
// on selecting Cure, "1 -> 2" on cancel). This is the "use on whom?"
// character picker. ⚠ historical trap: 1 was ALSO v2.30.52's wrong guess
// for the spell list — the number is right here for a different pane.
constexpr int32_t  MAGICMENU_MODE_TARGET    = 1;
constexpr int32_t  MAGICMENU_MODE_LIST_MIN  = 2;   // 2/3/4 = the three lists
constexpr int32_t  MAGICMENU_MODE_LIST_MAX  = 4;
constexpr uint32_t MAGICMENU_TARGET_SLOT  = 0x00DD16D4; // u32 party slot the
                                                        // OK path indexes into
                                                        // SAVEMAP_PARTY_IDS
                                                        // (0x7137F8) — the
                                                        // use-on-whom cursor.
                                                        // PLAY-CONFIRMED
                                                        // 2026-08-01 (v2.30.59)
constexpr uint32_t MAGIC_MENU_USABLE_TABLE = 0x00714440; // u8[0x34] in .text
constexpr uint32_t MAGIC_MENU_USABLE_GRAY_CASE = 3;      // case 3 = grayed

// ---------------------------------------------------------------------------
// MENU TUTORIAL live state (v2.30.29, 2026-07-26) — the per-slide sync the
// v2.30.27 narrator lacked. ALL STATIC (investigate/ff7_tutorial_static.py,
// log tutorial_static_20260726_110911 + the writer sweeps in the same
// session; FFNx cross-anchor: menu_tutorial_window_state / _text_ptr are
// FFNx's own names for the first two, resolved via its documented chain
// menu_sub_6CB56A+0x2B7 -> renderer 0x6C49FD, operands +0x9/+0x18).
//
// ARCHITECTURE (who does what, from the disasm):
//   - The field TUTOR opcode only REQUESTS a tutorial; the menu module
//     starts it (0x6CB618 start_tutorial(script_ptr), which sets
//     TUTORIAL_RUNNING=1 and SCRIPT_PC=ptr INTO THE FIELD BUFFER).
//   - A byte-code VM (0x71832E, jump table 0x7185C7) steps the script
//     each menu tick: opcode 0x00=wait u16 frames, 0x02-0x0D = INJECTED
//     key presses driving the demo (masks UP 0x1000/DOWN 0x4000/LEFT
//     0x8000/RIGHT 0x2000/OK 0x20/CANCEL 0x40/menu-buttons 0x80,0x10,
//     8,4,2,1), 0x10 = open text window (text follows to 0xFF), 0x12 =
//     window x,y, 0x11 = END (clears TUTORIAL_RUNNING).
//   - While a tutorial runs, the menu's input refresh (0x7186C8 ->
//     0x71826E) OVERWRITES the pressed/held digests (0x9A85E0/0x9A85D4)
//     with the VM's output — REAL INPUT NEVER REACHES MENU NAVIGATION
//     during a tutorial (why pressing keys mid-demo does nothing).
//   - The text window is the ONLY player-paced element: renderer state 2
//     closes when the raw pressed digest is nonzero — ANY key (test
//     eax,eax at 0x6C4C52), after a minimum-display countdown
//     (TUTWIN_TIMER from 0x14/0x28). TUTWIN_MODE==0 windows (the save
//     screen's info popups reuse this renderer) auto-close on the timer
//     instead and take no input.
constexpr uint32_t TUTORIAL_RUNNING = 0x00DBFD30; // u32 1 = tutorial active
constexpr uint32_t TUTWIN_STATE    = 0x00DC1310;  // u8 0=closed 1=opening
                                                  //    2=text shown 3=closing
constexpr uint32_t TUTWIN_TEXT_PTR = 0x00DC1214;  // u32 -> CURRENT window's
                                                  //    FF7 text (state>=1)
constexpr uint32_t TUTWIN_MODE     = 0x00DC1318;  // u8 0=timer auto-close,
                                                  //    else any-key-advanced
constexpr uint32_t TUTWIN_TIMER    = 0x00DC1314;  // u32 min-display countdown
                                                  //    (not consumed; doc)
constexpr uint32_t TUTORIAL_SCRIPT_PC = 0x00DD1BC8; // u32 -> next opcode in
                                                  // the field buffer (doc)

// Savemap gil + materia inventory (promoted from raw literals now that a
// third feature reads them; gil offset live-proven by the v2.35 victory
// total, materia array = FFNx savemap struct, and the shop's own sell
// code indexes both exactly here — 0x71DD16/0x71DBB2):
constexpr uint32_t SAVEMAP_GIL     = SAVEMAP_BASE + 0xB7C;   // 0xDC08B4 u32
constexpr uint32_t SAVEMAP_MATERIA = SAVEMAP_BASE + 0x77C;   // 0xDC04B4
constexpr uint32_t SAVEMAP_MATERIA_COUNT = 200;              // u32 id|ap<<8
                                                             // -1 = empty slot

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
// Savemap character records and party roster (v2.19).
//
// DERIVATION (no scan needed — pinned by two independent layout anchors):
//   1. The 7thHeaven-confirmed equipment blocks above start at
//      SAVEMAP_BASE + 0x70 with the WEAPON byte first. In the community-
//      documented savemap character struct (qhimm wiki "Save Map"), the
//      weapon byte sits at record offset 0x1C — so the records themselves
//      begin at 0x70 - 0x1C = savemap + 0x54.
//   2. Nine records of 0x84 bytes end at 0x54 + 9*0x84 = 0x4F8, which is
//      EXACTLY where the same community layout places the three party-
//      member ID bytes. Both anchors agree, so the record base, stride,
//      and the party array location all lock together.
//
// RUNTIME CROSS-CHECK (used by proxy.cpp PartySlotLabel): the byte at
// SAVEMAP_PARTY_IDS (party slot 0's character ID) must equal PARTY_LEADER
// (0xDC09E5, 7thHeaven-confirmed, live-proven by the v2.7+ battle labels).
// Party slot 0 IS the leader by definition, so any mismatch means the
// derivation doesn't hold in this build — the mod then falls back to the
// old positional "ally N" labels instead of speaking a wrong name.
// ---------------------------------------------------------------------------

// First of 9 character records (Cloud), stride 0x84. Name field: FF7-encoded,
// 0xFF-terminated, at +0x10 (12 bytes) — this is the LIVE name, so player
// renames from the naming screen are reflected automatically.
constexpr uint32_t SAVEMAP_CHAR_RECORDS  = SAVEMAP_BASE + 0x54;   // 0xDBFD8C
constexpr uint32_t SAVEMAP_CHAR_REC_SIZE = 0x84;
constexpr uint32_t SAVEMAP_CHAR_NAME_OFF = 0x10;
constexpr uint32_t SAVEMAP_CHAR_NAME_LEN = 12;

// Three party-member character IDs, one per battle/menu party slot 0-2.
// 0xFF = empty slot. IDs 0-8 = the nine playable characters; the Kalm
// flashback uses 9 (Young Cloud, data stored in Cait Sith's record) and
// 10 (Sephiroth, data stored in Vincent's record).
constexpr uint32_t SAVEMAP_PARTY_IDS = SAVEMAP_BASE + 0x4F8;      // 0xDC0230

// Character record HP/MP words (v2.31, offsets from FFNx's savemap_char
// struct — same struct that gave the live-verified +0x10 name field, and
// the id/level bytes at +0x00/+0x01 already used by the v2.19 machinery):
//   +0x2C current HP, +0x38 max HP, +0x30 current MP, +0x3A max MP.
// Spoken in the item menu's use-on-whom pane for heal-target parity (the
// sighted pane shows exactly these four numbers — items_menu_2.png).
constexpr uint32_t SAVEMAP_CHAR_HP_OFF     = 0x2C;
constexpr uint32_t SAVEMAP_CHAR_MAXHP_OFF  = 0x38;
constexpr uint32_t SAVEMAP_CHAR_MP_OFF     = 0x30;
constexpr uint32_t SAVEMAP_CHAR_MAXMP_OFF  = 0x3A;

// Battle-row byte (v2.32): 0xFF = front row, 0xFE = back row. LIVE-CONFIRMED
// by the Order-menu scan (record+0x20 toggled 0xFF↔0xFE — the single A/B/A
// candidate) AND by the Order handler disasm (XOR 1 at 0x6CA67F..0x6CA6A4).
// ⚠ The community savemap doc places this at +0x1F ("flags") — that is one
// byte off; +0x1F stayed 0 throughout the live toggle.
constexpr uint32_t SAVEMAP_CHAR_ROW_OFF    = 0x20;
constexpr uint8_t  SAVEMAP_ROW_FRONT       = 0xFF;
constexpr uint8_t  SAVEMAP_ROW_BACK        = 0xFE;

// Party inventory: savemap items[320] (v2.31). Offset +0x4FC is pinned by
// the FFNx savemap struct layout: party_members[3] at +0x4F8 (live-verified
// above) + one padding byte. Word format per FFNx's own reimplementation
// of menu_decrease_item_quantity (FFNx/src/ff7/menu.cpp):
//   id = word & 0x1FF, quantity = word >> 9, EMPTY SLOT = 0xFFFF.
// The on-screen item-list ROW ORDER is the ARRAY ORDER (the menu draws
// slots as stored; Arrange rewrites the array itself).
// Item id namespace (id = word & 0x1FF):
//   0-127 items, 128-255 weapons (-128), 256-287 armor (-256),
//   288-319 accessories (-288) — same split ResolveActionName already uses
//   for thrown weapons (id space shared with battle).
constexpr uint32_t SAVEMAP_ITEMS       = SAVEMAP_BASE + 0x4FC;    // 0xDC0234
constexpr uint32_t SAVEMAP_ITEMS_COUNT = 320;

// Key items: 32-byte bitmask (256 key-item bits) right after the materia
// arrays (FFNx savemap struct field_B5C). NOT yet consumed by the mod —
// recorded for the Key Items pane follow-up (player has none yet).
constexpr uint32_t SAVEMAP_KEYITEM_BITS = SAVEMAP_BASE + 0xB5C;   // 0xDC0894

// ---------------------------------------------------------------------------
// COUNTDOWN TIMER (v2.34, 2026-07-18) — the timed-escape clock.
//
// STATIC-PROVEN before the first timer was ever reachable in play (the
// scorpion-boss one-shot problem): the STTIM field opcode (0x38 — FFNx
// FieldOpcode enum counted to the MESSAGE=0x40 anchor) handler at 0x61FCD8
// reads its three byte args and stores h*3600 + m*60 + s — WHOLE SECONDS —
// directly to 0xDC08BC = savemap+0xB84, which FFNx's savemap struct
// already names `countdown_timer` (two independent sources agree). The
// dword right after (0xDC08C0) is FFNx's `millisecond_counter` (operand at
// timer_menu_sub+0xD06) — the sub-second accumulator that drives the
// once-per-second tick. Being savemap state, the timer persists in saves.
//
// The on-screen clock window (WSPCL special window, opcode 0x36) renders
// FROM this value, so freezing = rewriting the value each poll freezes the
// display too, and field-script time checks keep seeing a healthy number —
// no game-over can fire while frozen. Tick cadence/pause behavior (menus,
// battles) is captured by TimerThread's debug logging on the first real
// escape run (ff7_timer_static.py, log timer_static_20260718_183947).
constexpr uint32_t COUNTDOWN_TIMER_SECONDS = SAVEMAP_BASE + 0xB84; // 0xDC08BC u32
constexpr uint32_t COUNTDOWN_TIMER_MS      = SAVEMAP_BASE + 0xB88; // 0xDC08C0 u32

// ---------------------------------------------------------------------------
// BATTLE VICTORY screens (v2.35, 2026-07-19) — "Gained EXP and AP." /
// "Gained gil." + drops. All static (ff7_battle_results_static.py +
// ff7_results_block_refs.py, logs 20260719):
//
//   BATTLE_END_MODE 0xDC1300 (u16) = FFNx's menu_battle_end_mode (operand
//   at menu_battle_end_sub_6C9543+0x2C). v2.35's static-only phase read
//   below (FFNx's achievement-hook framing) was PLAY-CORRECTED v2.35.2
//   (2026-07-19, player report: announcements trailed the button-driven
//   flow) -- it advances on the player's OK PRESSES, not screen
//   appearances: mode 0 = EXP/AP screen SHOWING (waiting for OK), mode 1
//   = the roll-up itself (chirps/levels applying), mode 2 = gil/items
//   screen SHOWING, mode 3 = after ITS OK (gil applied). proxy.cpp's
//   VictoryThread uses this corrected map, not the raw disasm one below.
//   FFNx's own achievement hook brands the values: 0 = battle won/init,
//   1 = EXP/AP screen (level achievements fire), 3 = gil/items screen
//   (gil achievement fires). 2 = observed in the OK-press handler as the
//   state whose exit applies gil (see below); exact on-screen meaning
//   logged at runtime.
//   ⚠ FULL LIFECYCLE (v2.30.75, ff7_menu_handoff_monitor.py 2026-08-03,
//   two battles observed live): results init writes 0 ~60ms BEFORE
//   MENU_OPEN rises, then 1 -> 2 -> 3 on the player's OKs, a transient
//   4 (~30ms, teardown begins), and the byte RESTS AT 5 until the next
//   battle's results init. It is 0 between battles ONLY before the
//   session's first battle (BSS default). ⚠ TRAP: "battle_end != 0" is
//   therefore NOT a victory-window test -- v2.35.1 used it as the
//   victory stand-down in the materia/equip/limit/magic menu threads,
//   which DEAD-GATED those four screens (silent) for the rest of the
//   session after the first battle. The victory window test is
//   MENU_OPEN==1 && GAME_MODE==GAME_MODE_BATTLE; this byte is only
//   meaningful INSIDE that window.
//
//   Results pools (battle module 0x431541.. accumulates per enemy slot
//   from actor_vars, stride 0x68): 0x99E2C0 u32 gained EXP, 0x99E2C4 u32
//   gained AP, 0x99E2C8 u32 gained gil. ⚠ CONSUMED ON APPLY: the menu
//   does SAVEMAP_GIL += pool; pool = 0 as mode goes 3 (0x6C6B8F), and
//   EXP/AP drain similarly during the mode-1 count-up — CAPTURE ALL
//   THREE AT RESULTS ENTRY, never read them at screen time.
//
//   Drops: count u32 0x9AE12C; entries at 0x99E2F0, STRIDE 6: u16 item
//   id at +0 (0-319 namespace, same as inventory), +4 word copied during
//   list compaction (qty/taken flag — logged, not spoken, until live-
//   confirmed). Battle fill loop 0x4315E9 (imul 6) is the stride proof.
//
//   Level-ups: not announced from these pools — the savemap level bytes
//   (records +0x01) are watched during the results window instead; the
//   game writes them when EXP applies, which catches multi-level-ups
//   and needs no new addresses.
constexpr uint32_t BATTLE_END_MODE     = 0x00DC1300; // u16 screen phase
constexpr uint32_t BATTLE_GAINED_EXP   = 0x0099E2C0; // u32, capture at entry
constexpr uint32_t BATTLE_GAINED_AP    = 0x0099E2C4; // u32, capture at entry
constexpr uint32_t BATTLE_GAINED_GIL   = 0x0099E2C8; // u32, capture at entry
constexpr uint32_t BATTLE_DROPS_COUNT  = 0x009AE12C; // u32 entries
constexpr uint32_t BATTLE_DROPS_ARRAY  = 0x0099E2F0; // stride 6, u16 id @+0
constexpr uint32_t BATTLE_DROPS_STRIDE = 6;
constexpr uint32_t BATTLE_DROPS_MAX    = 32;         // sanity cap

// ---------------------------------------------------------------------------
// FRIENDLY LOCATION NAME — the MPNAM buffer (v2.24, found + confirmed
// 2026-07-16 in one session):
//
//   STATIC (ff7_mpnam_static.py): MPNAM = field opcode 0x43 (FFNx enum:
//   MESSAGE,MPARA,MPRA2,MPNAM consecutive; MESSAGE=0x40 is the mod's
//   oldest live-proven table entry). Handler 0x618E33 reads the one-byte
//   dialog-text id and calls the storage callee 0x633691, which walks the
//   field text entry via the text-block pointer 0xCC08E8 (u16 offset at
//   ptr+2+id*2), DECODES tokens (0xE2-family expansions; character-name
//   tokens 0xEA+ resolved through 0x6CB9B8), and writes the result to the
//   static buffer below, at most 0x17 bytes, 0xFF-terminated.
//
//   LIVE (ff7_mpnam_verify.py, same day): buffer read "Sector 1 Station"
//   on field 117, "Platform" on field 116, updating exactly on the
//   player's screen changes. ⚠ Bytes BEYOND the 0xFF terminator keep the
//   previous name's tail ("Platform\xFFSTATION…") — always stop at 0xFF.
//
//   The buffer is savemap+0xF0C (0xDC0C44 − 0xDBFD38), which is WHY saved
//   games remember the location caption. A field without an MPNAM keeps
//   the previous field's name — the same persistence the sighted menu
//   caption has, so speaking it stale is information parity, not a bug.
// ---------------------------------------------------------------------------
constexpr uint32_t LOCATION_NAME_BUFFER = 0x00DC0C44;  // savemap + 0xF0C
constexpr uint32_t LOCATION_NAME_MAX    = 0x17;        // handler's write cap

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
// BATTLE_ACTOR_DATA struct at 0x00DC38E0 (v2.7, 2026-07-11).
//   This is FFNx ff7.h's `struct battle_actor_data` — the "kernel2 request
//   struct" of the earlier notes is actually its middle fields:
//     +0x08  DWORD  formation_entry (0xDC38E8) — pending flag: 1 = flash
//            message queued, cleared by the consumer within a frame or two
//            (a 50ms poll usually reads 0; do NOT gate on catching the 1)
//     +0x0C  DWORD  command_index   (0xDC38EC) — commandID of the action the
//            CURRENT FLASH MESSAGE describes (2=Magic, 4=Item, 0x14=Limit,
//            0x20=enemy attack, ...)
//     +0x10  DWORD  action_index    (0xDC38F0) — ability index within that
//            command's namespace (magic id, item id, formation attack slot)
//   Written at flash-message display time by FFNx's replacement of
//   display_battle_action_text_sub_6D71FA (FFNx battle.cpp) — or by the
//   original sub_6D71FA without FFNx. Same addresses either way.
//   LIVE-VERIFIED 2026-07-11: magic cast wrote (2, 30) = 'Ice'; Potion wrote
//   (4, 0) = 'Potion'; enemy attacks wrote (0x20, 0/3) = 'Machine Gun' /
//   'Tentacle'. The struct LAGS the actor-turn start by ~1-2s (it syncs when
//   the flash text appears) and is NOT rewritten when the same flash content
//   repeats — announce logic must tolerate both (see BattleActionThread).
//
// ACTION NAME RESOLUTION (v2.7) — how (command_index, action_index) becomes
// text, replicated from dispatcher sub_6D1CC0 + get_kernel_text (=sub_41963C,
// confirmed via FFNx chain: relative CALL at +0xF7 -> kernel2_get_text
// 0x419457) by static disassembly (kernel2_consumer_disasm 2026-07-11):
//
//   branch = byte[0x6D70A8 + command_index]   (static .text table, cmds 0-0x20)
//     branch 0/1: magic-names section, entry action_index      (cmd 0x02 Magic)
//     branch 2:   action_index<16 ? summon-attack-names section
//                 : magic-names section                        (cmd 0x03 Summon)
//     branch 3/5: action_index<128 ? item-names section
//                 : <256 ? weapon-names section [idx-128] : none (cmd 0x04 Item)
//     branch 4:   game-built buffer at 0xDC3640                (cmd 0x07)
//     branch 6:   magic-names section, entry action_index+72   (cmd 0x0D E.Skill)
//     branch 7:   magic-names section, entry action_index+128;
//                 action_index==0x7F means '????' (unnamed)    (cmd 0x14 Limit)
//     branch 8:   ENEMY_ATTACK_NAME_TABLE + idx*0x20           (cmd 0x20 enemy)
//     branch 9:   no flash text exists (Attack/Steal/...) — keep generic label
//   The +56/+72/+128 biases and the section->branch mapping come from the
//   exe's own static tables (0x7B74A0 bias, 0x7B74A8 file, 0x7B7488/8A/98
//   item-namespace remap), read 2026-07-11 from the exe image.
//
//   Kernel-text section STORAGE: sections live in ONE heap block (address
//   varies per run), each section = u16 entry-offset table followed by
//   0xFF-terminated FF7-encoded strings; entry N is at base + u16[base+N*2],
//   and u16[base+0] equals the table's byte size (offset of first string).
//   The static scratch copy at 0x9A13C8 (offset table 0x9A7FC8) that
//   get_kernel_text itself uses is EMPTY during battle (menu-module only),
//   and the documented result pointer 0xDC208C is never written under FFNx
//   (FFNx replaces the whole consumer path) — neither can be used.
//   The DLL locates each needed section by scanning its own process memory
//   for the section's known first entries (signature), then validating with
//   the u16[base]==distance rule. ⚠ NOT once-per-process (v2.22.1
//   correction, 2026-07-23 audit fixed this stale comment): the COMMAND
//   section proved to live in a TRANSIENT battle allocation, so proxy.cpp's
//   ValidatedSection() re-checks every cached section pointer's head
//   signature before EVERY use and rescans on mismatch. Signatures:
//     magic-names:  'Cure'|'Cure2'         (entries 0..55 spells,
//                                            56..71 summon names,
//                                            72..95 enemy skills,
//                                            128+   limit breaks)
//     item-names:   'Potion'|'Hi-Potion'   (entries 0..127)
//     weapon-names: 'Buster Sword'          (thrown weapons, idx 128..255)
//     armor-names:  'Bronze Bangle'         (idx 256..287; v2.31)
//     accessories:  'Power Wrist'           (idx 288..319; v2.31)
//     item-descs:   (v2.31, see proxy.cpp)
//   ENGLISH-ONLY: signatures assume the English kernel2; on other languages
//   the scan fails cleanly and v2.5 generic labels are used throughout.
// ---------------------------------------------------------------------------

constexpr uint32_t G_ACTIVE_ACTOR_ID          = 0x00BE1170;
constexpr uint32_t G_BATTLE_MODEL_STATE        = 0x00BE1178;
constexpr uint32_t G_SMALL_BATTLE_MODEL_STATE  = 0x00BF23B8;
// GET_KERNEL_TEXT (the real one) is sub_41963C — but calling it is useless in
// battle: it reads the menu-module scratch tables, which are empty then.
// v2.7 reads the underlying heap sections directly instead (see above).
constexpr uint32_t BATTLE_ACTOR_DATA           = 0x00DC38E0; // FFNx battle_actor_data
constexpr uint32_t BATTLE_ACTOR_PENDING        = 0x00DC38E8; // +0x08 formation_entry
constexpr uint32_t BATTLE_ACTOR_CMD_INDEX      = 0x00DC38EC; // +0x0C command_index
constexpr uint32_t BATTLE_ACTOR_ACTION_INDEX   = 0x00DC38F0; // +0x10 action_index

// Battle action-name dispatch table (static .text, byte per commandID 0-0x20).
// byte[DISPATCH_BYTE_TABLE + cmd] = branch index; see resolution notes above.
constexpr uint32_t BATTLE_DISPATCH_BYTE_TABLE  = 0x006D70A8;
constexpr uint32_t BATTLE_DISPATCH_MAX_CMD     = 0x20;   // table covers 0x00-0x20

// Enemy attack names for the CURRENT battle formation, loaded from scene.bin
// at battle start. Fixed-stride table: entry = base + action_index * 0x20,
// FF7-encoded, 0xFF-terminated/padded. Live-verified 2026-07-05/06/11
// ('Machine Gun'/'Tonfa'/'Bite'/'Tentacle').
constexpr uint32_t ENEMY_ATTACK_NAME_TABLE     = 0x009A9484;
constexpr uint32_t ENEMY_ATTACK_NAME_STRIDE    = 0x20;

// Struct layout constants for the battle model state arrays.
constexpr uint32_t BATTLE_MODEL_STATE_STRIDE  = 0x1AEC; // bytes per actor, large array
constexpr uint32_t BATTLE_SMALL_MODEL_STRIDE  = 0x74;   // bytes per actor, small array
constexpr uint32_t BATTLE_COMMAND_ID_OFFSET   = 0x23;   // commandID (uint8_t) in large elem
constexpr uint32_t BATTLE_ACTION_IDX_OFFSET   = 0x3E;   // actionIdx (uint16_t) in small elem

// ---------------------------------------------------------------------------
// SECTION 1c2: Battle COMMAND MENU (the in-battle Attack/Magic/Item cursor)
//
// Solved 2026-07-12 after three failed live-scanning sessions, by static
// FFNx-chain resolution + capstone disassembly of the battle menu's state
// handler table (investigate/ff7_battle_menu_static.py + the two disasm
// scripts), then LIVE-CONFIRMED the same day by
// investigate/ff7_battle_menu_cursor_live_verify.py across two battles
// (command names, magic list rows, target cursor, and the Limit-replaces-
// Attack swap all spoken correctly in real time).
//
// ARCHITECTURE (the PSX decomp's widget prediction, carried over intact):
//   The battle menu is a state machine. BATTLE_MENU_STATE selects the
//   active widget; a 64-entry function table (0x91E6B8, resolved from
//   battle_sub_6DB0EE+0x1B4 exactly as FFNx does) holds one update handler
//   per state. Handlers move cursors by calling a shared navigation helper
//   (0x6F4DB2) with a WIDGET STRUCT pointer — which is why no live scan
//   ever found an absolute-address cursor write.
//
// LIVE-CONFIRMED STATE VALUES (see the research doc §4 for the full table):
//   1      = command menu open (the Attack/Magic/Item window)
//   6      = magic list        (per-actor spell table)
//   24     = limit select      (opened by confirming the Limit command)
//   0      = no menu ATB wait, AND post-Confirm target selection
//   0xFFFF = menu closed / turn executing
//   Static-only (not yet crossed live): 5 = item list (its table is
//   party-global — inventory), 7 = summon list, 2/3 = Defend/Change-row
//   dispatch, 0x18/0x1A/0x1B = limit widgets, 26/27 = Cait/Tifa slots.
//
// WIDGET STRUCTS: 0x38 bytes each, one block of them per party slot at
//   BATTLE_WIDGET_BASE + slot*0x700:
//     +0x00 command widget   +0x38 state-5 list widget
//     +0x70 state-6 (magic)  +0xA8 state-7 list widget
//   Fields (from the nav helper 0x6F4DB2's disassembly):
//     +0x00 u32 horizontal cursor (LEFT 0x8000 / RIGHT 0x2000)
//     +0x04 u32 vertical cursor   (UP 0x1000 / DOWN 0x4000)
//     +0x08 u32 horizontal wrap count   +0x0C u32 visible rows
//     +0x14 u32 scroll offset (top row) +0x1C u32 total entries
//     +0x28/+0x2C u32 per-axis behavior +0x30 u32 scroll-busy flag
//
// COMMAND MENU SELECTION: the grid is COLUMN-MAJOR, 4 rows per column
//   (matching the on-screen layout: Attack/Magic/Summon/Item down the
//   first column, extra columns to the right with more materia commands):
//     entry index = row + col*4      (row = widget+4, col = widget+0)
//     col wraps mod u8[CHAR_BLOCK + slot*0x440 + 0x21] (column count)
//     row wraps mod 4 (an AND 3 in the handler)
//   Entries: 6 bytes each at CHAR_BLOCK + slot*0x440 + 0x4C:
//     u8[+0] = command id, u8[+1] = action type (drives the Confirm jump
//     table), u8[+2] = action id for direct-dispatch commands.
//     0xFF = empty cell (the game's own cursor-skip loop tests this).
//
// COMMAND IDS ARE 1-BASED for the basic commands — live-corrected after
//   run 1 spoke everything one command off: 1=Attack, 2=Magic, 3=Summon,
//   4=Item (0 = none). This is the SAME id space BattleActionThread's
//   flash struct uses (its live-verified values: 0x02 Magic, 0x04 Item),
//   so the v2.7 dispatch-table/name machinery applies directly. Limit is
//   NOT shifted: it keeps 0x14 and REPLACES Attack's row-0 entry when the
//   gauge fills (live: id 1 -> 20 in place, Confirm -> state 24). The
//   Defend/Change-row pseudo-commands (0x12/0x13) are written by the
//   handler's Left/Right-at-edge paths, never stored in the table.
//
// LIST WIDGETS — the three lists have DIFFERENT layouts (v2.36 CORRECTION,
//   from the Confirm-path disasm of BATTLE_MENU_FN_TABLE[5]/[6],
//   ff7_kernel2_text_disasm.py 2026-07-19; the v2.9 single-formula reading
//   below was right ONLY for the item list and for a magic list of <= 3
//   spells in one row — which is exactly what the v2.9 test had, hiding
//   the bug until the player carried a full spell list):
//     ITEM  (state 5, global table 0x9AC354): SINGLE COLUMN, entry
//       STRIDE 6, u16 id at +0, empty = 0xFFFF. index = w0+w4+scroll.
//       ⚠ id 0 = POTION is VALID — the old "skip id 0" silenced Potions.
//     MAGIC (state 6, CHAR_BLOCK+slot*0x440+0x108) and
//     SUMMON (state 7, +0x2C8): 3-COLUMN GRID, entry STRIDE 8, u8 id at +0,
//       empty = 0xFF, disabled flag = u8[+6] bit 0x02. index = horiz +
//       (vert+scroll)*3  [= w0 + (w4+scroll)*3]. (Summon shares the magic
//       widget family; grid/stride assumed identical, verify when the
//       player has summons.)
//   Widget cursor fields unchanged: +0 horiz, +4 vert, +0x14 scroll.
//
// CONFIRM FLOW (what the game writes when the player picks something):
//   command id  -> 0xDC3C70 (u8,  = FFNx issued_command_id;  live: 1/2/20)
//   action id   -> 0xDC3C78 (u16, = FFNx issued_action_id;   live: 30=Ice)
//   target type -> 0xDC3C90, target index -> 0xDC3C94 (u8 pair)
//   target pointer actor -> 0xDC3C98 (= FFNx targeting_actor_id_DC3C98)
//   TARGETING runs with BATTLE_MENU_STATE == 0 (prev state 0x91EF98 holds
//   the menu it came from) — NOT state 19 as the fn-table position
//   suggested. TARGET_INDEX tracks the moving selection (live: 4<->5
//   across enemies, 0 = party slot 0; actor slots: party 0-2, enemy 4-9).
// ---------------------------------------------------------------------------

// v2.36 list-layout constants (see the LIST WIDGETS note above).
constexpr uint32_t BLIST_ITEM_STRIDE   = 6;   // u16 id @+0, empty 0xFFFF
constexpr uint32_t BLIST_MAGIC_STRIDE  = 8;   // u8  id @+0, empty 0xFF
constexpr uint32_t BLIST_MAGIC_NCOLS   = 3;   // magic/summon are 3-col grids
constexpr uint32_t BLIST_MAGIC_DISABLE_OFF = 6; // u8 bit 0x02 = can't use

// ---------------------------------------------------------------------------
// BATTLE SCENE MESSAGES (v2.36) — enemy AI dialogue like the scorpion's
// "Attack while it's tail's up!" warning. These reach the screen through
// the battle text DISPLAY QUEUE, a channel no announcer touched before.
//
//   BATTLE_TEXT_QUEUE 0xBF1EB8 = battle_text_data[64] (FFNx ff7.h; base =
//   operand at add_text_to_display_queue+0x25). Entry STRIDE 6: s16
//   buffer_idx @+0 (-1 = slot empty), s16 field_2, u8 wait_frames,
//   u8 n_frames. A buffer_idx >= 0x100 is a SCENE (scene.bin AI) message
//   — the dialogue class; < 0x100 is kernel battle text whose source
//   (0x9A13C8 menu scratch) is empty in battle, so only >= 0x100 is read.
//
//   Text lookup replicates GET_KERNEL_TEXT section 8 (handler 0x4199AD →
//   0x41D2E5, disasm 2026-07-19): for idx >= 0x100,
//     text = SCENE_MSG_BASE + u16[SCENE_MSG_OFFSETS + (idx-0x100)*2]
//   then FF7-decode at that pointer (0xFF-terminated). The base + offset
//   table are the current formation's decompressed scene messages.
constexpr uint32_t BATTLE_TEXT_QUEUE      = 0x00BF1EB8; // 64 x 6, s16 @+0
constexpr uint32_t BATTLE_TEXT_QUEUE_LEN  = 64;
constexpr uint32_t BATTLE_TEXT_QUEUE_STRIDE = 6;
constexpr uint32_t SCENE_MSG_BASE         = 0x009AD1E0;
constexpr uint32_t SCENE_MSG_OFFSETS      = 0x009AD9E0;
constexpr int16_t  SCENE_MSG_MIN_IDX      = 0x100;      // >= this = scene dialogue

constexpr uint32_t BATTLE_MENU_STATE       = 0x0091EF9C; // u16 current widget
constexpr uint32_t BATTLE_MENU_PREV_STATE  = 0x0091EF98; // u16 previous widget
constexpr uint32_t BATTLE_ACTIVE_SLOT      = 0x00DC3C7C; // u8 party slot 0-2
constexpr uint32_t BATTLE_MENU_BUSY        = 0x00DC35AC; // u32 transition flag

// Live-confirmed BATTLE_MENU_STATE values the mod reacts to.
constexpr uint16_t BMENU_STATE_TARGETING   = 0;      // also plain ATB wait
constexpr uint16_t BMENU_STATE_COMMAND     = 1;
// v2.30.49: the Defend/Change pseudo-commands are dedicated WIDGET STATES
// (not command-table entries — the v2.9 note finally resolved): the
// command handler fn[1] 0x6D91FA tests LEFT (0x8000) / RIGHT (0x2000) at
// the grid's edge column and jumps straight to state 2 / 3 with
// issued_command_id (0xDC3C70) pre-loaded to 0x12 / 0x13
// (writes at 0x6D937C / 0x6D9429 — ff7_defend_toggle_static.py,
// 2026-08-01). OK there dispatches; Cancel returns to state 1.
constexpr uint16_t BMENU_STATE_CHANGE      = 2;      // "Change" (row swap)
constexpr uint16_t BMENU_STATE_DEFEND      = 3;      // "Defend"
constexpr uint16_t BMENU_STATE_ITEM_LIST   = 5;      // static-only so far
constexpr uint16_t BMENU_STATE_MAGIC_LIST  = 6;      // live-confirmed
constexpr uint16_t BMENU_STATE_SUMMON_LIST = 7;      // static-only so far
constexpr uint16_t BMENU_STATE_LIMIT       = 24;     // limit-select widget (v2.9 note)
constexpr uint16_t BMENU_STATE_CLOSED      = 0xFFFF;

// Per-slot widget block and the widget offsets within it.
constexpr uint32_t BATTLE_WIDGET_BASE        = 0x00DC20A0;
constexpr uint32_t BATTLE_WIDGET_SLOT_STRIDE = 0x700;
constexpr uint32_t BWIDGET_COMMAND     = 0x00;
constexpr uint32_t BWIDGET_ITEM_LIST   = 0x38;   // state-5 widget
constexpr uint32_t BWIDGET_MAGIC_LIST  = 0x70;   // state-6 widget
constexpr uint32_t BWIDGET_SUMMON_LIST = 0xA8;   // state-7 widget
constexpr uint32_t BWIDGET_OFF_HORIZ   = 0x00;
constexpr uint32_t BWIDGET_OFF_VERT    = 0x04;
constexpr uint32_t BWIDGET_OFF_SCROLL  = 0x14;

// Per-slot battle character data block (command table, list tables).
// v2.33: this block is NOT battle-only — the MENU populates it too, with
// the character's EFFECTIVE stats (materia/equipment modifiers applied).
// Live-proven 2026-07-18: pattern-scanning the whole BSS for the status
// screen's exact stat run (20,16,24,17,9,17) hit EXACTLY ONCE, at
// 0xDBA49A = this block + 2, while the savemap record held base 22/20
// (ff7_status_stats_hunt / ff7_char_block_dump logs; screenshot
// status_screen_1.jpg = ground truth). Layout of the stat head:
//   +0x02..+0x07 u8  effective str, vit, mag, spr, dex, luck
//   +0x08 u16 Attack, +0x0A Defense, +0x0C Magic atk, +0x0E Magic def
//   +0x10/+0x12 u16 HP/maxHP, +0x14/+0x16 u16 MP/maxMP
// The three % stats (Attack%/Defense%/Magic def%) are NOT in the block —
// the screen draws them from kernel equipment data (residual).
// STALENESS GUARD for menu use: the block's HP/maxHP must equal the
// savemap record's — mismatch means the block describes someone/somewhen
// else; fall back to savemap base stats rather than speak wrong numbers.
constexpr uint32_t BATTLE_CHAR_BLOCK        = 0x00DBA498;
constexpr uint32_t BATTLE_CHAR_SLOT_STRIDE  = 0x440;
constexpr uint32_t BCHAR_OFF_CMD_NCOLS      = 0x21;   // u8 command column count
constexpr uint32_t BCHAR_OFF_CMD_TABLE      = 0x4C;   // 6-byte entries
constexpr uint32_t BCHAR_OFF_MAGIC_LIST     = 0x108;  // 8-byte entries (v2.36
                                                      // stride correction; the
                                                      // magic MENU's draw loop
                                                      // re-confirms *8 —
                                                      // v2.30.48 disasm)
constexpr uint32_t BCHAR_OFF_SUMMON_LIST    = 0x2C8;  // 8-byte entries (v2.36)
constexpr uint32_t BCHAR_OFF_EFF_STATS      = 0x02;   // 6× u8 (see above)
constexpr uint32_t BCHAR_OFF_ATTACK         = 0x08;   // u16
constexpr uint32_t BCHAR_OFF_DEFENSE        = 0x0A;   // u16
constexpr uint32_t BCHAR_OFF_MAGIC_ATK      = 0x0C;   // u16
constexpr uint32_t BCHAR_OFF_MAGIC_DEF      = 0x0E;   // u16
constexpr uint32_t BCHAR_OFF_HP             = 0x10;   // u16 pair cur/max
constexpr uint32_t BCHAR_OFF_MP             = 0x14;   // u16 pair cur/max
constexpr uint32_t BATTLE_ITEM_LIST_TABLE   = 0x009AC354; // global, 6-byte entries

// Confirm-flow staging block (all = FFNx externals, resolved + live-checked).
constexpr uint32_t BATTLE_ISSUED_CMD        = 0x00DC3C70; // u8
constexpr uint32_t BATTLE_ISSUED_ACTION     = 0x00DC3C78; // u16
constexpr uint32_t BATTLE_TARGET_TYPE       = 0x00DC3C90; // u8
constexpr uint32_t BATTLE_TARGET_INDEX      = 0x00DC3C94; // u8 moving selection
constexpr uint32_t BATTLE_TARGETING_ACTOR   = 0x00DC3C98; // u8 pointer actor

// ---------------------------------------------------------------------------
// SECTION 1c3: Battle TARGET NAMES (real enemy names from scene.bin)
//
// Derived 2026-07-13 by static disassembly of get_kernel_text's (sub_41963C)
// battle-section switch (investigate/ff7_target_name_disasm.py; the 07-11
// consumer disasm had already exposed the first half). The 4-entry jump
// table at 0x419A38 maps sections 6-9; SECTION 7 (handler 0x4197D3) is the
// game's OWN target-name lookup — the exact code the targeting window
// displays from — so these tables are authoritative by construction, no
// live scan needed:
//
//   idx < 6 (enemy list index; actor slot = idx + 4):
//     record = movsx( u16[0x9A8794 + idx*0x10] )       ; formation slot table
//     name   = 0x9A8E9C + record*0xB8, first 0x20 bytes ; loaded enemy records
//     letter = u8[0x9A8B1F + (idx+4)*0x44]              ; duplicate suffix
//     if letter != 0xFF: append FF7-char( dword[0x9AB070] + letter )
//                        (0x9AB070 holds the encoded 'A' base -> "MP A"/"MP B")
//   idx >= 6: returns the empty-string default — party target names do NOT
//             come from this path (menu module handles them), so the mod
//             keeps its savemap-leader/"ally N" labels for party slots.
//
// WHY these strides are trustworthy: 0xB8 (184) is exactly the scene.bin
// enemy record size (name = bytes 0-0x1F, FF7-encoded), and a scene holds
// 3 records — so valid record indices are 0-2 (movsx allows -1 = empty
// formation slot). The name field can occupy all 0x20 bytes with NO 0xFF
// terminator; the game copies max 0x20 bytes then writes its own 0xFF
// (0x41999B) — callers must impose the same cap, never Decode() the record
// in place.
//
// The same branch also revealed (documented for future use, NOT read yet):
//   u32[0x9AB0E0 + slot*0x68] bit 0x40  -> game appends kernel string 0x71
//   u8 [0x9A8B39 + slot*0x44] bit 0x40  -> Sense-style readout: formats
//     u16[0x9A8B4C + slot*0x44] and u16[0x9AB10C + slot*0x68] (HP pair)
//     through kernel strings 0x7F/0x72.
// ---------------------------------------------------------------------------

// Per-enemy-slot formation table: u16 record index (signed; -1 = empty slot),
// stride 0x10, indexed by enemy list index 0-5 (= actor slot - 4).
constexpr uint32_t BATTLE_FORMATION_SLOTS       = 0x009A8794;
constexpr uint32_t BATTLE_FORMATION_SLOT_STRIDE = 0x10;

// Loaded scene.bin enemy records (3 per scene), stride 0xB8; the FF7-encoded
// display name is bytes 0-0x1F (0xFF-padded, possibly UNterminated at 0x20).
constexpr uint32_t BATTLE_ENEMY_RECORDS         = 0x009A8E9C;
constexpr uint32_t BATTLE_ENEMY_RECORD_STRIDE   = 0xB8;
constexpr uint32_t BATTLE_ENEMY_RECORD_COUNT    = 3;
constexpr uint32_t BATTLE_ENEMY_NAME_LEN        = 0x20;

// Per-ACTOR-SLOT duplicate-name letter index (0='A', 1='B', ...; 0xFF = the
// enemy type is unique in this formation, no suffix), stride 0x44.
constexpr uint32_t BATTLE_DUP_LETTER_TABLE      = 0x009A8B1F;
constexpr uint32_t BATTLE_DUP_LETTER_STRIDE     = 0x44;

// ---------------------------------------------------------------------------
// SECTION 1c4: Battle actor variables + Sense HP readout (v2.11, 2026-07-13)
//
// BATTLE_ACTOR_VARS is FFNx's battle_ai_context::actor_vars — the per-actor
// battle stat array (10 slots, party 0-2 / enemies 4-9, stride 0x68 = exact
// sizeof(battle_actor_vars) in FFNx ff7.h). Resolved STATICALLY, two ways
// that agree (investigate/ff7_sense_hp_static.py):
//   1. FFNx's own chain: battle_context = get_absolute_value(0x41CCB2, 0x5F)
//      = 0x9AB0A0; actor_vars = +0x3C (header: 10 bytes + 23 u16 masks +
//      u32 partyGil) = 0x9AB0DC. The operand lives inside "mov edi,0x9AB0A0 /
//      rep stosd" — sub_41CCB2 is the battle-state init memset, and its other
//      memsets clear exactly the v2.10 regions (0x9A8748 covers the formation
//      slots, 0x9A8B10 covers enemy records + attack names) — strong mutual
//      confirmation that all these tables are one battle-state family.
//   2. get_kernel_text section 7's own reads land on named fields with this
//      base: its status-append gate 0x9AB0E0 = stateFlags (+0x04), and the
//      HP word it formats after Sense, 0x9AB10C, = maxHP (+0x30). (Its other
//      operand, u16[0x9A8B4C + slot*0x44], is the display struct's cached
//      CURRENT HP — the window renders "cur/max".)
//
// The Sense gate: the game appends HP to a target-window name only when
// u8[0x9A8B39 + slot*0x44] has bit 0x40 set (same 0x44-stride per-actor
// display struct as the duplicate-letter byte). That flag is set by casting
// Sense — the readout therefore has exact information parity with the
// sighted target window. Party HP is always visible in battle, so the mod
// speaks party slots' HP unconditionally.
//
// The mod reads the FULL i32 currentHP/maxHP from actor_vars rather than
// the game's u16 display words, so >65535-HP bosses can't truncate.
// ---------------------------------------------------------------------------

constexpr uint32_t BATTLE_ACTOR_VARS            = 0x009AB0DC;
constexpr uint32_t BATTLE_ACTOR_VARS_STRIDE     = 0x68;
constexpr uint32_t BAVARS_OFF_STATUS_MASK       = 0x00;   // u32 (v2.30.30:
                                                 // FFNx battle_actor_vars
                                                 // .statusMask; kernel
                                                 // status bit order — the
                                                 // H-key readout's table)
constexpr uint32_t BAVARS_OFF_CURRENT_MP        = 0x28;   // u16
constexpr uint32_t BAVARS_OFF_MAX_MP            = 0x2A;   // u16
constexpr uint32_t BAVARS_OFF_CURRENT_HP        = 0x2C;   // i32
constexpr uint32_t BAVARS_OFF_MAX_HP            = 0x30;   // i32

// Per-actor-slot "show HP in the target window" flag byte (bit 0x40), set by
// Sense; shares the 0x44-stride display struct with BATTLE_DUP_LETTER_TABLE.
constexpr uint32_t BATTLE_SENSED_FLAG_TABLE     = 0x009A8B39;
constexpr uint8_t  BATTLE_SENSED_FLAG_BIT       = 0x40;

// ---------------------------------------------------------------------------
// SECTION 1d: Field navigation addresses (wall-bump tone feature)
//
// All resolved statically from the exe on disk by
// investigate/ff7_wall_nav_static.py (2026-07-09) using FFNx's own discovery
// chains (FFNx/src/ff7_data.h), then confirmed live by
// investigate/ff7_wall_nav_verify.py the same day:
//   Phase A (walking freely):   wall predicate fired  0.0% of samples
//   Phase B (pushing a wall):   wall predicate fired 98.4% of samples
//   Phase C (standing still):   wall predicate fired  0.0% of samples
//
// modules_global_object (0xCC0D88):
//   The field module's global state struct (FFNx ff7.h struct
//   ff7_modules_global_object; its own source comment confirms 0xCC0D88).
//   Static-chain provenance: get_absolute_value(field_init_event_60BACF, 0x20).
//   We only read one member:
//     +0x68  uint32_t current_key_input_status — the DIGESTED input bitmask
//            the field engine consumes each frame (keyboard and controller
//            already merged by the input layer). Bit layout confirmed live:
//              0x1000 = Up, 0x2000 = Right, 0x4000 = Down, 0x8000 = Left
//            (matches FFNx's ff7::world::input_key enum — the same digest
//            format is shared across game modules).
//
// field_event_data_ptr (0xCC0B60):
//   Global pointer to the array of per-model field_event_data structs
//   (0x88 bytes each; layout from FFNx ff7.h). model_pos — the model's
//   world position as 3 consecutive int32 (x, y, z) — is at +0x0C.
//   Static-chain provenance: execute_opcode_table[0xB1] (CANM1 handler)
//   → get_absolute_value(+0xC1); FFNx's own comment confirms 0xCC0B60.
//   Live observation: the pointer held 0xCC1670 (static BSS, not heap),
//   but we always re-read the pointer each poll anyway — the engine is the
//   source of truth, and other fields could relocate the array.
//
// field_player_model_id (0xCC162C):
//   uint16 index of the PLAYER's model within that array. The player is
//   NOT always model 0 — fields load models in file order. This is the one
//   address with no FFNx-comment cross-check; provenance is the chain
//   field_loop_sub_63C17F +0x5DD relative call → field_update_models_positions
//   → get_absolute_value(+0x45D), plus the live walk test above (position
//   at this index tracked the player's movement exactly).
//
// field_n_models (0xCFF73E):
//   uint16 count of models on the current field. Used only as a bounds
//   sanity check before indexing the event-data array.
// ---------------------------------------------------------------------------

constexpr uint32_t MODULES_GLOBAL_OBJECT   = 0x00CC0D88;
constexpr uint32_t FIELD_KEY_INPUT_STATUS  = 0x00CC0DF0; // modules_global_object + 0x68
constexpr uint32_t FIELD_EVENT_DATA_PTR    = 0x00CC0B60; // field_event_data**
constexpr uint32_t FIELD_PLAYER_MODEL_ID   = 0x00CC162C; // uint16 player model index
constexpr uint32_t FIELD_N_MODELS          = 0x00CFF73E; // uint16 model count

// ---------------------------------------------------------------------------
// Wall-bump false-positive gates (added after 2026-07-09 live testing showed
// false tones during battles, FMVs, and control-locked scripted scenes).
//
// GAME_MODE (modules_global_object + 0x01, uint8):
//   The active engine module. LIVE-CONFIRMED VALUES (ff7_wall_gate_snap.py,
//   2026-07-09, two separate monitor sessions):
//     0 = field play (walking, player control)
//     2 = battle (flipped 0->2 exactly when a live battle started)
//     9 = menu overlay open on a field
//   v2.30.75 (ff7_menu_handoff_monitor.py, 2026-08-03, full battle→
//   victory→menu play-through at 30ms): two SCREEN-IDENTITY facts that
//   killed the menu family's timing heuristics:
//     - The victory results screens NEVER leave battle mode: GAME_MODE
//       stays 2 for the whole sequence while MENU_OPEN=1 (and MENU_OPEN
//       was continuous across both results screens — no dips). So
//       MENU_OPEN==1 && GAME_MODE==2 positively identifies the results
//       window, and MENU_OPEN==1 && GAME_MODE==9 the real main-menu
//       family — the discriminator every menu thread now gates on.
//     - On a real menu open, GAME_MODE rises to 9 ~0.5-1.2s BEFORE
//       MENU_OPEN goes 1 (module init runs first); both drop to 0
//       together on close. The title and game-over prompts raise
//       MENU_OPEN with GAME_MODE=0 (mode 9 is field-menu only), so the
//       ==9 gate also excludes them by construction.
//   WARNING: FFNx's ff7_game_modes enum (FIELD=1, BATTLE=2, MENU=5, ...)
//   does NOT describe this byte — that enum belongs to a different variable
//   (the graphics/game-object mode). Gating on ==1 (the enum's FIELD) made
//   the tone never fire; only the live-observed values above can be trusted.
//   Values during the pre-battle swirl, FMVs, and world map are not yet
//   observed; the movie/UC/FIELD_ID gates cover those independently.
//   GAME OVER (live-observed 2026-07-27, party wipe in a train-graveyard
//   battle): the byte holds 26 only BRIEFLY (~60ms — one 50ms wall-thread
//   poll caught it) while the engine hands off from the dead battle to the
//   game-over sequence, then returns to 0 for the whole GAME OVER film-reel
//   screen (~40s in the log) with the FIELD module frozen and FIELD_ID
//   STALE at the dead field — byte-for-byte indistinguishable from field
//   play, which is exactly why the v2.30.1 wall-tone fix had to gate on
//   observed movement. The transient 26 is currently the ONLY positive
//   in-memory signal that a game over began; GameOverWatchThread (proxy.cpp)
//   polls at 30ms to catch it and latches "title context" until the game
//   reloads. Single-session evidence — if a play-test log ever shows a
//   missed game over (no "GAMEOVER" line after a wipe), the blip can be
//   shorter than 30ms in some paths and needs a second trigger (e.g. the
//   battle-side all-party-dead signal).
//   WHY NEEDED: when a random battle starts, the FIELD module freezes with
//   current_key_input_status stuck at whatever direction the player was
//   holding while walking, and the player position frozen — the wall
//   predicate stays permanently true for the whole battle. FIELD_ID does NOT
//   reliably zero during battle (live-tested 2026-07-09: tone continued all
//   battle until the victory screen's MENU_OPEN=1 stopped it).
//
// FIELD_UC_LOCK (modules_global_object + 0x32, uint8):
//   Player-control lock, written by field-script opcode UC. Nonzero =
//   scripted scene has frozen the player; direction input is ignored, so a
//   frozen position does not mean "wall".
//   PROVENANCE: the PSX decompilation (PSX_decomps/ff7-decomp) implements
//   opcode UC as `modules_global->unk32 = operand` with unk32 commented
//   "character lock" at struct offset +0x32 (include/game.h). The PSX struct
//   is a field-for-field match with the PC ff7_modules_global_object across
//   +0x28..+0x3B — num_models(+0x28), pc model id(+0x2A), and the exact
//   five-flag run scrlo/mpdsp/mvcam/bgmovie/btlon (+0x37..+0x3B) all align —
//   so +0x32 carries over. (FFNx leaves this byte unnamed as field_32.)
//
// FIELD_MOVIE_PLAYING (0xCC1638, uint16) + FIELD_BGMOVIE_FLAG (+0x3A, uint8):
//   FFNx's own is-a-movie-playing test (widescreen.cpp, renderer.cpp) is:
//     *word_CC1638 && !modules_global_object->BGMOVIE_flag
//   word_CC1638 is nonzero while a movie plays on a field; BGMOVIE_flag set
//   means the movie is only a scrolling BACKGROUND (player retains control —
//   e.g. moving-train fields), in which case wall tones must stay ENABLED.
//   Statically verified 2026-07-09: get_absolute_value(sub_40B27B, 0x25)
//   in the exe on disk = 0x00CC1638, matching FFNx's name for it.
// ---------------------------------------------------------------------------
constexpr uint32_t GAME_MODE            = 0x00CC0D89; // modules_global_object + 0x01
constexpr uint8_t  GAME_MODE_FIELD      = 0;          // live-observed field-play value
                                                      // (NOT FFNx's enum; see above)
constexpr uint8_t  GAME_MODE_BATTLE     = 2;          // live-observed; HELD through the
                                                      // victory screens (v2.30.75)
constexpr uint8_t  GAME_MODE_MAIN_MENU  = 9;          // the main-menu family's mode —
                                                      // twice confirmed: static jump-
                                                      // table decode (v2.30.28) + live
                                                      // handoff log (v2.30.75)
constexpr uint8_t  GAME_MODE_GAMEOVER   = 26;         // transient (~60ms) game-over
                                                      // handoff value, live-observed
                                                      // 2026-07-27 (see block above)
constexpr uint32_t FIELD_UC_LOCK        = 0x00CC0DBA; // modules_global_object + 0x32
constexpr uint32_t FIELD_BGMOVIE_FLAG   = 0x00CC0DC2; // modules_global_object + 0x3A
constexpr uint32_t FIELD_MOVIE_PLAYING  = 0x00CC1638; // word_CC1638 (FFNx name)

// ---------------------------------------------------------------------------
// FIELD JUMP INTERFACE (v2.30.64) — the engine's ONE transition-request
// mailbox, a cluster of modules_global_object fields. Static disasm
// 2026-08-02 (ff7_screen_construction_static.py + ff7_gateway_cross_disasm
// + ff7_gateway_hit_disasm.py; research doc §4 FIELD_JUMP_INTERFACE row):
//
//   EVERY way of entering a field writes these same globals —
//     - MAPJUMP opcode handler 0x6131C4 (script jumps; args field,x,y,
//       tri,dir; quirk: field 0x313 is remapped to 0x159 in-handler),
//     - the gateway crossing-hit path 0x636233 (walk-across exits; copies
//       the 24-byte gateway record's +0x12/+0x0C/+0x0E/+0x10/+0x14),
//     - the save-load entry 0x63CCBA (savemap continue block
//       0xDC08CE..0xDC08DA),
//     - the world-map exit 0x76713B/163/172,
//     - the new-game/init region 0x60B48C..
//
//   GAME_MODE (+0x01) is held at 1 while a field jump is pending, and the
//   PHASE word is the completion signal: the field ARRIVAL routine
//   (0x63BF60..0x63C17E, ends right before field_loop 0x63C17F) places the
//   player, applies the arrival direction to facing (+0x38), initializes
//   the walkmesh pointers and door triggers, and then writes PHASE = 2
//   (0x63C148/0x63C232) — which is exactly what MAPJUMP's second entry
//   polls for before advancing the script. So:
//
//     DEST_FIELD_ID changing + GAME_MODE==1  =  "transition started, to X"
//     PHASE == 2 (after an armed jump)       =  "new screen fully built"
//
//   No hook needed — the mod polls these like every other module global.
//   ⚠ These bytes are STALE after arrival (nothing clears them until the
//   next jump arms) — always pair reads with an edge/latch, never treat a
//   bare value as "a jump is happening" (same stale-leftover class as the
//   countdown timer, v2.30.8).
constexpr uint32_t FIELD_JUMP_DEST_FIELD  = 0x00CC0D8A; // s16, modules + 0x02
constexpr uint32_t FIELD_JUMP_DEST_X      = 0x00CC0D8C; // s16, modules + 0x04
constexpr uint32_t FIELD_JUMP_DEST_Y      = 0x00CC0D8E; // s16, modules + 0x06
constexpr uint32_t FIELD_JUMP_DEST_TRI    = 0x00CC0DAA; // s16, modules + 0x22
constexpr uint32_t FIELD_JUMP_DEST_DIR    = 0x00CC0DAC; // u8,  modules + 0x24
constexpr uint32_t FIELD_JUMP_PHASE       = 0x00CC0DAE; // u16, modules + 0x26
constexpr uint16_t FIELD_JUMP_PHASE_READY = 2;          // field constructed
constexpr uint8_t  GAME_MODE_FIELD_JUMP   = 1;          // jump pending

// MPJPO — "map jump port on/off" (v2.30.64, ff7_mpjpo_static.py
// 2026-08-02): the MPJPO opcode (0xD2, handler 0x61A4D4) writes its 1-byte
// script arg RAW to [modules_global_object]+0x36 — the byte the PSX decomp
// names "map jump disabled". Scripts set it during scenes so walking across
// a gateway line does nothing. Nonzero = gateways currently DEAD; the
// pathfinder should not promise a gateway exit while it is set. ⚠ The
// live VALUE convention (1=disabled per the PSX label) rides the v2.30.64
// ARRIVE/JUMP debug lines for one-log confirmation before any spoken
// feature depends on it.
constexpr uint32_t FIELD_MAPJUMP_DISABLED = 0x00CC0DBE; // u8, modules + 0x36

// field_event_data struct layout (FFNx ff7.h). Offsets below are computed
// from the struct's field order; the layout is anchored by movement_speed
// at +0x76, which v2.6 verified LIVE (displacement = movement_speed × 32
// per 50ms, exactly) — the neighbors inherit that confidence.
constexpr uint32_t FIELD_EVENT_DATA_STRIDE = 0x88; // sizeof(field_event_data)
constexpr uint32_t FIELD_EVENT_MODEL_POS   = 0x0C; // vector3<int32> model_pos
constexpr uint32_t FIELD_EVENT_ENTITY_ID   = 0x5D; // u8, owning script entity
constexpr uint32_t FIELD_EVENT_CHARACTER_ID = 0x6C; // s16 — ⚠ NOT a party-membership
                                                    // indicator: live 2026-07-13 an
                                                    // ordinary reactor NPC carried 4
                                                    // ("Red XIII"); naming from this
                                                    // field was removed (v2.15.2),
                                                    // kept only in the debug log
constexpr uint32_t FIELD_EVENT_TALK_RADIUS = 0x74; // s16, talk interaction radius
constexpr uint32_t FIELD_EVENT_TRIANGLE_ID = 0x78; // s16, walkmesh triangle the
                                                   // model stands on (<0 = off-mesh)

// COLLISION-RADIUS CANDIDATES (v2.30.22, diagnostics only -- NOT confirmed,
// do not consume in logic). The 2026-07-25 hideout log proved model bodies
// hard-block movement (player pinned at exactly 64.0 units from Tifa = a
// 32+32 radius pair) but the struct offset holding each model's collision
// radius is unmapped. The three words between character_id (+0x6C..+0x6D)
// and talk_radius (+0x74) are the natural suspects; the NAV person debug
// line dumps them per model so one play session's log picks the offset
// (expect ~32 in the winner for ordinary people).
// CONFIRMED 2026-07-25 (v2.30.24) by that very dump against TWO
// independent behavioral anchors from the same day's play:
//   - +0x72 varies per model in radius-like units: Tifa 30, Barret 48,
//     AVALANCHE trio 34, generic NPCs 30/34;
//   - body-block distances match player_r + npc_r with Cloud ~32:
//     frozen vs Tifa at 64.0 (32+30, one step above contact), vs Barret
//     at 81.0 (32+48 = 80) — one rule, two bodies, both fit;
//   - +0x6E reads constant 0 and +0x70 flaps 0/1 per frame (some flag):
//     both REJECTED as radius.
// DYNAMIC: scripts change it at runtime (the SLIDR opcode family) — the
// same log shows Tifa 30 in the bar but 20 during a hideout scene state,
// parked models 0, the pinball prop briefly 120. Consumers must read it
// LIVE per use, never cache per field; 0 = no collision right now
// (intangible — e.g. parked models), which is exactly when a body
// should NOT block routing or be named as a blocker.
// ⚠ radius > 0 does NOT prove the model is tangible: the SOLID flag
// below is the engine's actual gate and is toggled independently of the
// radius (the Sector 1 station's unconscious guards keep their radii
// while SOLID(1) makes them walk-through). Check BOTH.
constexpr uint32_t FIELD_EVENT_COLLISION_RADIUS = 0x72; // s16, walkmesh units

// ---------------------------------------------------------------------------
// +0x5F: SOLID-OFF flag (u8) — 0 = model blocks movement, nonzero = the
// model is INTANGIBLE (walk-through) regardless of its collision radius.
// (v2.30.80, 2026-08-04 — pathfinder falsely called script-intangible
// people "in the way", e.g. the station guards at the game start.)
//
// PROVENANCE (all static, disasm'd from the exe on disk,
// ff7_solid_static.py / ff7_solid_consumer_static.py /
// ff7_solid_modelhit_dump.py):
//   - the SOLID opcode (0xC7) handler at 0x61C9DD stores its 1-byte
//     script arg RAW to +0x5F (0x61CA30) — byte-identical code shape to
//     the TLKON handler (0x618A80 → +0x61), and the neighbor handlers
//     TALKR (0x618253 → +0x74) / SLIDR (0x61813D → +0x72) both matched
//     their known offsets in the same session, validating the decode.
//   - model INIT (0x60C327 block) writes 0 (solid is the default, like
//     talkable); the model-UNBIND path writes 1 at 0x60C928 alongside
//     talk-off=1 / visible=0 — polarity matches TLKON's convention.
//   - CONSUMER PROOF: the engine's own movement blocking test at
//     0x637724 ("would this candidate position overlap another model")
//     skips any model whose +0x5F is nonzero — read at 0x637788 as
//     `movsx edx, [ecx + 0xCC16CF]` with ecx = idx*0x88, i.e. the
//     static event array 0xCC1670 + 0x5F (the [ptr]+offset==static
//     cross-proof pattern). ⚠ engine code addresses event fields as
//     absolute statics like this — disp-based .text sweeps for small
//     struct offsets MISS these consumers (that's why the first sweep
//     found no reader).
//   Engine's FULL per-model skip list in 0x637724, for the record:
//     self, +0x5F != 0, |Δz| >= 0x80 (128 walkmesh units — its own
//     level gate), then hit iff dist < (r_mover + r_other)/2 tested
//     from feeler points on the mover's radius circle. It also SETS
//     +0x5E = 1 on the touched model when the mover is the player
//     (0x637859) — a flag NOTHING in the exe reads (whole-.text sweep,
//     v2.30.83): player-vs-NPC contact is consequence-free.
// SCALE (offline flevel scan, ff7_solid_flevel_scan.py): 2,876 entities
// across 559 fields toggle SOLID — script-intangible people are the
// COMMON case, not an edge case. md1stin's hei0/hei1/gu0/gu1/guadd
// (the reported guards) all run SOLID(1).
// ⚠ ROLE CORRECTED v2.30.83 (ff7_player_blocking_ground_truth.py, the
// tester-prompted ground-up re-derivation): 0x637724's verdict is
// DISCARDED for the user-controlled player — the movement step's
// decision branch (0x63732F) commits the move through model contacts
// whenever FIELD_UC_LOCK == 0. Solidity matters only to NPC steering
// and scripted (UC-locked) player movement. The mod therefore consumes
// NEITHER this flag nor the radius for blocking decisions any more;
// both stay mapped as engine documentation and for proximity/talk
// semantics (the talk-target selector at 0x63640x picks the nearest
// model within talk_radius + player_radius).
constexpr uint32_t FIELD_EVENT_SOLID_OFF = 0x5F; // u8, nonzero = intangible

// The engine's model-vs-model z gate from 0x637724: bodies more than
// this many walkmesh z-units from the mover never interact. No longer
// consumed (v2.30.83 — the body-blocking model was retired with it);
// kept as engine documentation.
constexpr int32_t FIELD_BODY_Z_GATE = 0x80;

// Talk-enabled byte (v2.26): the TLKON opcode (0x7E, handler 0x618A80 —
// static disasm 2026-07-16) writes its 1-byte arg RAW to +0x61 of the
// entity's model record: 0 = talkable (the memset default), 1 = talk
// disabled. LIVE-CONFIRMED same evening: Jessie at the nmkin_2 ladder
// tutorial read 1 while refusing to talk from 17 units inside her talk
// radius — the play report that started the hunt. ⚠ 0 does NOT guarantee
// dialog (the entity may simply have no talk script); only the DISABLED
// state is definitive, so the mod only ever announces that side.
constexpr uint32_t FIELD_EVENT_TALK_OFF = 0x61;    // u8, 1 = talk disabled

// +0x62: model VISIBILITY (u8) — 1 = visible, 0 = hidden (v2.30.45).
// PROVENANCE (both static, disasm'd from the exe on disk 2026-07-31):
//   - the VISI opcode (0xA4) handler at 0x618A01 writes its script
//     operand here: current entity from 0xCC0964, entity->model-index
//     table at 0xCBFB70 (0xFF = no model bound), imul 0x88, base from
//     [0xCC0B60] (= FIELD_EVENT_DATA_PTR — the [ptr]+offset==static
//     cross-proof pattern), store at +0x62 (0x618A54).
//   - the CHAR (0xA1) bind path stores 1 here at 0x6143D2 (same
//     0xCBFB70/imul-0x88 addressing; it also writes the entity id to
//     +0x5D at 0x6143F9, independently re-confirming
//     FIELD_EVENT_ENTITY_ID) — every bound model STARTS visible, so 0
//     is always a deliberate script hide, never an uninitialized state.
// WHY THE MOD READS IT: pickup scripts hide collected ground items with
// VISI 0 (game-wide offline proof: ff7_prop_interact_catalog.py — the
// reactor potion/materia talk scripts are LOOT+VISI), so this byte is
// the live "already taken" signal the Items category filters on.
// FFNx calls this struct member field_62 (unnamed there).
constexpr uint32_t FIELD_EVENT_VISIBLE = 0x62;

// ---------------------------------------------------------------------------
// LADDER / CLIMB state (v2.30.60, 2026-08-02 — tester report: "difficulty
// knowing when they are on or off a ladder and what direction to push").
// All from the LADER handler (opcode 0xC2 = 0x615EC6, ff7_ladder_static.py):
//
//   +0x63 MOVEMENT TYPE — the handler's four script cases (jump table
//     0x6163D0, selected by the opcode's byte arg) write **4** (cases 0/1)
//     or **5** (cases 2/3) here, and its own re-entry check tests
//     `>= 4 && <= 5` for "this model is already climbing" (0x615F33).
//     On arrival it writes 0 back (0x615F9E). A .text sweep found only
//     two other writers of this byte (0x60C321 / 0x60D494) and both write
//     0 — so **4 or 5 means ON A LADDER, unambiguously**, with no
//     "is it really a ladder" heuristic needed.
//   +0x6E  u16 orientation/animation variant the same cases pair with the
//     type (0 or 1). ⚠ this is the byte the v2.30.24 radius hunt saw as
//     "rc6E ≡ 0" — now explained: it is only written on a climb.
//   +0x70  u16 movement phase: 0 armed, 1 = still moving (handler returns
//     early), 2 = arrived (handler then clears +0x63).
//   +0x7C/+0x80/+0x84  the climb TARGET x/y/z — script args fetched via
//     0x60FD6C and shifted <<12 (0x616168/0x61619A), i.e. the same
//     fixed-point scale as model_pos, so target>>12 compares directly to
//     the player's walkmesh position. The push direction is the bearing
//     from the player to that target, rotated by control_direction like
//     every other spoken direction.
constexpr uint32_t FIELD_EVENT_MOVE_TYPE   = 0x63;  // 4/5 = climbing
constexpr uint8_t  MOVE_TYPE_LADDER_A      = 4;
constexpr uint8_t  MOVE_TYPE_LADDER_B      = 5;
constexpr uint32_t FIELD_EVENT_MOVE_PHASE  = 0x70;  // u16 0/1/2
constexpr uint32_t FIELD_EVENT_MOVE_TARGET = 0x7C;  // 3 x s32, <<12

// ---------------------------------------------------------------------------
// MODEL FACING (v2.30.64, static disasm 2026-08-02,
// ff7_screen_construction_static.py — the screen-construction investigation).
//
// +0x38 (FFNx: rotation_curr_value) is THE authoritative facing byte,
// proven from three independent directions in one session:
//   - the DIR opcode (0xB3, handler 0x618062) writes its direction arg
//     straight to +0x38 (0x6180A8), plus turn-step bookkeeping to
//     +0x3A/+0x3B;
//   - GETDIR (0xB7) reads +0x38 back into the script variable (0x6184F1);
//   - the field ARRIVAL routine applies the pending transition's arrival
//     direction (FIELD_JUMP_DEST_DIRECTION below) to the PLAYER's +0x38 at
//     0x63C094 (via absolute 0xCC16A8 = static event-data array 0xCC1670
//     + 0x38 — the [ptr]+offset==static cross-proof pattern again).
//
// UNITS: a 0..255 wheel, degrees = byte * 360/256 — the same encoding as
// the trigger header's control_direction (v2.14 calibration: byte 124 =
// 174.4°). The WORLD-vs-SCREEN composition (screen = world + control
// − 180, same as motion) was CONFIRMED 2026-08-02: ARRIVE match=1 on
// every untouched gateway arrival across three play runs, and the spoken
// sector was checked against the user's auto screen captures (the
// nrthmk bridge arrival spoke "left" with the party visibly crossing
// left — decisive). No offset, no mirror. The ARRIVE debug line keeps
// printing the raw byte for any future recalibration need.
constexpr uint32_t FIELD_EVENT_FACING = 0x38;  // u8, 0..255 wheel

// Entity id → model slot map (bonus find from the same disasm): u8 per
// entity, 0xFF = the entity has no model. The TLKON handler resolves its
// executing entity through this table. Not yet used by the mod.
constexpr uint32_t FIELD_ENTITY_MODEL_MAP = 0x00CBFB70;

// Digested-input direction bits (current_key_input_status). Confirmed live
// 2026-07-09: all four values observed individually during the Phase A walk.
constexpr uint32_t KEY_DIR_UP    = 0x1000;
constexpr uint32_t KEY_DIR_RIGHT = 0x2000;
constexpr uint32_t KEY_DIR_DOWN  = 0x4000;
constexpr uint32_t KEY_DIR_LEFT  = 0x8000;
constexpr uint32_t KEY_DIR_ANY   = KEY_DIR_UP | KEY_DIR_RIGHT | KEY_DIR_DOWN | KEY_DIR_LEFT;

// ---------------------------------------------------------------------------
// SECTION 1e: Field TRIGGERS header — exits/gateways (v2.14 exit scan)
//
// FIELD_TRIGGERS_HEADER_PTR is a global holding a field_trigger_header*
// (FFNx ff7.h) — the engine's parsed copy of field-file section 8: the
// field's own name, the per-field input rotation, and the 12 gateway (exit)
// definitions. Resolved STATICALLY (investigate/ff7_field_triggers_static.py,
// 2026-07-13) via FFNx's chain anchored at field_sub_6388EE (address embedded
// in the FFNx symbol name):
//   field_draw_everything          = grc(0x6388EE, 0x11) = 0x63A60B
//   field_pick_tiles_make_vertices = grc(^, 0xC9)        = 0x640F22
//   field_layer3_pick_tiles        = grc(^, 0x12)        = 0x640F95
//   FIELD_TRIGGERS_HEADER_PTR      = gav(^, 0x134)       = 0xCFF454
// Chain self-validated by THREE other FFNx name-embedded addresses read off
// the same function (0xCFFE3C do_draw_layer3, 0xCFF3D8 camera rotation
// matrix, 0x623C0F field_layer_sub) — all matched. 0xCFF454 sits in the
// known 0xCFF3xx-0xCFF5xx field-statics cluster (font tables 0xCFF3F8,
// FIELD_FILE_BUFFER 0xCFF594), as expected.
//
// Header layout (offsets computed from FFNx's packed struct):
//   +0x00 char field_name[9]     ASCII, the field's internal name ("MD1_1")
//   +0x09 u8   control_direction per-field INPUT ROTATION (0-255 = 0-360°):
//              the engine rotates d-pad input by this so "up" matches the
//              camera — the same value lets the mod announce directions in
//              d-pad terms without any camera-matrix math
//   +0x38 field_gateway gateways[12], 24 bytes each:
//              +0x00 s16[3] exit line vertex 1 (walkmesh coords)
//              +0x06 s16[3] exit line vertex 2
//              +0x0C s16[3] destination vertex (in the TARGET field)
//              +0x12 s16    destination field id (0x7FFF = unused slot)
//              +0x14 u8[4]  unknown
//   +0x158 field_trigger triggers[12] (bg toggles — not used by the mod)
//
// COORDINATE SCALE: field_event_data model_pos is walkmesh coords × 4096
// (FFNx background.cpp: "model_pos.x / 4096.f") — so player walkmesh pos =
// model_pos >> 12, directly comparable to gateway vertices. Walking covers
// ~160 walkmesh units/second (v2.6 measurement: 32768 highres units per
// 50ms at walk speed 1024 → ÷4096 ×20).
// ---------------------------------------------------------------------------

constexpr uint32_t FIELD_TRIGGERS_HEADER_PTR = 0x00CFF454;
constexpr uint32_t FTRIG_OFF_FIELD_NAME      = 0x00;  // char[9]
constexpr uint32_t FTRIG_OFF_CONTROL_DIR     = 0x09;  // u8
constexpr uint32_t FTRIG_OFF_GATEWAYS        = 0x38;  // field_gateway[12]
constexpr uint32_t FTRIG_GATEWAY_SIZE        = 24;
constexpr uint32_t FTRIG_GATEWAY_COUNT       = 12;
constexpr int16_t  FTRIG_FIELD_ID_UNUSED     = 0x7FFF;
constexpr float    WALKMESH_UNITS_PER_SEC    = 160.0f; // walking pace

// ---------------------------------------------------------------------------
// Field-file MODEL LOADER section (v2.16 — People names + save points).
//
// The raw field file behind FIELD_FILE_BUFFER has nine sections; the table
// of nine u32 offsets sits at buf+6, each offset pointing at a 4-byte size
// prefix followed by the section data (research doc §5). Section index 2 is
// the MODEL LOADER — format LIVE-DECODED 2026-07-13 from a full hex dump of
// md1stin (investigate/ff7_field_models_dump.py; header count matched
// FIELD_N_MODELS exactly and every entry walked cleanly):
//
//   header: u16 blank, u16 nModels, u16 scale
//   per model:
//     u16 len, char name[len]   descriptive! "md1stinmain_n_cloud.char",
//                               "md1stinshinra_hei.char", "...ballet.char"
//     u16 unknown               (0 on the first entry, 1 on later ones)
//     char hrc[8]               "AAAA.HRC"
//     char scale[4]             ASCII "512\0"
//     u16 nAnimations
//     byte light_data[30]
//     nAnimations × { u16 len, char name[len], u16 unknown }
//
// Model entry order = model LOAD order = field_event_data array order
// (v2.6: "fields load models in file order"), so entry i names model i.
// The .char names strip to speakable labels ("shinra hei", "ballet") and
// the save-point model is expected to carry a "save"-style name (to be
// confirmed the first time the player reaches one — heuristic documented
// at the call site in proxy.cpp).
// ---------------------------------------------------------------------------

constexpr uint32_t FIELD_SECTION_TABLE_OFF   = 6;   // nine u32 offsets at buf+6
constexpr uint32_t FIELD_MODEL_SECTION_INDEX = 2;   // model loader section
constexpr uint32_t FMODEL_LIGHT_BLOCK_SIZE   = 30;  // fixed light-data bytes

// ---------------------------------------------------------------------------
// SECTION 1g: LINE trigger zones (v2.17 — "Triggers" pathfinder category)
//
// Field scripts create invisible trigger LINES on the walkmesh (ladders,
// elevators, touch/cross zones) with three opcodes: LINE 0xD0 (declare),
// LINON 0xD1 (enable/disable), SLINE 0xD3 (move). The engine stores them in
// ONE static array that all three opcode handlers write — found STATICALLY
// (investigate/ff7_line_triggers_static.py, 2026-07-14) by resolving
// execute_opcode_table from the exe on disk via the mod's own Resolve()
// chain (grc(0x60BACF,0x80) → gav(^,0x10D) = table at 0x9055A0; validated by
// table[0x40] MESSAGE having FFNx's expected E8 CALL at +0x3B) and
// disassembling the three handlers:
//
//   LINE  handler 0x6111D8: writes vertices to 0xCC1F70 + n*0x18, sets
//         +0x0C = 1, +0x0D = entity id, increments count at 0xCC088C,
//         refuses when count >= 0x20
//   LINON handler 0x6115AD: writes its script arg byte to the SAME
//         +0x0C (the enable flag), clears +0x0E on disable
//   SLINE handler 0x6114D0: rewrites the SAME six vertex words
//
// Three independent handlers agreeing on base/stride/offsets = the same
// cross-validation standard as the FFNx-chain finds. LIVE-VERIFIED
// 2026-07-14 (ff7_line_triggers_verify.py): see research doc §4/§8.
//
// Array entry layout (stride 0x18):
//   +0x00 s16 x1  +0x02 s16 y1  +0x04 s16 z1   (walkmesh coords — the LINE
//   +0x06 s16 x2  +0x08 s16 y2  +0x0A s16 z2    opcode args are stored raw;
//                                               same units as model_pos>>12)
//   +0x0C u8 enabled   (1 = active; LINON writes its arg byte here)
//   +0x0D u8 entity id (which script entity owns this line)
//   +0x0E u8 state latch (engine's "player inside" tracking)
//   +0x0F..+0x17 unknown
//
// The count is NOT reset-checked here: field load re-runs the init scripts,
// which re-declare every line, and the LINE handler resets come from the
// field module's own state clear (count observed correct per-field live).
//
// ENTITY NAMES: field script section 0 (behind FIELD_SCRIPT_PTR) carries an
// 8-char ASCII dev name per entity at +0x20 + id*8 (header: u16 unknown,
// u8 nEntities, u8 nModels, u16 wStringOffset, u16 nAkaoOffsets, u16 scale,
// u8 blank[6], char creator[8], char name[8] = 0x20 bytes; community-
// documented layout, live-verified by the same verify script). nEntities
// sits at +2 (the mod's long-standing field-header knowledge).
// ---------------------------------------------------------------------------

constexpr uint32_t FIELD_LINE_COUNT       = 0x00CC088C;  // u16, 0..32
constexpr uint32_t FIELD_LINE_ARRAY       = 0x00CC1F70;  // 32 × 0x18 bytes
constexpr uint32_t FLINE_STRIDE           = 0x18;
constexpr uint32_t FLINE_MAX              = 32;
constexpr uint32_t FLINE_OFF_ENABLED      = 0x0C;        // u8
constexpr uint32_t FLINE_OFF_ENTITY       = 0x0D;        // u8
// Per-entity line-slot map, u8[entity_id] = index into FIELD_LINE_ARRAY.
// Written by the LINE handler together with the array entry; the mod uses
// it as a consistency check (map[entity] == slot) before trusting a
// line's entity id for NAMING — a mismatch means the entry is stale
// (mid field-transition) or superseded (entity re-declared its line), so
// the line speaks as "Trigger N" instead of a possibly-wrong dev name
// (v2.18.2, from the 2026-07-14 code review).
constexpr uint32_t FIELD_ENTITY_LINE_SLOT = 0x00CBF600;
constexpr uint32_t FSCRIPT_NENTITIES_OFF  = 2;           // u8 in section-0 header
constexpr uint32_t FSCRIPT_ENTITY_NAMES_OFF = 0x20;      // char[8] per entity

// ---------------------------------------------------------------------------
// SECTION 1h: WALKMESH — field-file section 5 (v2.22 turn-by-turn directions)
//
// The raw field file behind FIELD_FILE_BUFFER carries the walkmesh as
// section index 4 (0-based) of the nine-entry offset table at buf+6 — the
// same table the v2.16 model-loader reader has used in production since
// then. Section layout (offsets from the section start):
//
//   +0x00 u32 section_size                 (every section's 4-byte prefix)
//   +0x04 u32 nTriangles
//   +0x08 triangle pool: nTriangles × 24 bytes
//           3 vertices × { s16 x, s16 y, s16 z, s16 res }
//           — same coordinate space as model_pos>>12 / gateway vertices
//   +0x08 + 24×n: ACCESS pool: nTriangles × 3 × u16
//           access[t][e] = triangle adjacent to t across edge e
//           (0xFFFF = no neighbor: that edge is a wall)
//
// SOURCES AND CONFIDENCE:
//   - Count/triangle-pool offsets are PRODUCTION-CONFIRMED by FFNx, which
//     renders the walkmesh from these exact reads (lighting.cpp
//     ff7_create_walkmesh: offset table entry at level_data+0x16 == buf+6+
//     4×4, count at +4, triangles at +8 stride 24; field.cpp reads triangle
//     centroids the same way).
//   - The ACCESS pool (location, 3×u16 stride, 0xFFFF sentinel) is from the
//     community field-file spec (Qhimm wiki) and is NOT read by FFNx — but
//     it was CONFIRMED GAME-WIDE OFFLINE 2026-07-16
//     (investigate/ff7_walkmesh_route_dryrun.py): all 720 fields in
//     flevel.lgp parsed, 184,358 directed links, 100% of ids in range,
//     100% geometrically adjacent (each named neighbor shares ≥2 vertex
//     coordinates), 100.00% reciprocal (2 one-way links total). Since
//     FIELD_FILE_BUFFER holds the raw decompressed file, the on-disk bytes
//     ARE the in-memory bytes. The mod still SELF-GUARDS at runtime (every
//     entry 0xFFFF or < nTriangles, ≥90% of links reciprocal, else
//     straight-line fallback) as cheap corruption/mid-transition armor.
//     Which VERTEX PAIR edge e connects is deliberately NOT assumed:
//     portals between path triangles are recovered geometrically
//     (shared-vertex match), so an edge-order convention error cannot
//     corrupt directions.
//
// The player's current triangle is FIELD_EVENT_TRIANGLE_ID (+0x78, long
// confirmed); NPC/item targets carry theirs in the same field.
// ---------------------------------------------------------------------------

constexpr uint32_t FIELD_WALKMESH_SECTION_INDEX = 4;  // 5th offset at buf+6
constexpr uint32_t FWMESH_OFF_NTRIS   = 4;    // u32, after the size prefix
constexpr uint32_t FWMESH_OFF_TRIS    = 8;    // triangle pool start
constexpr uint32_t FWMESH_TRI_SIZE    = 24;   // 3 × (s16 x,y,z,res)
constexpr uint32_t FWMESH_ACCESS_SIZE = 6;    // 3 × u16 per triangle
constexpr uint16_t FWMESH_NO_NEIGHBOR = 0xFFFF;
// Largest observed field is a few hundred triangles; 4096 is a generous
// corruption guard, not a real limit.
constexpr uint32_t FWMESH_MAX_TRIS    = 4096;

// ---------------------------------------------------------------------------
// TRIANGLE LOCK BITFIELD (v2.30.21, static disasm 2026-07-23 -- logs
// idlck_static_20260723_201129 + idlck_bitmath_20260723_202147):
//
// The runtime overlay the game layers on top of the static access pool --
// how field scripts make counters/doorways impassable (the IDLCK opcode).
// One bit per walkmesh triangle id: byte [0xCC0E3A + (tri >> 3)], bit
// (tri & 7). Bit SET = LOCKED (impassable).
//
// WRITE side: the IDLCK handler (execute_opcode_table[0x6D] = 0x61E29F;
// args u16 triangle_id + u8 flag) ORs the bit in when flag != 0, ANDs it
// out when 0 -- via [field_global_object_ptr 0xCBF9D8] + 0xB2.
// READ side: the movement/edge-crossing code (0x6369E8 / 0x636AAF /
// 0x636B76 -- one branch per triangle edge) reads the neighbor id from the
// game's own parsed access pool (pointer at 0xCFF748, stride 3xu16 --
// matching the raw-section format the mod parses), does the identical
// >>3 / &7 bit math against STATIC 0xCC0E3A, and REFUSES the crossing when
// the bit is set ("test esi,esi / jne skip"). 0xCC0E3A == 0xCC0D88
// (MODULES_GLOBAL_OBJECT) + 0xB2, proving field_global_object_ptr points
// at the static modules block -- both sides describe one bitfield, and the
// polarity (1 = blocked) is the game's own.
//
// WHY THE MOD NEEDS IT: the pathfinder's A* read only the static access
// pool, so routes crossed locked triangles and walked the player into
// invisible walls (2026-07-23: route to Tifa led INTO the bar counter --
// her tri 7 is mesh-connected but script-locked). LoadWalkmesh() now cuts
// every edge INTO a locked triangle, exactly the test the game itself
// performs.
// ---------------------------------------------------------------------------
constexpr uint32_t TRIANGLE_LOCK_BITS = 0x00CC0E3A;

// True when walkmesh triangle `tri` is script-locked (impassable). Same
// bit test as the game's own movement code at 0x6369E8.
//
// CAPACITY (ff7_walkmesh_max_tris.py, 2026-07-23): the game-wide maximum
// walkmesh is 496 triangles (bugin1c) -> the bitfield never extends past
// struct offset 0xB2+0x3E = 0xF0, inside the modules_global_object's
// ~0x138-byte span. Callers only pass tri < the current field's ntris, so
// reads can never leave the struct in practice; the FWMESH_MAX_TRIS bound
// below is a pure corruption guard, not a real reachable range.
inline bool is_triangle_locked(int tri)
{
    if (tri < 0 || tri >= static_cast<int>(FWMESH_MAX_TRIS)) return false;
    const uint8_t b = *reinterpret_cast<const volatile uint8_t*>(
        TRIANGLE_LOCK_BITS + (tri >> 3));
    return ((b >> (tri & 7)) & 1) != 0;
}

// ---------------------------------------------------------------------------
// Chest open/closed state (v2.18.1) — field_event_data animation fields.
//
// FFNx ff7.h names the fields (movement_speed +0x76 anchors the offsets):
//   +0x64 s8  animation_id, +0x66 s16 animation_speed,
//   +0x68 s16 currentFrame, +0x6A s16 lastFrame
//
// A treasure chest "opens" by playing its single lid animation to the
// final frame and HOLDING it: lastFrame goes 0 -> 29 (and currentFrame
// 0 -> 29<<4 = 0x1D0). LIVE-CONFIRMED 2026-07-14 on nmkin_1's metal chest
// ("fieldbg trb mety", model slot 8) across the full state matrix
// (ff7_chest_state_watch.py + ff7_chest_reentry_check.py):
//   closed:          currentFrame=0,    lastFrame=0
//   just opened:     currentFrame ramps, lastFrame=0x1D
//   after leave+return SAME session: currentFrame=0x1D0, lastFrame=0x1D
//     -> the field init script RE-POSES looted chests open from the
//        savemap event flags, so the signal also detects chests opened
//        in earlier sessions. THE SIGNAL (tightened v2.18.2): opened =
//        lastFrame != 0 AND currentFrame == lastFrame << 4 (animation
//        HELD at its final frame — true in both confirmed open states;
//        the conjunct keeps a non-lid animation that returns to rest
//        from reading as opened).
// The glow-effect bytes (apply_kawai +0x00, anim kawai_opcode +0x21) are
// NOT usable: they read differently in all three states (1/0x0D closed,
// 2/0xFF just-opened, 0/0x00 after reload).
// ⚠ Confirmed on the METAL chest variant; wood/glow variants share the
// same script mechanism and are expected identical — first play-test on
// another variant confirms (TODO.txt).
// ---------------------------------------------------------------------------

constexpr uint32_t FIELD_EVENT_LAST_FRAME    = 0x6A;  // s16 in field_event_data
// currentFrame, s16 at +0x68 — subframe units, frame << 4. The v2.18.2
// opened test requires currentFrame == lastFrame << 4 (animation HELD at
// its final frame — true in both confirmed open states) so a non-lid
// animation that returns to rest cannot read as "opened"; residual risk
// flips to a missed "opened", the safer direction.
constexpr uint32_t FIELD_EVENT_CURRENT_FRAME = 0x68;

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
