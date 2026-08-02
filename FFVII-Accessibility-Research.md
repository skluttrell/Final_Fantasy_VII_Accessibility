# FFVII Blind Accessibility â€” Technical Research & Implementation Log

This document covers the technical analysis, architecture decisions, reverse engineering findings,
trials and tribulations, and current implementation status for the FF7 2013 Steam blind accessibility mod.

---

## 1. The Problem

A blind player needs audio feedback for every interactive element:

| Context | What They Need |
|---------|---------------|
| Field dialog | Text of dialog windows, speaker identification |
| Choice menus | All options read aloud; current selection as cursor moves |
| Field navigation | Where the player is, what's nearby to interact with |
| Battle | Whose turn, targets available, action results, enemy state |
| Main menus | Which item is highlighted, values, descriptions |
| World map | Current position, nearby location names |

---

## 2. Why FF7 2013 Steam is Hard

The accessible FF5/FF6 Pixel Remaster mods use **MelonLoader**, which only works for Unity-based games.
FF7 2013 Steam uses a proprietary C++ engine with a custom DirectX 8 wrapper (`AF3DN.P` / FFNx).
There is no managed runtime to hook into.

Three approaches were evaluated:

- **Braver engine reimplementation**: A full .NET reimplementation of the FF7 engine that replaces FF7.exe entirely. Has deep accessibility support already started, but does not run all game systems yet (battle effects, world map, several menus are incomplete), and requires users to abandon the 7th Heaven workflow.
- **External memory reader**: A separate process using `ReadProcessMemory`. Limited to what it can observe; cannot intercept events. Fragile against ASLR and address changes.
- **Standalone proxy DLL**: Our DLL loads inside FF7.exe as a Windows DLL proxy, hooks the field script opcode dispatch table, and calls Tolk for screen reader output.

**Decision: Standalone proxy DLL.** Zero workflow change for the user (drop DLL files in the game folder, launch as normal). Full mod compatibility. The hook points are identical to what FFNx's voice acting system uses.

---

## 3. Proxy DLL Architecture

### Why `version.dll`, not `winmm.dll`

The first attempt used `winmm.dll` as the proxy. **It crashed immediately.**

FFNx's `ff7_find_externals()` calls `GetModuleHandle("winmm.dll")` and then `GetProcAddress("timeBeginPeriod")`, then walks the returned function's machine code at specific byte offsets looking for call instructions to derive game addresses. When we were `winmm.dll`, it got our naked JMP stub (`FF 25 ...`) instead of real winmm code, found garbage bytes at the expected offset, and crashed with `0xC0000005`.

Switching to `version.dll` fixed this. FFNx does not use `version.dll` for code analysis. FF7.exe imports `version.dll` legitimately (for version resource lookups), so Windows loads our DLL from the game folder before the system copy. Our DLL gets in, loads the real system `version.dll` by full `System32` path, and provides 17 naked-JMP stubs for the real exports.

### Hook Installation Timing

The second crash: hooks installed too early.

The background thread slept 200ms and then installed hooks. But FFNx's `voice_init()` â€” which also patches the opcode table â€” was running *during* that 200ms window, after our hooks were already installed. FFNx read our hook address from the table and tried to walk *our* machine code looking for a CALL instruction, found our prologue bytes instead, and crashed.

Fix: `Resolve()` checks `execute_opcode_table[0x40]`. If the value is in the original FF7 code range (`0x401000â€“0x9FFFFF`) and FFNx is loaded (`GetModuleHandleA("AF3DN.P") != nullptr`), FFNx hasn't finished patching yet â€” return false and retry. Once FFNx's `voice_init()` has run, the entry is FFNx's handler in DLL address space (above `0x9FFFFF`). Only then do we install our hook on top. The background thread polls `Resolve()` every 50ms.

### Hook Chain

```
hook_message (us)  â†’  FFNx opcode_voice_message  â†’  FF7 original opcode_message
hook_ask    (us)  â†’  FFNx opcode_voice_ask       â†’  FF7 original opcode_ask
```

Both voice acting (FFNx) and TTS (us) fire on every dialog event. Neither blocks the other.

### No MinHook

The opcode dispatch table is a plain `uint32_t[256]` array of function pointers in FF7's data segment.
We overwrite two entries directly using `VirtualProtect` + DWORD write. No hooking library needed.

---

## 4. Address Discovery

All runtime addresses are derived from two anchor functions whose absolute addresses are embedded
in FFNx's naming convention:

```
FIELD_INIT_EVENT = 0x60BACF
  +0x80  relative CALL â†’ execute_opcode function address
  +0x10D absolute ref  â†’ execute_opcode_table (uint32_t[256] of opcode handlers)

OPCODE_MSG_UPDATE_LOOP = 0x630D50
  +0x12  absolute ref  â†’ opcode_message_loop_code (uint8_t[], 24-byte stride per window)
```

Additional chains resolved STATICALLY against the exe file on disk for v2.6
(`investigate/ff7_wall_nav_static.py`, 2026-07-09). Static file analysis avoids
FFNx's runtime trampolines entirely â€” the on-disk bytes are pure Square code and
the binary has no ASLR, so file-derived VAs are runtime VAs. Where FFNx's `ff7.h`
carries an address comment it doubles as a cross-check (all matched exactly):

```
FIELD_INIT_EVENT = 0x60BACF
  +0x20  absolute ref  â†’ modules_global_object            = 0xCC0D88  (ff7.h comment âœ“)
  +0x1C  absolute ref  â†’ field_global_object_ptr          = 0xCBF9D8

execute_opcode_table[0xB1]  â†’ opcode_canm1_canm2          = 0x614E3E
  +0xC1  absolute ref  â†’ field_event_data_ptr             = 0xCC0B60  (ff7.h comment âœ“)

FIELD_LOOP = 0x63C17F   (FFNx: field_loop_sub_63C17F)
  +0x5DD relative CALL â†’ field_update_models_positions    = 0x6342C6
    +0x45D absolute ref â†’ field_player_model_id           = 0xCC162C
    +0x25  absolute ref â†’ field_n_models                  = 0xCFF73E

SUB_40B27B = 0x40B27B
  +0x25  absolute ref  â†’ word_CC1638 (movie-playing word) = 0xCC1638  (FFNx name âœ“)
```

All other symbols are either hardcoded fixed addresses (confirmed from `externals_102_us.h` and `ff7.h`)
or read at runtime from opcode parameters. See Â§14 for a region-organized map of
every confirmed address â€” the clustering itself is a discovery tool.

### Confirmed Absolute Addresses (2013 Steam / 1.02 US)

| Symbol | Address | Source |
|--------|---------|--------|
| `current_dialog_string_pointer` (DIALOG_TEXT_PTRS) | `0xCBF578` | `ff7.h` |
| `ASKMENU_OPTION` | `0x00CC14D1` | âš  **DEMOTED v2.30.12 â€” NOT a cursor global, DO NOT read.** It is the ASK opcode's per-DIALOG script OUTPUT VARIABLE (the bank/address named in the opcode's own first params): the handler 0x618E83 reads it into a stack local (helper 0x60F750), the update loop 0x6310A1 moves/clamps THAT, and it's written back on exit (0x60FA7D). The 2026-07-20 live scan simply found the variable of the dialog it scanned â€” Aeris-field choices shared it (tracked fine), the soldier fight-or-flee dialog did not (frozen at 0, log-proven 2026-07-22). Replaced by ASK_CURSOR_PIXEL_Y below |
| `ASK_CURSOR_PIXEL_Y` | `0x00CFF5DE` | **The dialog-independent ASK cursor readout (v2.30.12)**: u16 at +window_idÂ·0x30, rewritten by the update loop EVERY frame the choice accepts input (disasm 0x631384â€“0x63139C, ff7_ask_lines_static log 20260720_171327): `lineÂ·16 + 6` â€” the highlight's pixel Y inside the window (16 px/line, 6 px top margin). Decode: `line = (yâˆ’6)>>4`, valid only when yâ‰¥6 and (yâˆ’6)%16==0 (else skip the frame). Part of the ASK per-window struct family, stride 0x30: byte 0xCFF5D2+nÂ·0x30 input-armed flag, u16 0xCFF5DC+nÂ·0x30 = 5 while choosing, u16 0xCFF5E4+nÂ·0x30 = 7 on confirm, u16 0xCFF5E6+nÂ·0x30 state-flag word (bit 0 gates the input branch) |
| `field_file_buffer` | `0xCFF594` | `externals_102_us.h` |
| `field_script_ptr` | `0xCBF5E8` | `externals_102_us.h` |
| `field_curr_script_position` | `0xCC0CF8` | `ff7_data.h` |
| `current_entity_id` | `0xCC0964` | `ff7_data.h` |
| `build_dialog_window` | `0x6E97E0` | `externals_102_us.h` |
| `menu_objects` | `0xDC0FC0` | `externals_102_us.h` |
| `savemap` | `0xDBFD38` | `externals_102_us.h` |
| `field_init_event_60BACF` | `0x60BACF` | FFNx naming convention |
| `field_opcode_message_update_loop_630D50` | `0x630D50` | FFNx naming convention |
| `field_opcode_ask_update_loop_6310A1` | `0x6310A1` | FFNx naming convention (v2 hook target) |
| `world_opcode_message_sub_75EE86` | `0x75EE86` | FFNx naming convention (v2) |
| `world_opcode_ask_sub_75EEBB` | `0x75EEBB` | FFNx naming convention (v2) |
| `display_battle_action_text_42782A` | `0x42782A` | FFNx naming convention (v2) |
| `TITLE_CURSOR` | `0x00DD6F24` | 0=New Game, 1=Continue. PROVENANCE UPGRADE v2.30.38 (static disasm): = ROW (+4) of a cursor WIDGET at 0xDD6F20 (the shop-mapped ctor 0x6F4D30, 2 rows Ã— 1 col, built in title init 0x720E64) â€” why no direct writer exists. Gate announces on TITLE_STATE==1, not FIELD_ID alone |
| `TITLE_STATE` | `0x00DD74E0` | dword, the title module's lifecycle (v2.30.38 static disasm; per-frame main 0x722393, draw 0x7212FB): **0**=fading in / module not yet run (BSS boot value through the logo movies â€” the splash-announce window), **1**=title menu INTERACTIVE (holds through the NEW GAME/Continue prompt AND the Continue save-grid; subscreen switch = 0xDD7704 0..7), **2**=choice accepted/fading out, **-1**=module exited (stale through gameplay â€” ==1 can't false-fire). Init guard 0xDD76F8 cleared at teardown (0x722441) â‡’ every title re-entry (boot/post-game-over/quit) re-cycles 0â†’1. âš  disasm-derived â€” first launch logs ("TITLE state=") are the live verification |
| `NAME_ENTRY_COL` | `0x00DD4538` | u8 (LOW byte of a 4-byte-spaced slot â€” read as u8, NOT u32: the three high bytes are unverified and a u32 read would fail the bounds check silently), grid column 0â€“9 on the naming screen. Adjacent X/Y pair with ROW below (v2.8, live-confirmed 2026-07-12) |
| `NAME_ENTRY_ROW` | `0x00DD453C` | u8 (same low-byte-only caveat as COL above), grid row 0â€“6 (Aâ€“J / Kâ€“T / Uâ€“Z,.+- / aâ€“j / kâ€“t / uâ€“z:;'" / 0â€“9) |
| `NAME_ENTRY_BUFFER` | `0x00DD45F0` | Name-in-progress, FF7-encoded, 0xFF-terminated, â‰¥9 chars capacity. âš  the first scan found 0xDD45F5 â€” that was just the first byte that CHANGED; the "Cloud" prefix masked F0â€“F4 until the Barret-screen handoff rewrote them |
| `NAME_ENTRY_CHAR_INDEX` | `0x00DD46F8` | Which character is being named: 0=Cloud, 1=Barret (flipped exactly at screen handoff). **This is the address the Echo mod hext patch mislabeled "cursor column"** â€” it never changes during grid navigation |
| `NAME_ENTRY_ACTIVE` | `0x00DD46FC` | 1 while a naming screen is open, 0 otherwise. Matched all three observed transitions (Cloud close, Barret open, final exit). Gate together with GAME_MODE==6 |
| `NAME_ENTRY_PANE_FLAG` | `0x00921ED4` | 0=cursor in letter grid, 1=cursor on side panel (v2.8.2, live-verified across 6 crossings). Lives in 0x92xxxx .data, NOT the DD block. Entering the panel can change the ROW byte (observed 1â†’4) â€” gate grid announcements on this flag |
| `NAME_ENTRY_PANEL_INDEX` | `0x00DD4574` | Side-panel button, valid only while PANE_FLAG==1: 0=Space 1=Delete 2=Select 3=Default (0/1 proven by name-buffer effects). Wraps 0â†”3; retains last value after leaving the panel |
| `NAME_ENTRY_CARET` | `0x00DD46F0` | Caret position, clamped 0â€“8. Name hard cap = 9 chars; at cap Confirm replaces the last char |
| `MENU_CURSOR` | `0x00DC1154` | Main menu row 0â€“10 (Itemâ€¦Quit); constant during field play |
| `MENU_OPEN` | `0x00DC12DC` | 1 when main menu, post-battle results, OR the naming screen is active; gate with FIELD_ID!=0 AND GAME_MODE!=6 (naming screen set it with FIELD_ID non-zero â†’ false "Item" announce, fixed v2.8.3) |
| `CONFIG_ROW` | `0x00DC10F0` | Config sub-menu row 0â€“9 (Window colorâ€¦Magic order); proxy gate: MENU_CURSOR==7 |
| `CONFIG_SPEED_BATTLE` | `0x00DC0E10` | Row 5 Battle speed â€” raw byte, 0=Fast â†’ 255=Slow |
| `CONFIG_SPEED_MSG` | `0x00DC0E11` | Row 6 Battle message speed â€” raw byte, 0=Fast â†’ 255=Slow |
| `CONFIG_PACKED_CURSOR_ATB` | `0x00DC0E12` | Packed byte: bit 4=Cursor (0=Initial/1=Memory); bits 7:6=ATB (0=Active/1=Recommended/2=Wait) |
| `CONFIG_PACKED_CAMERA_MAGIC` | `0x00DC0E13` | Packed byte: bit 0=Camera (0=Auto/1=Fixed); bits 4:2=Magic order index 0â€“5 (No.1â€“No.6) |
| `CONFIG_SPEED_FIELD_MSG` | `0x00DC0E24` | Row 7 Field message speed â€” raw byte, 0=Fast â†’ 255=Slow |
| `SOUND_CURSOR` | `0x00DC108C` | 0=Music slider highlighted, 1=FX slider highlighted; inside Sound sub-menu only |
| `QUIT_CURSOR` | `0x00DC0FA0` | 0=Yes, 1=No inside Quit confirmation dialog |
| `QUIT_OPEN` | `0x00DC0FB1` | **NOT USED** â€” sole clean 0â†’1 candidate from the same ff7_quit_dialog_scan.py scan (2026-07-02) that found QUIT_CURSOR, 0x20 bytes before MENU_OBJECTS in the same DC0F menu-state struct, but in practice stays at 1 after cancellation, which would loop MenuCursorThread in the quit handler indefinitely â€” left undocumented-in-code for reference only, not read by any thread |
| `SAVEMENU_GRID_CURSOR` | `0x00DC6AE0` | Save menu file-grid **COLUMN 0..4** (âš  v2.29.3: NOT a 0..9 index â€” the original "0..9 verified" speak-back only walked the top row). Row in the separate byte below; file index = (1âˆ’row)Ã—5+column. Single intersected candidate + live speak-back â€” ff7_save_menu_scan.py 2026-07-17. HOLDS its value while the slot list is open |
| `SAVEMENU_GRID_ROW` | `0x00DC6AE4` | Save menu file-grid row byte: 0 = top row (Save 1â€“5), 1 = bottom (Save 6â€“10). **LIVE-CONFIRMED** (field probe slot_scroll_probe_20260717_200802: 0â†’1 on Down to the bottom row, 1â†’0 on Up â€” v2.29.4 polarity exact) |
| `SAVEMENU_SLOT_CURSOR` | `0x00DC6B1C` | Save menu slot-list **visible ROW 0..2** (âš  NOT the absolute slot â€” the list shows 3 and scrolls; the "only 3 slots" player report, v2.29.2). 0x3C after the grid cursor. Absolute slot = row + SAVEMENU_SLOT_SCROLL |
| `SAVEMENU_SLOT_SCROLL` | `0x00DC6B2C` | u8 0..12 slot-list scroll offset. **LIVE-CONFIRMED** (field probe 20260717_200802; same tween/direction noise pattern as the title instance at +0x10/+0x1C past it). Bonus metadata found in the same run: `0xDC6B34` reads 15 = slot count, `0xDC6B24` reads 3 = visible rows; `0xDD7700` went nonzero in SAVE mode live, confirming the shared pane pointer end-to-end |
| `SAVEMENU_PHASE` | `0x00DC1210` | âš  **DISPROVED as a pane flag** (2026-07-17, v2.29.2): OSCILLATES in real use â€” the save menu alternated its two pane announcements endlessly (player report). Its clean 0/1 across three widely-spaced A/B/A snapshots was coincidence. Do not read. Pane signal for both menus = LOADMENU_LIST_PTR |
| `LOADMENU_GRID_CURSOR` | `0x00DD6D98` | Title-screen CONTINUE menu's OWN file-grid **COLUMN 0..4** (shared-module assumption live-DISPROVED â€” the SAVEMENU_* bytes freeze at the title; 0..9-index reading corrected v2.29.3). **LIVE-VERIFIED** by speak-back (0â†’4 and back) â€” ff7_continue_menu_scan.py 2026-07-17. Title module block. v2.29.1/3 |
| `LOADMENU_GRID_ROW` | `0x00DD6D9C` | Continue menu file-grid row byte at grid+4: **0 = top row, 1 = bottom** (v2.29.4 play-corrected â€” v2.29.3 shipped it inverted by misreading the probe's baseline of 1 as "top"; the player had started the probe already parked on the BOTTOM row, and their report of "Save 6" spoken on the top row settled the polarity). Column recounts 0..4 on both rows (probe log slot_scroll_probe_20260717_171930). File index = rowÃ—5+column |
| `LOADMENU_SLOT_CURSOR` | `0x00DD6DD4` | Continue menu slot-list **visible ROW 0..2** (same 3-row-window caveat as the save instance), grid+0x3C â€” the struct-spacing echo corroborating both instances. v2.29.1/2 |
| `LOADMENU_SLOT_SCROLL` | `0x00DD6DE4` | u8 0..12 slot-list scroll offset, **LIVE-CONFIRMED** (ff7_slot_scroll_probe.py log 20260717_123245: stepped 0â†’12 down the full list and 12â†’0 back while the row byte pinned at 2/0). slot_cursor+0x10. Neighbors are noise: +0x74 u32 scroll-animation tween (transient 0xFFFFFFxx), +0x80 direction flag (2=down 1=up 0=idle) â€” never read them. Absolute slot = row + scroll (v2.29.2) |
| `LOADMENU_LIST_PTR` | `0x00DD7700` | u32: 0 while the Continue file grid shows, HEAP POINTER to the selected file's loaded data while the slot list is open. Identical behavior in BOTH menus' phase passes (save scan 0â†’0x237E6008â†’0; continue scan 0â†’0x237D20A8â†’0). v2.29.1's load-mode pane signal â€” **nonzero-check only, never dereference** (transient allocation). Sidekick byte 0xDD7704 flips 0â†’1 with it (runner-up flag) |
| `SAVEMENU_WIDGET_STATE` | `0x00DCA028` | The save menu's widget state machine: observed 0 = file grid â†’ 1 = slot list (original scan's phase pass) and **7 = "Are you sure you want to save?" dialog open** (SINGLE A/B/A candidate, ff7_save_confirm_scan 2026-07-17, log 20260717_201751: 1â†’7 on open, reverted on Cancel). v2.29.5 acts only on value 7; other values unsampled |
| `SAVEMENU_CONFIRM_CURSOR` | `0x00DC6C6C` | Save-confirm dialog Yes/No cursor: **0 = Yes, 1 = No**, resets to Yes on open. Single intersected Down/Up candidate AND live speak-back verified in the same session. Slot-row 0xDC6B1C holds still while the dialog is up, so the dialog cleanly short-circuits slot announcements (v2.29.5) |
| `MENU_DISPATCH_INDEX` | `0x00DC12EC` | u32 sub-screen index the main-menu dispatcher (menu_sub_6CB56A, +0x2EC operand) uses to call menu_subs_call_table[16] @0x91AB98 in steady state. **ITEM screen = 1** (live: constant 1 through the whole item-menu scan session â€” overrides the static caption guess of table[3]). Known FFNx ids: [8]=config, [10]=save/load. v2.31's which-screen gate. âš  value on the PLAIN main menu not yet observed (ff7_menu_dispatch_disasm.py, v2.31) |
| `MENU_DISPATCH_TRANS` | `0x00DC12E8` | u32 twin index the dispatcher uses during fade-transition frames (mode values 2/4/5 from sub 0x6C9808). Same disasm; not consumed by the mod. Bonus finds in the same window: 0xDC1210 XOR-toggled every tick (the v2.29.2 oscillation explained), 0xDC1138 = menu frame counter |
| `ITEMMENU_MODE` | `0x00DD19C8` | Item menu's own state machine: **0 = top bar, 1 = item list (ENTRY state â€” the menu opens in the list, Cancel goes UP; player-corrected flow), 2 = use-on-whom target pane**. BOTH A/B/A toggles of the guided scan landed on this single address (item_menu_scan_20260718_114427). Other values (Arrange popup, Key Items pane) unmapped â€” v2.31 stays silent and debug-logs them |
| `ITEMMENU_TOPBAR_CURSOR` | `0x00DD1A18` | u8 top-bar cursor: 0=Use 1=Arrange 2=Key Items. Single intersected Right/Left candidate Ã—2 rounds (same scan) |
| `ITEMMENU_LIST_CURSOR` | `0x00DD1A54` | u8 item-list row; **speak-back verified live** (tracked 0..4 over a 3-item inventory â€” the cursor rides EMPTY rows, so v2.31 speaks "Empty"). âš  window-vs-absolute UNRESOLVED: 3 items cannot scroll the list (the v2.29.2 lesson); re-verify + hunt the nearby scroll word once inventory exceeds the visible rows |
| `ITEMMENU_TARGET_CURSOR` | `0x00DD1A8C` | u8 use-on-whom party cursor 0..2 top-to-bottom (party slot order â†’ PartySlotLabel + savemap HP/MP readout). Single intersected Down/Up candidate Ã—2 rounds (same scan) |
| `MENU_DISABLED_ROWS` | `0x00DC1130` | u16 bitmask, bit N = main-menu row N grayed/refuses activation (disasm 0x6CA4CD bit test â€” what grays Materia/PHS early game). v2.32 appends ", not available" from it |
| `MENU_FOCUS_MODE` | `0x00DC1324` | u8 main-menu input focus: **0 = menu bar, 1 = character-select pane (set WITH confirm chime â€” Magic/Equip/Status rows), 2 = Order pane (set at 0x6CA526 with NO sound call â€” the "no chime" the player noticed)**. Static-derived (v2.32 disasm); the missing Order entry signal both live probes couldn't see |
| `ORDERMENU_CURSOR` | `0x00DC11C4` | u8 Order-pane party cursor 0..2 (rides the empty slot). Single intersected candidate + speak-back verified (order_menu_scan_20260718_152825) |
| `ORDERMENU_LATCH` | `0x00DC1320` | u32, 1 = first member selected (flashing cursor). Scan A/B/A single real candidate AND disasm-confirmed exact write sites (0x6CA61B set / 0x6CA634 clear / 0x6CA363 init) |
| `ORDERMENU_FIRST_SLOT` | `0x00DC110C` | s8 slot latched at the first confirm (disasm 0x6CA616). Same-slot second confirm = row toggle; different = swap |
| `CHARSEL_CURSOR` / `CHARSEL_CHOSEN` | `0x00DC118C` / `0x00DC1288` | Mode-1 character-select pane cursor and the chosen slot it commits (disasm 0x6CA598 block; empty slot = error buzz 0x74580A(3)). Pre-solves the Magic/Equip/Status entry step; v2.32 speaks the cursor |
| *(savemap row byte)* | â€” | Char record **+0x20**: 0xFF = front row, 0xFE = back row (toggled by XOR 1 at 0x6CA67F). LIVE-CONFIRMED by the scan's single toggle candidate + disasm agreement. âš  community savemap doc says +0x1F â€” one byte off. Game's char-idâ†’record map: static u32 table 0x919928 |
| `SHOP_STATE` | `0x0092565C` | u32 shop screen state, the shop loop 0x71AAA3's own switch (jump table 0x71E193 decoded offline, v2.30.28 ff7_shop_static.py): **0=greeting + Buy/Sell/Exit bar, 1=buy list, 2=sell item list, 3=sell materia list, 4=buy quantity, 5=sell-item quantity, 6=sell-type bar (Item/Materia)**. Lives in menu-module .data like BATTLE_MENU_STATE. Shop gate = GAME_MODE==8 |
| `SHOP_ID` / `SHOP_NAME_IDX` / `SHOP_TEXT_IDX` | `0x00DD4724/28/2C` | u32 shop id (copy of the MENU opcode param word 0xCC0D8A) + the catalog's name/greeting-set indices, written by shop init 0x719D7A (disasm). Name string = 0x922FC8+idxÂ·0x14; greeting set = 0x923080+idxÂ·0x1CC (FF7-encoded exe .data) |
| `SHOP_BAR_CURSOR` | `0x00DD6B48` | u32 0=Buy 1=Sell 2=Exit â€” drawn Ã—0x32 px in states 0/6 (disasm). Widget struct base (+0=column) built by the generic list-widget ctor 0x6F4D30 |
| `SHOP_SELLTYPE_CURSOR` | `0x00DD6C98` | u32 0=Item 1=Materia on the sell-type bar (state 6, Ã—0x43 px highlight) |
| `SHOP_BUY_ROW` / `SHOP_BUY_SCROLL` | `0x00DD6B84` / `0x00DD6B94` | Buy-list widget (+4 row / +0x14 scroll of base 0xDD6B80); **ware index = row + scroll** (the confirm handler's own math at 0x71DAF7) |
| `SHOP_SELLI_COL/ROW/SCROLL` | `0x00DD6BB8/BC/CC` | Sell ITEM list widget (2-column grid over savemap items[320]); **item index = col + (row+scroll)Â·2** â€” lifted verbatim from the sell-confirm handler 0x71DC2B |
| `SHOP_SELLM_ROW` / `SHOP_SELLM_SCROLL` | `0x00DD6BF4` / `0x00DD6C04` | Sell MATERIA list widget (1 column over materia[200]); **slot = row + scroll** (0x71DD0A) |
| `SHOP_QTY` | `0x00DD473C` | u32 "How many" count, set to 1 on entering either quantity state; totals drawn as unitÃ—qty (buy 0x71B317, sell (price>>1)Ã—qty 0x71BD1E â€” the exact sell-price-halving proof) |
| `SHOP_PRICE_TABLE_PTR` | `0x00DD4720` | u32 â†’ heap price table: item buy price at (id&0x1FF)Â·4, materia at +0x600+(id&0xFF)Â·4. Materia sell = get_materia_gil 0x71FCF9: mastered (AP field 0xFFFFFF) â†’ baseÂ·70, else the raw AP count; base 1 = unsellable marker. Screenshot cross-check: Restore (id 53) master price 52500 = 750Â·70 âœ“ |
| `SHOP_CATALOG` | `0x00923418` | Static exe .data, record = base + shop_idÂ·0x54: +0 u8 name idx, +1 u8 greeting-set idx, +2 u16 ware count, +4 ware[10]{s16 type 0=item/1=materia; u16 pad; u32 id}. Read by init 0x719D7A and every buy-list access |
| `KERNEL_*_RESTRICT` | `0x00DBD16A/0xDBE75A/0xDBCD00/0xDBCAEE` | Kernel gear-record restriction words (items stride 0x1C / weapons 0x2C base id 0x80 / armor 0x24 base 0x100 / accessories 0x10 base 0x120), via helper 0x6C50DD; **bit 0 = cannot sell** (sell handler 0x71DC60 `and eax,1`) |
| `SAVEMAP_GIL` | `0x00DC08B4` | u32 party gil = savemap+0xB7C (was a raw literal in the v2.35 victory reader; promoted v2.30.28 â€” the shop's own buy/sell arithmetic reads/writes exactly here, third independent confirmation). The G key speaks it |
| `SAVEMAP_MATERIA` | `0x00DC04B4` | u32[200] materia inventory = savemap+0x77C (FFNx savemap struct; the shop sell code indexes it at 0x71DD16): word = id | AP<<8, 0xFFFFFFFF = empty slot |
| `SHOP_SESSION` / `SHOP_FADE_STATE` | `0x00DD6D78` / `0x00DD4734` | Session-active flag (wrapper 0x71FF95: 0â†’initâ†’1) and fade state (1 fading in / 2 fading out / -1 exiting â†’ menu-exit flag 0xDC12F4). Not consumed by the mod (GAME_MODE==8 is the gate); documented for completeness |
| `MATMENU_MODE` | `0x00920FA0` | u32 materia-menu state machine (jump table 0x70E246, modes 0-0xB, v2.30.33 static): 0=Check/Arrange bar, 1=slot navigation, 3=equip list, 4=Check mode, 5/6/7=transient, 8=Arrange popup (Arrange/Exchange/Remove all/Trash), 9/10=arrange list phases, 2/11=empty. Same .data band as SHOP_STATE/BATTLE_MENU_STATE â€” fourth confirmation of the per-screen state-machine cluster |
| `MATMENU_*` cursors | `0xDD12BC/F0/F4, 0xDD1364/74, 0xDD14B4/C4, 0xDD147C, 0xDD1398/9C, 0xDD1638` | bar cursor (0=Check 1=Arrange); slot idx/row (row 0=weapon 1=armor, OK on slot -> equip list); equip-list row/scroll (**materia[200] index = row+scroll**, the commit math at 0x70DC80); arrange-list row/scroll; popup row 0..3; Check-mode widget col/row; party slot 0..2 (Ã—0x440 = shared char-data index; weapon slot count byte at chardata+0x21) |
| `MATMENU_CHARREC_PTR` | `0x00DCA810` | u32 â†’ the viewed character's savemap record (init 0xDBFD8C=Cloud); slot contents = rec+0x40 weapon / +0x60 armor u32[8] materia words. The v2.31 "0xDCA7F8 exclusive block" was THIS screen's state all along |
| `EQMENU_PARTY_SLOT` | `0x00DCA4A4` | u32 equip-screen PARTY-MEMBER cycler 0..2 (L1/R1 char flip). âš  **PLAY-CORRECTED v2.30.50**: v2.30.34 shipped this as the category row â€” the Â±1-wrap code (0x707079/0x7070C0) reads SAVEMAP_PARTY_IDS[value] and re-steps on 0xFF (empty-slot skip), and the 0x707105 path copies it into CHARSEL_CHOSEN: it cycles CHARACTERS. The real category row is `EQMENU_CATEGORY` 0x00DCA5C4 (OK handler 0x707175/0x707187 passes it to the candidate builder 0x7083ED; bounds cmp 2 throughout the sub). Two 0..2 cursors on one screen â€” the wrap shape alone couldn't tell them apart (Â§8 v2.30.50 lesson)ettled it as the cursor |
| `EQMENU_LIST_OPEN` / `EQMENU_LIST_ROW/SCROLL/COUNT/BYTES` | `0xDCA6A0 / 0xDCA5FC / 0xDCA60C / 0xDCA7EC / 0xDCA6A8` | candidate-pane flag (0=rows 1=list); list widget @0xDCA5F8 (+4/+0x14); **candidate = u8[0xDCA6A8][row+scroll]** (the OK-commit's own read at 0x707350) â€” bytes are category-relative kernel gear indices, 0xFF terminator, count from the list builder 0x708640. Equip menu char = CHARSEL_CHOSEN (char page-flip writes it at 0x707148/0x70726E); equipped ids = record +0x1C/1D/1E. Equip sub = table[4] = FFNx menu_sub_705D16 (table[15] dupes it) |
| `LIMITMENU_MODE` | `0x009204D8` | u32 limit-menu state 0..4 (draw switch 0x70313A; 0 = Set/Check bar, 1-4 = grid/confirm phases â€” per-value mapping rides the mod's debug log; v2.30.35 static). Same 0x92 state band as the shop/materia/battle machines |
| `LIMITMENU_*` cursors | `0xDCA1D0, 0xDCA198/9C, 0xDCA208/0C, 0xDCA3C8` | bar cursor (Ã—0x50 highlight, 0=Set 1=Check); Set grid col/row (Ã—0x124/Ã—0x89 â€” the 2Ã—2 LEVEL grid, level=rowÂ·2+col); Check grid col/row (second instance); party slot 0..2 (the sub resolves char via SAVEMAP_PARTY_IDS + the game's own idâ†’record table 0x919928) |
| *(limit data)* | â€” | learned mask = charrec **+0x22** u16, bit = levelÂ·3+technique (the sub's own `imul 3/shl` test at 0x702190); technique names = magic text 128 + blockÂ·7 + (levelÂ·2+tech; L4=+6) with the KERNEL'S Aeris/Tifa block swap (kernel2 ground truth: 128 Braver/Cloud, 135 Barret, 142 AERIS, 149 TIFA, 156 Red XIII); current limit level = charrec +0x0E |
| `MAGICMENU_PARTY_SLOT` | `0x00DD17E8` | u32 party slot 0..2 shown by the MAGIC menu (v2.30.48 static, ff7_magic_menu_static.py): the sub computes [this]Â·0x440 + 0xDBA5A0 = BATTLE_CHAR_BLOCK + BCHAR_OFF_MAGIC_LIST â€” **the menu's spell list IS battle's per-slot magic list** (stride 8, u8 id @+0, 0xFF empty; the [ptr]+offset==static proof pattern). âš  same address the v2.30.38 E8-scan lesson flagged as an operand false-positive â€” now identified: it was this slot variable all along |
| `MAGICMENU_LIST_*` | `0xDD1708 / 0xDD170C / 0xDD171C` | standard list widget (ctor 0x6F4D30 family: +0 col, +4 row, +0x14 scroll); spell index = col + (row+scroll)Â·3 (3-column grid, draw loop at 0x711726..0x711789). Window struct ptr at 0xDD1690 (+0x10/+0x12 screen coords) |
| `MAGIC_MENU_USABLE_TABLE` | `0x00714440` | u8[0x34] **in .text** â€” the renderer's own menu-usable classifier: table[id] â†’ jump table 0x714430; cases 0/1/2 draw color 7 (white/usable â€” disk bytes: ids {0,1,2,7,8,0x33}), case 3 + ids >0x33 draw color 0 (grayed). Mod reads it LIVE so ", battle only" mirrors the drawn gray by construction (v2.30.48) |
| `MAGICMENU_PANE` / `_TARGET_ROW` | `0x00921100` / `0x00DD16D4` | pane selector (0=spell list, 1=target pane; cmp sites 0x710E0E/0x710FBA) and the pane-1 cursor row (drawn at Â·0x78). âš  least-proven of the v2.30.48 set â€” flagged verify-live |
| `TUTORIAL_RUNNING` | `0x00DBFD30` | u32, 1 while a menu tutorial's byte-code VM runs (set by menu start_tutorial 0x6CB620, cleared by the VM's END opcode 0x7185AC / stop paths). v2.30.29's authoritative tutorial gate + "Tutorial finished." edge (ff7_tutorial_static.py 2026-07-26) |
| `TUTWIN_STATE` | `0x00DC1310` | u8 tutorial/message window renderer state: 0=closed, 1=opening, 2=TEXT SHOWING, 3=closing (= FFNx's menu_tutorial_window_state, operand at renderer 0x6C49FD+0x9; FFNx's voice hook uses the same 0â†’1â†’2â†’3â†’0 edges). v2.30.29 speaks each slide on the â†’2 edge |
| `TUTWIN_TEXT_PTR` | `0x00DC1214` | u32 â†’ the CURRENT window's FF7-encoded text (= FFNx menu_tutorial_window_text_ptr, operand +0x18). For tutorial slides it points INTO the field buffer (the VM passes its script PC); for the save screens' info popups (same renderer, callers 0x6FFB65-0x6FFEAD/0x721Fxx) it points at exe .data strings â€” v2.30.29 speaks both |
| `TUTWIN_MODE` | `0x00DC1318` | u8 window advance mode (0x6C49CB arg): 0 = auto-close on TUTWIN_TIMER (0xDC1314, from 0x14/0x28), nonzero = closes on ANY pressed key (renderer 0x6C4C4D: `call consume-pressed; test eax,eax` â€” no specific button). The v2.30.29 "Press any button to continue" hint keys off this |
| `TUTORIAL_SCRIPT_PC` | `0x00DD1BC8` | u32 VM script pointer into the field buffer (start_tutorial 0x71820F arg; stepped by the opcode cases). Not consumed (TEXT_PTR suffices); documented with the VM map: opcode 0x00=wait u16 frames, 0x02-0x0D = INJECTED keys (UP 0x1000/DOWN 0x4000/LEFT 0x8000/RIGHT 0x2000/0x10/CANCEL 0x40/0x80/OK 0x20/8/2/4/1 â€” jump table 0x7185C7), 0x10=text window, 0x11=END, 0x12=window x,y. **While a tutorial runs the menu input refresh (0x7186C8â†’0x71826E) OVERWRITES the pressed/held digests 0x9A85E0/0x9A85D4 with VM output â€” real input never reaches menu navigation**; only the window-close test reads real presses first |
| `FIELD_ID` | `0x00CC15D0` | s16, non-zero on named field maps, 0 on title/world. **Does NOT zero during battle** (live-corrected 2026-07-09; earlier belief wrong) |
| `G_ACTIVE_ACTOR_ID` | `0x00BE1170` | u8 slot of last-acting battle actor (0â€“2 party, 4â€“9 enemy); never resets between battles (v2.5) |
| `G_BATTLE_MODEL_STATE` | `0x00BE1178` | Per-actor battle array, stride 0x1AEC; commandID u8 at +0x23 (v2.5) |
| `G_SMALL_BATTLE_MODEL_STATE` | `0x00BF23B8` | Stride 0x74; its +0x3E "actionIdx" climbs like an animation counter when polled continuously, but AT FLASH TIME it holds the real ability id (FFNx passes it to the flash writer) â€” only sample it via the flash struct below |
| `BATTLE_ACTOR_DATA` | `0x00DC38E0` | FFNx ff7.h `battle_actor_data`; the old "KERNEL2_REQUEST" reading was its middle: +0x08 formation_entry (pending pulse), **+0x0C command_index (0xDC38EC), +0x10 action_index (0xDC38F0)** â€” written at FLASH TIME (~1â€“2s after turn start), not rewritten for repeated identical flashes (v2.7, live-verified 2026-07-11: Ice/Potion/Machine Gun/Tentacle) |
| `BATTLE_DISPATCH_BYTE_TABLE` | `0x006D70A8` | Static .text: byte[table+cmd] = flash-name branch for cmd 0x00â€“0x20; jump table at 0x6D7080. Branchâ†’source: 0/1=magic names; 2=summon; 3/5=item namespace; 4=buffer 0xDC3640; 6=magic+72 (E.Skill); 7=magic+128 (Limit, 0x7F='????'); 8=enemy attack table; 9=no flash text (v2.7) |
| `ENEMY_ATTACK_NAME_TABLE` | `0x009A9484` | Current formation's enemy attack names from scene.bin, stride 0x20, FF7-encoded (v2.5 candidate â†’ CONFIRMED v2.7; 'Machine Gun'/'Tonfa'/'Bite'/'Tentacle') |
| `GET_KERNEL_TEXT` | `0x0041963C` | The REAL get_kernel_text (= FFNx external; sub_41963C; kernel2_get_text=0x419457 at +0xF7). âš  Useless in battle: reads menu-module scratch (0x9A13C8 via u16 table 0x9A7FC8) which is EMPTY during battle. v2.7 reads the heap text sections directly instead |
| `KERNEL2_RESULT_PTR` | `0x00DC208C` | Written with the lookup result after every CALL 0x41963C in the consumer (disasm-confirmed) â€” but NEVER written under FFNx (consumer path replaced); observed 0 through all battles. Do not use |
| `MODULES_GLOBAL_OBJECT` | `0x00CC0D88` | Field module global struct; **PSX decomp struct (include/game.h ~370) matches field-for-field across +0x28..+0x3B** â€” PSX comments identify unnamed PC fields |
| `GAME_MODE` | `0x00CC0D89` | +0x01, u8. Live-observed: **0=field play, 1=FIELD JUMP PENDING (audit 2026-08-02: held for the whole screen load; set by MAPJUMP/gateway-hit/save-load/world-exit when arming FIELD_JUMP_INTERFACE, cleared at phase 2 - v2.30.64 watcher saw it on every transition of both runs), 2=battle, 6=name entry, 9=menu, 26=game-over handoff (TRANSIENT ~60ms â€” v2.30.37, 2026-07-27 wipe log)**. STATIC (v2.30.28, menu-type dispatcher 0x6CDA83 jump table decoded offline â€” index bytes 0x6CDBE4, targets 0x6CDBC4): **6=name entry, 7=PHS, 8=SHOP, 9=main menu, 14/18/19 = further menu screens**; also STATIC 2026-08-02: field_loop's own dispatch (0x63C1A0..) switches on mode - 0xF via jump table 0x63CC09, so modes **15..24 = menu-module sub-entries** invoked from the field loop (several take DEST_FIELD_ID as an argument) â€” the two live-confirmed values (6, 9) both match the decode, validating the table. âš  FFNx's `ff7_game_modes` enum does NOT describe this byte (it's for a different variable). âš  the GAME OVER film reel + post-game-over title prompt read as mode **0** with FIELD_ID **stale** at the dead field â€” the 26 blip is the only positive game-over signal (GameOverWatchThread polls it at 30ms) |
| `FIELD_UC_LOCK` | `0x00CC0DBA` | +0x32, u8. Player-control lock (field opcode UC); nonzero = scripted scene, input ignored. Via PSX struct match |
| `FIELD_BGMOVIE_FLAG` | `0x00CC0DC2` | +0x3A, u8. Movie is background-only (player walkable) |
| `FIELD_KEY_INPUT_STATUS` | `0x00CC0DF0` | +0x68, u32. Digested input: UP=0x1000 RIGHT=0x2000 DOWN=0x4000 LEFT=0x8000, Cancel/run=0x40. **Freezes at last value when battle starts** |
| `FIELD_EVENT_DATA_PTR` | `0x00CC0B60` | â†’ per-model array, stride 0x88: model_pos 3Ã—i32 at +0x0C, movement_speed u16 at +0x76. Observed target: static 0xCC1670 |
| `FIELD_PLAYER_MODEL_ID` | `0x00CC162C` | u16 player index into event-data array (player â‰  always model 0) |
| `FIELD_ANIM_DATA_PTR` | `0x00CFF738` | â†’ field_animation_data array, stride 0x190 per model; kawai_opcode u8 at +0x21. Doubly confirmed 2026-07-14 (FFNx ff7.h address-in-comment + our LADER-handler disasm reads it with the same stride). Used by the chest-state investigation; not read by the shipped mod |
| `FIELD_N_MODELS` | `0x00CFF73E` | u16 model count on current field |
| `FIELD_MOVIE_PLAYING` | `0x00CC1638` | u16 nonzero while movie plays on field. FFNx movie test: `word && !BGMOVIE_flag` |
| `BATTLE_MENU_STATE` | `0x0091EF9C` | u16, current battle menu widget â€” **LIVE-CONFIRMED 2026-07-12** (two runs, logs battle_menu_live_20260712_2136/2144): **1=command menu, 6=magic list, 24=limit select, 0=waiting/ATB AND post-Confirm targeting (with PREV=1), 0xFFFF=menu closed/turn executing**. 3=Change-row dispatch (fired on Right press). Statics: 5=item list (global inventory table), 7=summon list, 2=Defend dispatch â€” not yet crossed live. âš  targeting does NOT use state 19 in the normal flow |
| `BATTLE_MENU_PREV_STATE` | `0x0091EF98` | u16, written on every state transition (static 2026-07-12) |
| `BATTLE_MENU_FN_TABLE` | `0x0091E6B8` | uint32[64] per-state handler table (= FFNx battle_menu_state_fn_table; resolved from battle_sub_6DB0EE+0x1B4) |
| `BATTLE_ACTIVE_SLOT` | `0x00DC3C7C` | u8 party slot (0â€“2) whose battle menu is open; selects the widget block AND the char data block below (âœ“ live 2026-07-12, slot=0) |
| `BATTLE_MENU_BUSY` | `0x00DC35AC` | u32, 1 = menu transition/animation in progress; handlers skip input while set (static 2026-07-12) |
| `BATTLE_WIDGET_BASE` | `0x00DC20A0` | **THE BATTLE MENU CURSOR â€” LIVE-CONFIRMED 2026-07-12** (spoke Attack/Magic/Item correctly through two full battles). Per-slot block at +slotÂ·0x700; 0x38-byte widget structs: +0x00 command widget, +0x38 state-5 (item) list, +0x70 state-6 (magic) list, +0xA8 state-7 (summon) list. Widget fields: +0 horiz cursor (LEFT/RIGHT), +4 vert cursor (UP/DOWN), +0x08 horiz wrap count, +0x0C visible rows, +0x14 scroll offset, +0x1C total entries, +0x28/+0x2C axis modes, +0x30 scroll-busy. Command menu: selected entry index = **row + colÂ·4** (column-major, 4 rows/col, `and 3` wrap); col wraps mod u8[0xDBA4B9+slotÂ·0x440]. List widgets: selected index = w0+w4+scroll (âœ“ live for magic list) |
| `BATTLE_CHAR_BLOCK` | `0x00DBA498` | Per-slot battle char data, stride 0x440. +0x21 = command column count; **+0x4C (0xDBA4E4) = command table**, 6-byte entries indexed row+colÂ·4: u8[+0] command id, u8[+1] action type (Confirm jump-table selector 0â€“0xB), u8[+2] action id. **Command ids are 1-BASED for basic commands** (âœ“ live: 1=Attack, 2=Magic, 4=Item; 0xFF=empty cell) **but Limit keeps kernel id 0x14=20** (âœ“ live: replaces Attack's row-0 entry when the gauge fills; Confirm â†’ state 24). +0x108 (0xDBA5A0) magic list (âœ“ live via state 6), +0x2C8 (0xDBA760) summon list, both 6-byte entries. **v2.33: NOT battle-only â€” the menu populates it too**, with EFFECTIVE stats (materia applied): +0x02..+0x07 u8 str/vit/mag/spr/dex/luck, +0x08/+0x0A/+0x0C/+0x0E u16 Attack/Defense/Magic atk/Magic def, +0x10..+0x16 HP/maxHP/MP/maxMP (single BSS pattern hit against the status screenshot; hunt + dump logs 2026-07-18). Menu consumers must guard staleness: block HP pair == savemap record HP pair |
| `BATTLE_ITEM_LIST_TABLE` | `0x009AC354` | Global (not per-slot) ITEM list (state 5): single column, **6-byte** entries, u16 id at +0 (**0xFFFF = empty; id 0 = Potion is VALID**, v2.36 â€” the old "skip 0" silenced Potions), u8[+4] enable flag. index = w0+w4+scroll |
| *(magic/summon list format)* | â€” | **3-COLUMN grid, 8-byte entries** (v2.36 Confirm-path disasm â€” NOT the item layout): u8 id at +0 (0xFF = empty), u8[+6] bit 0x02 = disabled. Selected index = **w0 + (w4+scroll)Â·3**. Tables: magic = CHAR_BLOCK+slotÂ·0x440+0x108, summon = +0x2C8. The v2.9 linear formula/6-byte reading was correct only for items + a â‰¤3-spell single row |
| `BATTLE_TEXT_QUEUE` | `0x00BF1EB8` | Battle text display queue (v2.36): battle_text_data[64], **stride 6**, s16 buffer_idx at +0 (-1 = empty slot, â‰¥0x100 = scene AI dialogue). FFNx name-anchored (add_text_to_display_queue+0x25). The channel BattleMessageThread reads for the scorpion tail warning etc. |
| `SCENE_MSG_BASE / _OFFSETS` | `0x009AD1E0 / 0x009AD9E0` | Current formation's scene.bin messages: text(idx) = 0x9AD1E0 + u16[0x9AD9E0 + (idx-0x100)Â·2], FF7-decoded. Replicates GET_KERNEL_TEXT section 8 (handler 0x4199AD â†’ 0x41D2E5). v2.36 |
| `BATTLE_ISSUED_CMD` | `0x00DC3C70` | u8 = FFNx issued_command_id (âœ“ live: 1 on Attack confirm, 2 on Magic, 19=0x13 on Right press = Change-row, 20 on Limit) |
| `BATTLE_ISSUED_ACTION` | `0x00DC3C78` | u16 = FFNx issued_action_id (âœ“ live: 30 after confirming Ice) |
| `BATTLE_TARGET_TYPE/INDEX` | `0x00DC3C90/94` | u8 pair = FFNx issued_action_target_type/index. INDEX tracks the moving target selection live (âœ“: 4â†”5 across enemies, 0 = party slot 0) |
| `BATTLE_TARGETING_ACTOR` | `0x00DC3C98` | u8 = FFNx targeting_actor_id_DC3C98 â€” live target cursor actor id (âœ“ 2026-07-12: 4/5 = enemy slots, party 0â€“2). Updates during state-0 targeting after a Confirm |
| `BATTLE_FORMATION_SLOTS` | `0x009A8794` | Per-enemy-slot formation table, stride 0x10: u16 (movsxâ†’signed, -1 = empty) = index into the loaded enemy records, indexed by enemy list index 0â€“5 (= actor slot âˆ’ 4). From get_kernel_text SECTION 7 = the game's own target-name lookup (jump table 0x419A38, handler 0x4197D3; static disasm 2026-07-13, v2.10) |
| `BATTLE_ENEMY_RECORDS` | `0x009A8E9C` | The 3 loaded scene.bin enemy records, stride 0xB8 (= exact scene.bin record size); FF7-encoded display name = bytes 0â€“0x1F, 0xFF-padded but possibly UNterminated at 0x20 â€” the game copies max 0x20 then writes its own 0xFF (0x41999B); never Decode() in place (v2.10) |
| `BATTLE_DUP_LETTER_TABLE` | `0x009A8B1F` | Per-ACTOR-SLOT duplicate-name letter, stride 0x44: u8 index appended as FF7-char(dword[0x9AB070]+idx) â†’ "MP A"/"MP B"; 0xFF = enemy type unique in formation. dword[0x9AB070] = encoded 'A' base (v2.10) |
| *(target-name extras)* | `0x9AB0E0/0x9A8B39` | From the v2.10 disasm, identities RESOLVED in v2.11 via BATTLE_ACTOR_VARS below: u32[0x9AB0E0+slotÂ·0x68] = actor_vars stateFlags (+0x04), bit 0x40 â†’ game appends kernel string 0x71 (unused); u8[0x9A8B39+slotÂ·0x44] bit 0x40 = **SENSED display flag** â†’ game formats "cur/max" HP from u16[0x9A8B4C+slotÂ·0x44] (display-cached cur) + u16[0x9AB10C+slotÂ·0x68] (= actor_vars maxHP low word) via kernel strings 0x7F/0x72. 0x9A80F0 = the game's target-name scratch buffer (write-on-render only â€” do NOT poll) |
| `BATTLE_ACTOR_VARS` | `0x009AB0DC` | FFNx battle_ai_context::actor_vars â€” per-actor battle stats, 10 slots Ã— stride 0x68 (= sizeof battle_actor_vars). Static, two agreeing derivations (ff7_sense_hp_static.py, v2.11): (1) FFNx chain battle_context = u32 operand at 0x41CCB2+0x5F = 0x9AB0A0, actor_vars = +0x3C; the operand sits in "mov edi,0x9AB0A0 / rep stosd" â€” sub_41CCB2 is the battle-init memset whose OTHER memsets clear exactly the v2.10 formation/enemy-record regions; (2) section 7's reads land on named fields with this base. Key offsets: +0x04 stateFlags, +0x24 formationID (u16, = FFNx voice enemy_id), +0x28/+0x2A cur/max MP (u16), **+0x2C/+0x30 cur/max HP (i32)** â€” read the i32s, not the game's u16 display words (>65535-HP bosses truncate) |
| `BATTLE_SENSED_FLAG_TABLE` | `0x009A8B39` | u8 per actor slot, stride 0x44 (same display struct as the dup-letter byte); bit 0x40 = target window shows HP (set by Sense). v2.11 gates the enemy HP readout on it â€” exact info parity with the sighted window; party slots 0-2 speak HP unconditionally (party HP is always on-screen) |
| `BATTLE_END_MODE` | `0x00DC1300` | u16 victory-screen phase = FFNx's `menu_battle_end_mode` (operand at menu_battle_end_sub_6C9543+0x2C). âš  **v2.35's static-only reading (0=won/init, 1=EXP/AP screen, 3=gil/items screen) was PLAY-CORRECTED v2.35.2**: it advances on the player's OK PRESSES, not screen appearances â€” 0=EXP/AP screen SHOWING, 1=roll-up running (chirps/levels apply), 2=gil/items screen SHOWING, 3=after its OK (gil applied). Use the v2.35.2 phase map, not the raw disasm-only one (ff7_battle_results_static.py/ff7_results_block_refs.py, v2.35, 2026-07-19; corrected 2026-07-19) |
| `BATTLE_GAINED_EXP` / `_AP` / `_GIL` | `0x0099E2C0` / `_C4` / `_C8` | u32 results pools (battle module 0x431541.. accumulates per enemy slot from actor_vars, stride 0x68). âš  **CONSUMED ON APPLY** â€” the menu does `SAVEMAP_GIL += pool; pool = 0` as mode goes to 3 (0x6C6B8F), and EXP/AP drain similarly during the mode-1 count-up: capture all three AT RESULTS ENTRY, never at screen time (v2.35) |
| `BATTLE_DROPS_COUNT` / `BATTLE_DROPS_ARRAY` | `0x009AE12C` / `0x0099E2F0` | u32 entry count; stride-6 array, u16 item id at +0 (0-319 namespace, same as inventory), +4 word copied during list compaction (qty/taken flag, logged not spoken pending live confirmation). Battle fill loop 0x4315E9 (imul 6) is the stride proof (v2.35). Level-ups are NOT announced from these pools â€” the savemap level bytes (records +0x01) are watched during the results window instead, needing no new addresses |
| `FIELD_TRIGGERS_HEADER_PTR` | `0x00CFF454` | Global holding field_trigger_header* (FFNx ff7.h) â€” engine's parsed TRIGGERS section (âš  naming audit 2026-08-02: RAW file section INDEX 7 per the corrected Â§5 table; FFNx's docs historically call it "section 8" by 1-based count â€” both names mean this same data). Parsed layout, tail COMPLETED 2026-08-02 (arrow renderer 0x64DAC8 disasm): +0x158 field_trigger[12] door boxes (16B: 2 corner vertices, bg_group/bg_frame/behavior/sound â€” background-flip doors, 119 used game-wide), +0x218 show_arrow_flag[12] (the story-lock parity candidate), +0x224 field_arrow[12] (16B: x/y/z i32 + type). Gateway record fully decoded â€” see the *(gateway record layout - COMPLETE)* row below. Single writer 0x6211DA (one screen in memory). Original v2.14 facts: +0x00 char[9] field name (ASCII; live-confirmed "md1stin" spoken by M), +0x09 u8 control_direction, +0x38 field_gateway[12] exits (24B: 2Ã— s16[3] exit-line vertices in walkmesh coords, s16[3] destination vertex, s16 dest field id, 0x7FFF = unused), +0x158 field_trigger[12]. Static via FFNx chain anchored at name-embedded field_sub_6388EE, 3 name-embedded cross-checks passed (0xCFFE3C/0xCFF3D8/0x623C0F) â€” ff7_field_triggers_static.py, v2.14 |
| *(control_direction semantics)* | â€” | **FULLY CONFIRMED 2026-07-13** (calibration walkabout + follow-up play test): control_direction = the WORLD BEARING OF SCREEN-DOWN in atan2(dx,dy) convention (0=+Y, clockwise toward +X). Screen/d-pad angle = world_deg + control_deg âˆ’ 180, a PURE ROTATION â€” left/right ear-confirmed correct, no mirror. (Calibration data: md1stin control_dir=124â†’174.4Â°; Up motion 5.6Â°, Down âˆ’174.4Â°. First guess world âˆ’ control was 180Â° off.) Player-accepted v1 limitation: story-locked exits are still listed (see TODO for the show_arrow_flag/unknown-bytes detection routes) |
| *(coordinate scale)* | â€” | field_event_data model_pos = walkmesh coords Ã— 4096 (FFNx background.cpp `/4096.f`); player walkmesh pos = model_pos >> 12, directly comparable to gateway vertices. Walking â‰ˆ 160 walkmesh units/sec (from v2.6: 32768 highres/50ms at walk speed 1024) |
| *(field_event_data offsets)* | â€” | Per-model struct (stride 0x88, base via FIELD_EVENT_DATA_PTR 0xCC0B60), offsets from FFNx ff7.h field order, anchored by the LIVE-verified movement_speed +0x76 (v2.6): **+0x00 u16 apply_kawai, +0x04 kawai params ptr (toggles every frame while an effect runs), +0x36..+0x3B rotation/FACING cluster (+0x38 = THE authoritative facing byte - see the *(model FACING)* row below; audit cross-ref 2026-08-02), +0x5D u8 entity_id, +0x61 u8 TALK-DISABLED (the TLKON opcode's arg written raw: 0=talkable default, 1=disabled â€” handler 0x618A80 disasm + live confirm 2026-07-16, the "Jessie won't talk" incident; v2.26 speaks ", talk disabled"), **+0x62 u8 VISIBILITY** (1=visible, 0=script-hidden; v2.30.45 â€” the VISI opcode (0xA4) handler 0x618A01 writes its operand here and the CHAR bind path stores 1 at 0x6143D2, so every bound model STARTS visible and 0 is always a deliberate hide; pickup scripts hide collected items exactly this way (game-wide walk, ff7_prop_interact_catalog.py) â€” the Items category and prox chirp filter on it; FFNx's unnamed field_62), **+0x63 s8 movement_type: 4 or 5 = ON A LADDER** (LADER's four cases write 4/4/5/5, its re-entry test is >=4 && <=5, arrival writes 0; the only two other writers in .text also write 0 => exclusive climb signal, v2.30.60), +0x6E u16 climb orientation variant (0/1 — explains the v2.30.24 'rc6E identical to 0' reading: only written on a climb), +0x70 u16 climb phase (0 armed/1 moving/2 arrived), +0x7C/+0x80/+0x84 s32 climb TARGET x/y/z <<12 (push-direction source), +0x64 s8 animation_id, +0x66 s16 animation_speed, +0x68 s16 currentFrame, +0x6A s16 lastFrame (CHEST OPEN SIGNAL â€” see v2.18.1), +0x6C s16 character_id (âš  LIVE-DISPROVED as a party indicator 2026-07-13: an ordinary reactor NPC carried 4 = "Red XIII" â€” do NOT name from it, v2.15.2), **+0x72 s16 COLLISION RADIUS** (CONFIRMED 2026-07-25 v2.30.24: the v2.30.22 rc-candidate dump showed per-model radius-like values â€” Tifa 30, Barret 48, AVALANCHE trio 34 â€” and body-block rest distances fit player_r+npc_r with Cloud â‰ˆ32 on two independent anchors, 64 vs Tifa and 81 vs Barret; +0x6E â‰¡ 0 and +0x70 flaps 0/1, both rejected. âš  DYNAMIC â€” scripts change it (SLIDR family): 0 = intangible right now, Tifa read 20 in a hideout scene state, a prop briefly 120 â€” always read LIVE, never cache), +0x74 s16 talk_radius, +0x78 s16 field_triangle_id (<0 = off-walkmesh â€” v2.15 People filter)** (v2.15/v2.18.1/v2.26/v2.30.24) |
| `FIELD_LINE_COUNT` | `0x00CC088C` | u16, number of LINE trigger zones declared on the current field (0â€“0x20; the LINE handler refuses past 32). Per-field value â€” LIVE-CONFIRMED 2026-07-14 (0 on fields 116â€“119, 2 on field 120, stable on field re-entry). Static find: all three line-opcode handlers read/increment it (ff7_line_triggers_static.py, v2.17) |
| `FIELD_LINE_ARRAY` | `0x00CC1F70` | The engine's LINE trigger zone array, 32 Ã— 0x18: **+0x00 s16Ã—6 = x1,y1,z1,x2,y2,z2 (walkmesh coords, raw LINE-opcode args), +0x0C u8 enabled (1 on create; LINON writes its arg byte here), +0x0D u8 owning entity id, +0x0E u8 state latch (cleared on disable)**. Three handlers agree on base/stride/offsets: LINE 0x6111D8, LINON 0x6115AD, SLINE 0x6114D0 (opcode table 0x9055A0 read from disk via the mod's own Resolve() chain, validated by MESSAGE+0x3B=E8). LIVE-CONFIRMED 2026-07-14 on field 120: 2 sane segments, valid entity ids, plausible distances (v2.17) |
| `FIELD_ENTITY_LINE_SLOT` | `0x00CBF600` | u8 per entity id â†’ index of that entity's line in FIELD_LINE_ARRAY (written by the LINE handler, read by LINON/SLINE). Not needed for browsing (the array itself carries the entity id at +0x0D) |
| `FIELD_ENTITY_MODEL_MAP` | `0x00CBFB70` | u8 per entity id â†’ model slot, 0xFF = the entity has no model. Bonus find from the TLKON handler disasm (0x618A80) â€” that handler resolves its executing entity through this table to reach the talk-disabled byte. Re-confirmed by TWO more handlers 2026-07-31 (VISI 0x618A01, CHAR bind 0x6143A5-region â€” v2.30.45 hunts). Not yet used by the mod directly (v2.26) |
| `FIELD_CURRENT_ENTITY` | `0x00CC0964` | u8 â€” index of the script entity whose opcode is EXECUTING right now; every field opcode handler disasm'd to date (TLKON/VISI/CHAR/MPNAM...) starts by loading it. Not consumed by the mod (our hooks receive context from the engine call); recorded 2026-07-31 (v2.30.45 VISI hunt) |
| `FIELD_SCRIPT_PC_ARRAY` | `0x00CC0CF8` | u16 per entity â€” each entity's current script program counter (offset into the section-0 code block at FIELD_SCRIPT_PTR 0xCBF5E8). Handlers read their operands via it and advance it by their instruction length (VISI: +2 at 0x618A73; CHAR: +2 at 0x614418). Not consumed by the mod; recorded 2026-07-31 |
| `SAVEMAP_CHAR_RECORDS` | `0xDBFD8C` | First of 9 savemap character records (Cloud), stride 0x84; **FF7-encoded live name (renames included) at +0x10, 12 bytes, 0xFF-terminated**. Derived, not scanned (v2.19): 7thHeaven equipment blocks at savemap+0x70 start with the weapon byte = record offset 0x1C â†’ records at +0x54; 9Â·0x84 ends exactly at the party IDs below â€” two anchors agree. v2.33 screenshot-verified field map (status_record_verify log): +0x01 level, +0x02..+0x07 **BASE** str/vit/mag/spr/dex/luck (dex FFNx-named; screen shows EFFECTIVE â€” see BATTLE_CHAR_BLOCK), +0x0E limit level, +0x1C/+0x1D/+0x1E weapon/armor/accessory ids (0xFF = none), +0x20 row byte (v2.32), +0x2C/+0x38 HP/maxHP, +0x30/+0x3A MP/maxMP, +0x3C exp u32, +0x40 materia[16] u32, +0x80 exp-to-next u32 |
| `PARTY_LEADER` | `0xDC09E5` | u8 character ID of the current party leader (7th Heaven `PartyLeader` var). Consumed by PartySlotLabel's self-verification: SAVEMAP_PARTY_IDS slot 0 must equal it or naming falls back to positional "ally N" (v2.19). Was previously documented only inline in the SAVEMAP_PARTY_IDS row (2026-07-23 audit) |
| `STORY_PROGRESS` | `0xDC08DC` | s16 story-progress counter advanced by field scripts (7th Heaven `PPV` var). Defined in ff7_addresses.h since early research; FIRST CONSUMED v2.30.66: logged as ppv= on every ARRIVE line (the [STORYNAV] evidence pipeline - live values 1..13 observed across the 2026-08-02 reactor run, advancing at story beats). Future: PPV -> next-objective table for the Places story marker; also the story-locked-exit suppression candidate. Was missing from this table entirely (2026-07-23 audit) |
| `SAVEMAP_PARTY_IDS` | `0xDC0230` | u8[3] â€” character IDs of party slots 0-2 (0xFF = empty; 9=Young Cloudâ†’record 6, 10=Sephirothâ†’record 7 during the Kalm flashback). **Self-verifying at runtime**: slot 0's byte must equal PARTY_LEADER (0xDC09E5) or PartySlotLabel falls back to positional "ally N" (v2.19) |
| `SAVEMAP_ITEMS` | `0xDC0234` | **Party inventory items[320]** u16 (savemap+0x4FC â€” pinned by party_members[3]+pad in FFNx's savemap struct, i.e. 4 bytes past the live-verified party IDs): id = bits 0-8 (0-127 items, 128-255 weapons, 256-287 armor, 288-319 accessories), qty = bits 9-15, **EMPTY = 0xFFFF** (format from FFNx's own menu_decrease_item_quantity reimplementation, menu.cpp). Screen row order = array order (Arrange rewrites the array). v2.31's item-list data source â€” needed NO scan |
| `SAVEMAP_KEYITEM_BITS` | `0xDC0894` | 32-byte key-item bitmask (savemap+0xB5C, FFNx field_B5C). Recorded for the Key Items pane follow-up; not yet consumed (player has no key items to verify against) |
| `COUNTDOWN_TIMER_SECONDS` | `0xDC08BC` | **The timed-escape clock, u32 WHOLE SECONDS** (savemap+0xB84 = FFNx's own `countdown_timer` field). STATIC-PROVEN pre-play (v2.34, the scorpion one-shot problem): the STTIM opcode (0x38) handler 0x61FCD8 stores hÂ·3600+mÂ·60+s here (ff7_timer_static.py). The WSPCL clock window renders FROM it â†’ rewriting it freezes display AND satisfies script time checks (Shift+T). âš  Persists in saves (it's savemap) and the game never resets it once an escape ends â€” a v2.30.8 play report (loading well past a completed escape resurrected "Timer started" in the slums) proved a bare observed-DECREASE heuristic isn't enough; v2.30.8 LIVE-HOOKS opcode 0x38 itself (execute_opcode_table[0x38], same pattern as MESSAGE/ASK) so TimerThread only trusts this value once a real STTIM call has fired THIS process run (`Hooks::SttimSeen()`) |
| `COUNTDOWN_TIMER_MS` | `0xDC08C0` | u32 sub-second accumulator driving the 1/sec tick (= FFNx `millisecond_counter`, operand at timer_menu_sub+0xD06). Not consumed by the mod |
| *(savemap char HP/MP)* | â€” | Character record words (record base = SAVEMAP_CHAR_RECORDS + recÂ·0x84): **+0x2C cur HP, +0x38 max HP, +0x30 cur MP, +0x3A max MP** â€” offsets from FFNx's savemap_char struct, the same struct that supplied the live-verified +0x10 name field. v2.31 speaks them in the use-on-whom pane (heal-target parity), guarded by the v2.19 leader cross-check |
| *(script entity names)* | â€” | Field-file section 0 header carries char[8] ASCII dev names per entity at **script_ptr + 0x20 + idÂ·8** (header: u16 unknown, u8 nEntities @+2, u8 nModels, u16 wStringOffset, u16 nAkaoOffsets, u16 scale, u8[6] blank, char[8] creator, char[8] field name = 0x20). LIVE-CONFIRMED 2026-07-14: field 120 line owners read 'evb' and 'drE', clean ASCII, ids < nEntities. Names the v2.17 Triggers category (v2.16 trick applied to entities) |
| `LOCATION_NAME_BUFFER` | `0xDC0C44` | **The friendly location caption** ("Sector 1 Station") the main menu displays â€” savemap+0xF0C, which is why saves remember it. Written by the MPNAM opcode (0x43) storage callee 0x633691: field text entry decoded token-by-token (char-name tokens via 0x6CB9B8), â‰¤ 0x17 bytes, 0xFF-terminated. âš  bytes past the terminator hold the PREVIOUS caption's tail (live-observed) â€” always stop at 0xFF. Found statically + LIVE-CONFIRMED 2026-07-16 in one session (ff7_mpnam_static.py / ff7_mpnam_verify.py: "Sector 1 Station" â†” "Platform" tracking the player's screen changes). A field without MPNAM keeps the previous caption â€” same persistence the sighted menu shows. v2.24 speaks it in the screen-change announce and the M key |
| `FIELD_TEXT_BLOCK_PTR` | `0xCC08E8` | Pointer to the current field's dialog-TEXT block: u16 offset table at ptr+2 (entry id â†’ ptr + u16[ptr+2+idÂ·2]). Read by the MPNAM callee 0x633691 (static disasm 2026-07-16); 0 when no field is loaded (the callee's own guard). Complements FIELD_SCRIPT_PTR (0xCBF5E8, section-0 base â€” same 0xCC08xx field cluster as FIELD_LINE_COUNT 0xCC088C) |
| `TRIANGLE_LOCK_BITS` | `0x00CC0E3A` | **The IDLCK triangle-lock bitfield** (v2.30.21, static disasm 2026-07-23): one bit per walkmesh triangle id â€” byte [0xCC0E3A + (tri>>3)], bit (tri&7), **SET = LOCKED/impassable**. Write side: IDLCK handler (opcode 0x6D = 0x61E29F, args u16 tri + u8 flag) via [field_global_object_ptr 0xCBF9D8]+0xB2; read side: the movement edge-crossing code (0x6369E8/0x636AAF/0x636B76, one branch per edge) tests the bit against STATIC 0xCC0E3A and refuses the crossing when set. 0xCC0E3A = MODULES_GLOBAL_OBJECT+0xB2 â€” proves 0xCBF9D8 points at the static modules block. How scripts make counters/doorways impassable over the static access pool (the Tifa bar-counter route bug); LoadWalkmesh cuts edges into locked triangles |
| *(game's parsed access-pool ptr)* | `0x00CFF748` | u32 â†’ the engine's own parsed copy of the walkmesh ACCESS pool (stride 3Ã—u16 per triangle, neighbor ids), read by the same movement code above. The mod parses the raw file section instead (equivalent data); recorded as the live-side anchor if a future feature needs the engine's copy |
| *(walkmesh section)* | â€” | Raw field file (behind FIELD_FILE_BUFFER 0xCFF594) **section index 4** (offset table entry buf+6+4Ã—4 = the `level_data+0x16` FFNx's renderer reads): u32 size prefix, u32 nTriangles, triangle pool (24B each: 3 Ã— s16 x,y,z,res â€” same coord space as model_pos>>12), then ACCESS pool (3 Ã— u16 per triangle = neighbor across each edge, 0xFFFF = wall). Triangle layout FFNx-production-confirmed; access pool **CONFIRMED GAME-WIDE OFFLINE 2026-07-16** (ff7_walkmesh_route_dryrun.py: 720/720 fields, 184,358 links, 100% id-valid + geometrically adjacent, 100.00% reciprocal) **and LIVE 2026-07-16** (nmkin_2 parsed in-game with the exact dry-run triangle count, turn-by-turn routes play-confirmed). Source of v2.22 turn-by-turn + v2.23 journeys; constants at ff7_addresses.h SECTION 1h; format detail Â§5 |
| *(player/model walkmesh triangle)* | â€” | field_event_data **+0x78 s16 field_triangle_id** (see offsets row above): the model's live walkmesh triangle â€” v2.22 uses it as the exact A*/journey endpoint (player and model targets), immune to stacked-layer ambiguity; <0 = off-mesh (the v2.15 People filter) |
| *(model FACING +0x36..+0x3B)* | - | field_event_data rotation cluster (FFNx names): +0x36 rotation_value, **+0x38 rotation_curr_value = THE authoritative facing byte** (0-255, x360/256 deg, same atan2(dx,dy) convention as control_direction). STATIC-PROVEN 2026-08-02 from three sides (ff7_screen_construction_static.py): DIR handler 0x618062 writes +0x38 directly (also +0x3A step idx, +0x3B steps type), GETDIR reads +0x38 back at 0x6184F1, DIRA path writes the same trio via 0x616BA8; and the field-ARRIVAL code applies DEST_DIRECTION to the player's +0x38 at 0x63C094 (absolute 0xCC16A8 = static event-data array 0xCC1670 + 0x38). **LIVE-CONFIRMED 2026-08-02 (audit upgrade)**: ARRIVE match=1 on every untouched gateway arrival across three play runs (facing38 == mailbox direction), and the wheel-to-screen composition (screen = world + control - 180, same as motion) was CONFIRMED against the user's auto screen captures (bridge arrival spoke "left", capture shows the party crossing left - decisive). The two match=0 arrivals were entry cutscenes turning the player, the predicted class; v2.30.68 defers the spoken facing past the UC lock for exactly that case |
| `FIELD_JUMP_INTERFACE` | `0xCC0D8A..0xCC0DAE` | **The engine's ONE transition-request interface** (modules_global_object fields; STATIC 2026-08-02, ff7_screen_construction_static.py + ff7_gateway_cross_disasm.py + ff7_gateway_hit_disasm.py): +0x02 `0xCC0D8A` dest field id (s16), +0x04/+0x06 `0xCC0D8C/8E` dest X/Y, +0x22 `0xCC0DAA` dest walkmesh triangle, **+0x24 `0xCC0DAC` dest arrival DIRECTION** (byte), +0x26 `0xCC0DAE` jump phase (armed 0, **2 = new field constructed**, written at 0x63C148/0x63C232 - the construction-complete signal), GAME_MODE (+0x01) held =1 while a field jump is pending. ALL entry paths write it: MAPJUMP handler 0x6131C4 (args field,x,y,tri,dir; quirk: field 0x313 remapped to 0x159), gateway-hit 0x636233 (from the gateway record), save-load 0x63CCBA (from savemap continue block), world-map exit 0x76713B/163/172, field-init/new-game region 0x60B48C.. Watching 0xCC0D8A+0xCC0DAE gives dest-field + screen-ready edges with no hook |
| *(gateway record layout - COMPLETE)* | - | 24B record (triggers hdr +0x38, 12 slots): +0x00/+0x06 exit-line vertices (2x s16 x,y,z), +0x0C/+0x0E dest X/Y, **+0x10 dest TRIANGLE id** (not a Z coord - validated game-wide offline 2026-08-02: 978/978 resolvable gateways < destination walkmesh nTriangles, ff7_gateway_flevel_dump.py), +0x12 dest field id (0x7FFF = unused), **+0x14 ARRIVAL DIRECTION byte, +0x15..+0x17 = three exact copies** (distributions identical across all 1036 used gateways; no hidden flags - the story-lock hunt moves to show_arrow_flag[12] at hdr+0x218). Crossing-hit consumer 0x636233 reads +0x12/+0x0C/+0x0E/+0x10/+0x14 into FIELD_JUMP_INTERFACE in that order |
| `WALKMESH_PTR` / `TRIANGLE_POOL_PTR` | `0xCFF434` / `0xCFF744` | The engine's parsed-walkmesh globals (STATIC 2026-08-02, arrival-init disasm 0x63C116..0x63C142): [0xCFF434] -> u16 nTriangles, +4 = triangle pool; 0xCFF744 = that pool ptr; ACCESS_POOL_PTR 0xCFF748 = base + 4 + nTri*0x18. Complements the raw-file section-4 parse the mod already does (walkmesh row above) - live-side anchors if we ever want the engine's copy |
| `SAVEMAP_CONTINUE_POS` | `0xDC08CE..0xDC08DA` | Save-file re-entry block (STATIC 2026-08-02, save-load path 0x63CCBA disasm): 0xDC08CE saved field id -> 0xCC0DEC module copy, 0xDC08D2/D4 X/Y -> DEST_X/Y, 0xDC08D6 triangle -> DEST_TRIANGLE, **0xDC08D8 direction -> DEST_DIRECTION**, 0xDC08D9/DA -> 0xCC165C/0xCC1660 (unnamed). The loader first rep-movsd's 0x43D dwords (=4340B, the whole savemap) from a staging buffer to 0xDBFD38 - loading a save enters the field through the SAME jump interface as MAPJUMP/gateways |
| `FIELD_MAPJUMP_DISABLED` | `0xCC0DBE` | modules+0x36, u8: MPJPO opcode (0xD2, handler 0x61A4D4) stores its arg raw; nonzero = gateway walk-across jumps disabled (how scenes deaden exits). PSX label confirmed by handler disasm (ff7_mpjpo_static.py 2026-08-02); the pathfinder should consult it before promising a gateway exit. Value convention live-confirm pending (v2.30.64 debug lines carry it) |
| *(world-module leads, FFNx-sourced)* | - | For a future world-nav campaign (2026-08-02, FFNx name-embedded addresses - NOT our derivation): `world_player_pos` 0xE04918 (vector4<int>), `world_map_type` 0xE045E8, `world_event_current_entity_ptr` 0xE39AD8 -> world_event_data struct (position vec4, facing s16, walkmap_type u16, direction s16, model_id - ff7.h:2333), world_update_player 0x74EA48, world_mode_loop 0x74DB8C, world_loop 0x74BE49, walkmap-type/region getters via grc(0x74EA48,0x7DF)/grc(0x767641,0x2B). Our own find: world-to-field exit writes FIELD_JUMP_INTERFACE at 0x76713B/163/172 (same globals as MAPJUMP) |

---

## 5. Field File Buffer Architecture (Confirmed 2026-06-27)

**Dialog text is embedded in section 0 (the script section) of the field file.**

FF7 field files have 9 sections (indices 0â€“8). For the bombers_start field (confirmed by runtime DIAG logging):

| Section | Offset | Content |
|---------|--------|---------|
| 0 | 0x2A | **Script** â€” entity bytecodes + dialog text strings at the end |
| 1 | 0x17EA | Camera placement data |
| 2 | 0x183A | **MODEL LOADER** â€” âš  the original "(empty/padding)" label was WRONG (corrected 2026-07-13 via the md1stin live dump, where section 2 held all 10 model entries and the walk matched FIELD_N_MODELS exactly). Format: u16 blank / u16 nModels / u16 scale header, then per model: u16-len-prefixed descriptive .char name ("md1stinshinra_hei.char"), u16 unknown, char[8] HRC, char[4] ASCII scale, u16 nAnims, 30-byte light block, nAnims Ã— (u16 len + name + u16). **Entry order = model load order = field_event_data array order** â€” entry i names model i (v2.16) |
| 3 | 0x1844 | Palette *(the June "walkmesh here" guess was WRONG â€” corrected 2026-07-16; per the community spec this slot is the palette)* |
| 4 | 0x2054 | **WALKMESH** â€” âš  June guessed "tile map"; corrected 2026-07-16: FFNx's own renderer reads the walkmesh from THIS slot (`lighting.cpp ff7_create_walkmesh`: offset at `level_data+0x16` = buf+6+4Ã—4, i.e. section index 4), which is production confirmation. Format: u32 size prefix, u32 nTriangles, then nTriangles Ã— 24-byte triangles (3 vertices Ã— s16 x,y,z,res â€” same coord space as model_pos>>12), then the ACCESS pool: nTriangles Ã— 3 Ã— u16 = neighbor triangle across each edge, 0xFFFF = wall. Access pool **CONFIRMED GAME-WIDE OFFLINE 2026-07-16** (ff7_walkmesh_route_dryrun.py: 720/720 fields, 184,358 links, 100% id-valid, 100% geometrically adjacent, 100.00% reciprocal â€” and the buffer holds the raw decompressed file, so disk bytes = memory bytes); v2.22's loader still self-guards at runtime as corruption armor. Used by v2.22 turn-by-turn directions; constants at ff7_addresses.h SECTION 1h |
| 5 | 0x22B4 | Tile map *(June guessed "encounter table"; community spec says tile map â€” unverified)* |
| 6 | 0x43B0 | (empty) |
| 7 | 0x43E4 | Triggers *(md1stin dump: raw section 7 begins with the field name, exactly like the parsed trigger header â€” the June "Background" label belonged here)* |
| 8 | 0x46CC | Background *(md1stin dump: section 8 = 385KB starting "PALETTE...BACK")* |

There is **no separate text section** in this field file. The dialog strings live at the end of section 0,
after all entity bytecodes. `field_text_box_window_create_631586` reads the text from within section 0
by `dialog_id` and stores the pointer in `DIALOG_TEXT_PTRS[window_id]`.

The buffer layout: `*(char**)0xCFF594 = buf`. Section table at `buf+6`: nine consecutive `uint32_t` values,
each an offset from buf start to the beginning of that section's block (including a 4-byte size prefix).
Section i data: `buf + *(uint32_t*)(buf + 6 + i*4) + 4`.

**`get_field_dialog_text()` behavior**: We implemented a function that searches all 9 sections for the
text section by validating the offset table format (`first_off` even, 2â€“2048 range, monotonically
increasing subsequent offsets). It skips section 0 (the script) by comparing against `field_script_ptr`.
In practice, every other section fails validation, so this function always returns nullptr and the rawptr
fallback handles all dialogs. The function remains as a correct no-op for fields that might have a
standalone text section.

**Rawptr validation**: `DIALOG_TEXT_PTRS[window_id]` points within the script section's data
(confirmed buf offsets 0xA43â€“0xC78 for bombers_start dialogs). Before using rawptr, we validate it
falls within `[field_buf, field_buf + 512KB)`. This prevents reading binary data from outside the
field buffer when the pointer is stale or corrupt.

### Save file (.ff7) slot-preview layout â€” DERIVED 2026-07-17

For the save/continue menu TTS: the slot previews the menu displays live in the save FILES
(`workingdir\save\saveNN.ff7`, one file per "Save N" grid entry, 15 slots each), so the mod parses
them from disk â€” no memory addresses needed for the data. Layout derived EMPIRICALLY from the
player's own save00.ff7 against screenshot ground truth (Cloud / Level 7 / 00:21 / 376 gil /
"No. 1 Reactor"), ff7_savefile_preview_derive.py, log savefile_preview_derive_20260717_113941:

| Offset | Field |
|---|---|
| file+0x00 | 9-byte file header `71 73 27 06 00 01 00 00 00` |
| slot base | 9 + nÃ—0x10F4 (file size 65,109 = 9 + 15Ã—0x10F4 exactly) |
| +0x00 | u32 checksum-ish (0x0000893A observed) |
| +0x04 | u8 lead character LEVEL (read 7 âœ“) |
| +0x05..07 | 3 Ã— u8 party portrait char ids, 0xFF = empty slot in party (read 00 01 FF = Cloud, Barret âœ“) |
| +0x08 | lead character NAME, FF7-encoded, 0xFF-terminated (read "Cloud" âœ“ â€” the SAVED text, renames carry automatically) |
| +0x18 | u16 curHP (222), +0x1A u16 maxHP (311), +0x1C u16 curMP (54), +0x1E u16 maxMP (57) |
| +0x20 | u32 GIL (read 376 âœ“) |
| +0x24 | u32 play time in SECONDS (read 1313 â†’ menu displays 00:21 âœ“) |
| +0x28 | location caption, FF7-encoded, 0xFF-terminated (read "No.1 Reactor" âœ“ â€” stored WITHOUT the display space) |
| empty slot | entire 0x10F4 bytes are zero (slot 1 verified all-zero while menu showed EMPTY âœ“) |

---

## 6. Dialog Detection Strategy

The MESSAGE opcode handler is called **every game frame** while a dialog window is open.
We must detect *new* dialogs without speaking on every call.

### Dialog ID Tracking (primary mechanism)

Each MESSAGE call carries two parameters: `window_id` (param[0]) and `dialog_id` (param[1]).
`dialog_id` is a stable identifier that does not change during the dialog's lifetime.
We track `last_dialog_id` per window slot. When `dialog_id != last_dialog_id`, a new dialog started.

### State Machine (secondary trigger for win=0/1)

`opcode_message_loop_code[24 * window_id]` is a state byte per window. Transitions:
- `0 â†’ nonzero` or `7 â†’ nonzero`: dialog starting â€” PRIMARY speak path
- `14 â†’ 2` or `4 â†’ 8`: page advance
- `any â†’ 7`: dialog closing â€” reset `last_dialog_id`, silence TTS

The state machine works reliably for win=0 and win=1 but **never transitions for win=2 and win=3**
(state byte stuck at 0 perpetually). Those windows rely entirely on the dialog_id tracking path.

### Two-Frame Delay

`field_text_box_window_create_631586` runs *inside* `s_old_message()`, which we call *after* reading
the text pointer. So on frame N (when `dialog_id` first changes), `DIALOG_TEXT_PTRS[window_id]` is
still stale from the previous dialog. On frame N+1, `s_old_message()` has run and the pointer is valid.

The DLGID fallback path handles this naturally: frame N fails (`rawptr` invalid or 0xFF), does NOT
update `last_dialog_id`; frame N+1 tries again, succeeds, speaks, updates `last_dialog_id`. The state
machine START path (win=0/1) works because the 0â†’1 transition happens one frame after 7â†’0, by which
time the previous frame's `s_old_message()` has already set the new dialog's rawptr.

### Preventing Duplicate Speaks

Without a guard, both PRIMARY (state machine) and DLGID paths could fire for the same dialog:
- DLGID fires on frame N (state=0, new `dialog_id`), speaks, sets `last_dialog_id`
- PRIMARY fires on frame N+1 (0â†’1 transition), would speak again without a guard

Fix: PRIMARY path checks `dialog_id != last_dialog_id` before speaking. If DLGID already spoke
this id, PRIMARY skips silently.

### Win=3 Timing Edge Case

`win=3` (TUTOR/auxiliary window) uses state 37 (not the standard sequence), and `s_old_message()`
timing is less predictable. In some runs, `DIALOG_TEXT_PTRS[3]` still holds text from the *previous*
win=3 dialog when START fires, causing the wrong text to be spoken. The DLGID two-frame delay catches
the correct text reliably. This can result in different code paths between runs (START vs DLGID) but
both produce the correct output when rawptr is valid at the time of reading.

---

## 7. Text Decoding

FF7 uses a custom 8-bit encoding. The decoder (`FF7Text::Decode`) translates to `std::wstring` for Tolk.

### Encoding Map

```
0x00â€“0xDF  :  byte + 0x20  =  encoded character
               (0x00 = space, 0x21 = 'A', etc.)
               NOTE: bytes 0x5Fâ€“0xDF map to extended Latin (U+007Fâ€“U+00FF),
               but FF7's font renders DIFFERENT glyphs. This is a known mismatch.
0xE0       :  newline (replaced with space in TTS output)
0xEA       :  Cloud (speaker token at position 0; inline name elsewhere)
0xEB       :  Barret
0xEC       :  Tifa
0xED       :  Aerith / Aeris
0xEE       :  Red XIII
0xEF       :  Yuffie
0xF0       :  Cait Sith
0xF1       :  Vincent
0xF2       :  Cid
0xEBâ€“0xF0  :  mid-string dynamic token â€” 4 bytes total (type byte + 3 data bytes)
               placeholder: [item name], [number], [target], [attack], [special], [target letter]
0xF8       :  formatting skip â€” consume this byte + 2 data bytes (3 total)
0xFF       :  end of string
```

### Speaker Token Detection

The first byte of a dialog string can be a character name token (0xEAâ€“0xF2), indicating the speaking
character. We detect this by tracking `at_start`: if the very first byte is in that range, we emit
`"CharName: "` before the dialog text. Mid-string appearances of these same bytes are inline name
references (Cloud, Barret) or 4-byte dynamic tokens (0xEBâ€“0xF0).

The 4-byte mid-string dynamic token is the key distinction: 0xEB at position 0 = "Barret:" speaker,
0xEB mid-string = `[item name]` placeholder (4-byte token). Missing this caused the `Ã¶Â­Ã¹Barret`
prefix garbage in early builds.

### Extended Character Problem (Temporary Fix)

Bytes 0x5Fâ€“0xDF add 0x20 and land in the Unicode extended Latin range (U+007Fâ€“U+00FF). FF7's bitmap
font renders completely different glyphs at those positions â€” the mapping is *wrong* for what the screen
reader will say. Examples:
- 0xB5 â†’ U+00D5 'Ã•', but FF7 renders `'` (apostrophe) â†’ "I'm" becomes "I Ã•m"
- 0xB2 â†’ U+00D2 'Ã’', but FF7 renders `"` (left quote)
- 0xB3 â†’ U+00D3 'Ã“', but FF7 renders `"` (right quote)
- 0x82 â†’ U+00A2 'Â¢', but FF7 renders `-` (hyphen)

**Temporary fix (current)**: ASCII filter â€” strip everything outside U+0020â€“U+007E, replace with a
single space to preserve word boundaries. Apostrophes become spaces ("I'm" â†’ "I m"), which is
sub-optimal but prevents garbled speech.

**Permanent fix needed**: A lookup table mapping each FF7 byte 0x5Fâ€“0xDF to the correct Unicode
character. The table must be derived from the actual FF7 font texture / character set documentation.

### 3-Byte Window Header Codes

Some dialogs begin with `0xD6 ?? 0xD9` â€” FF7 window-formatting control bytes. These decode to
extended Latin characters under byte+0x20 and appear before the speaker token, breaking speaker
detection (`at_start` becomes false before the 0xEAâ€“0xF2 check). The ASCII filter currently strips
these silently. A proper fix would require detecting and skipping bytes in the 0xD0â€“0xDF range at
position 0.

---

## 8. Build History

### v1.0 (2026-06-24) â€” First compile; crashed immediately

- Proxy: `winmm.dll`, 168 exports, 220 KB
- Crash cause: FFNx's `ff7_find_externals` uses `GetModuleHandle("winmm.dll")` as an anchor for
  machine code analysis. Got our naked JMP stub instead of real winmm code; invalid bytes caused
  `0xC0000005` access violation.
- Also: address readiness check `< 0x9FFFFF` was too narrow; FFNx-patched addresses (0x69xxxxxx)
  would never pass, so hooks would install prematurely.

### v1.1 (2026-06-24) â€” Switched to `version.dll`; still crashed

- Proxy: `version.dll`, 17 exports, 205 KB
- Crash cause: background thread's 200ms sleep was not long enough. Our hooks were installed *before*
  FFNx's `voice_init()` ran. FFNx then read our hook from the table and walked our x86 prologue as if
  it were the original opcode handler code, crashing inside `get_absolute_value`.

### v1.2 (2026-06-24) â€” Fixed FFNx timing race; first successful run

- `Resolve()` now waits for `execute_opcode_table[0x40]` to be in DLL address space (> 0x9FFFFF),
  which only happens after FFNx's `voice_init()` has patched the entry. Without FFNx, any value
  â‰¥ 0x401000 is accepted immediately.
- First confirmed TTS output: field dialog spoken via NVDA.

### v1.3 (2026-06-26) â€” First real-game test; chunking and duplicate bugs identified

- `starting` condition only checked `last==0`, missed the `last==7` reuse case. Windows reused
  directly from closed (state=7) to new dialog fired no "starting" event; subsequent dialogs on
  that window were all missed.
- Fix: `starting = ((last==0 || last==7) && current!=0 && current!=7)`.
- Debounce threshold set too high â†’ some dialogs silenced. Removed debounce in favor of dialog_id
  tracking.

### v1.4 (2026-06-26) â€” Dialog ID tracking; win=2 still silent

- Introduced `last_dialog_id` per window. Replaced debounce with "speak when dialog_id changes."
- win=2 (Barret, Jessie lines): state machine stuck at 0 permanently â†’ `starting` never fired â†’
  all win=2 dialogs silently dropped.
- Fix: added DLGID fallback that fires whenever `dialog_id != last_dialog_id`, regardless of state.

### v1.5 (2026-06-26) â€” Duplicate speak bug fixed; win=2 restored

- Duplicate root cause: DLGID fired on the state=0 frame (before START), set `last_dialog_id`.
  Then START fired on the 0â†’1 frame, `dialog_id == last_dialog_id` was FALSE (forgot DLGID had
  already spoken it), so PRIMARY spoke again.
- Fix: PRIMARY path checks `dialog_id != last_dialog_id` before speaking. DLGID guard now works
  bidirectionally.
- Added `rawptr` fallback in DLGID path: if field text section returns nullptr, try
  `DIALOG_TEXT_PTRS[window_id]`.

### v1.6 (2026-06-27) â€” ASCII filter; garbage block; section diagnostic

- Added ASCII filter at end of `FF7Text::Decode()`: strip everything outside U+0020â€“U+007E,
  replace with space. Eliminated garbled TTS from extended Latin characters and window-header codes.
- Added DIAG logging: sections 7 and 8 structure. Confirmed section 8 is NOT the text section
  (`first_off=0`, bytes `00 00 01 00 01 50`). Section 7 is background data (`first_off=27746`,
  bytes "blackb..."). Both fail validation. `get_field_dialog_text` always returns nullptr.
- win=3 TUTOR window: garbage rawptr (reading binary data) produced a large block of junk TTS.
  Filtered by ASCII filter to empty string â†’ not spoken â†’ win=3 silent.

### v1.7 (2026-06-27) â€” All field dialogs working; garbage block fixed

- Expanded DIAG to all 9 sections + rawptr offset logging. Confirmed dialog text is in section 0
  (script section). All rawptr values (buf_off 0xA43â€“0xC78) land within section 0's data range.
- `get_field_dialog_text()` updated to search all 9 sections instead of hardcoding section 8.
  Skips section 0 (script) explicitly. Monotonicity validation on first 4 offsets rejects all
  other sections. Still always returns nullptr â€” rawptr remains the only source.
- Rawptr bounds check: validate rawptr âˆˆ `[field_buf, field_buf+512KB)` before use. Garbage win=3
  pointer (which previously passed `is_readable_ptr` and decoded to junk) now rejected if it falls
  outside the field buffer.
- All dialogs in the opening mission now spoken correctly, including the previously-missing Barret
  "The hell you all doin'!?" (win=3 id=13, caught via DLGID two-frame delay path).
- DIAG logging reduced to one summary line. Diagnostic SAMEID branch removed after confirmation.

### v2.7 (2026-07-11) â€” Battle action TTS: exact names replace generic labels

Investigation chain (all scripts + logs in `investigate/`):
1. `ff7_kernel2_result_verify.py`: the doc'd result pointer 0xDC208C stays 0 through
   every battle action â€” FFNx replaces the whole flash-text consumer path, so the
   original `mov [0xDC208C], eax` stores never execute. Dead end confirmed live.
2. FFNx source (battle.cpp/voice.cpp): the "kernel2 request struct" is actually FFNx's
   `battle_actor_data` (0xDC38E0) â€” command_index/action_index written at FLASH time.
3. `ff7_kernel2_consumer_disasm.py` + `ff7_kernel2_dispatch_map.py`: full static
   derivation of dispatcher sub_6D1CC0's cmdâ†’branchâ†’section mapping, get_kernel_text
   (=sub_41963C) internals, and the bias tables (magic file entries: 0â€“55 spells,
   56â€“71 summons, 72â€“95 E.Skills, 128+ limits).
4. `ff7_kernel2_table_probe.py`: get_kernel_text's static scratch (0x9A13C8) is ALL
   ZERO in battle â€” explains why blanks came back; the text really lives in a heap
   block (`ff7_name_memory_scan.py`), with NO stable static anchor
   (`ff7_kernel2_anchor_chain.py` / `ff7_kernel2_section_ptrs.py`).
5. `ff7_action_name_final_verify.py`: signature-scan + walk-back rule
   (`u16[base] == distance-to-first-string`) locates magic/item/weapon sections;
   live battle resolved 'Tentacle', 'Machine Gun', 'Potion', 'Ice' â€” all exact.

Implementation (BattleActionThread v2.7 in proxy.cpp):
- Turn detection unchanged (actor change + commandIDâ‰ 0).
- Name-bearing commands defer the announce until battle_actor_data changes (flash
  appeared) or 2.5s timeout; struct-cmd must match model-cmd or the generic v2.5
  label is used â€” degraded, never wrong. Branch-9 commands (plain Attack, Steal)
  announce generic labels immediately (they never flash).
- Kernel2 sections found by one in-process signature scan (lazy, retry â‰¤1/min).
  English-only signatures; other languages fall back to generic labels entirely.
- Limit names carry a leading F8+param colour code â€” skipped locally (the dialog
  decoder's single-byte 0xF8 handling is correct for dialog, wrong for these).

### v2.9 (2026-07-12) â€” Battle menu navigation TTS (the battle cursor, solved)

The battle command-menu cursor â€” unsolved through three live-scanning sessions â€”
fell to static analysis in one session. Full derivation in Â§14 (battle module
block note) and Â§4 (BATTLE_* entries); investigation scripts
`ff7_battle_menu_static.py`, `ff7_battle_menu_handler_disasm.py`,
`ff7_battle_menu_submenu_disasm.py`, live verify
`ff7_battle_menu_cursor_live_verify.py` (two battles, user-confirmed:
"I think that's got it").

Implementation (BattleMenuThread in proxy.cpp, 50ms poll, gated on new config
key `speak_battle_menu`):
- **Command menu (state 1)**: speaks the command under the cursor on every
  (slot,col,row) change AND on menu open (state entry invalidates the key, so
  the landing command speaks immediately â€” that is the "your turn" cue).
  Names resolve via a NEW kernel2 section â€” command names, signature
  `"Attack|Magic|"` â€” at entry id-1 (ids are 1-based); Defend (0x12),
  Change-row (0x13), and Limit (0x14, unshifted) are hardcoded ahead of the
  lookup; GenericActionLabel is the final fallback. Empty cells (0xFF) stay
  silent: the game's own nav skips them, we only ever read one mid-move.
- **Lists (states 5/6/7)**: selected index = w0+w4+scroll; the entry's u16
  packs action index (low byte) + flags (high). The name section is chosen by
  the command that OPENED the list (BATTLE_ISSUED_CMD â†’ dispatch branch â†’
  ResolveActionName), reusing the entire v2.7 machinery including the
  item/thrown-weapon namespace split. Unknown commands degrade to "row N".
- **Targeting**: armed only on a menu-stateâ†’0 transition (state 0 is also
  plain ATB wait â€” prev-state gating is the difference between "target cursor"
  and silence), disarmed on 0xFFFF/new menu/battle exit. Speaks target labels
  on TARGET_INDEX (0xDC3C94) change: leader name for slot 0, "ally N"/
  "enemy N" positionally. Real enemy names (scene.bin): DONE in v2.10 below.
- Kernel2 scan now guarded by an interlocked busy flag â€” two threads
  (BattleActionThread + BattleMenuThread) can trigger it lazily; duplicate
  concurrent walks are wasteful though harmless, so one runs and the other
  skips to its rate-limited retry.

### v2.10 (2026-07-13): Real enemy names in battle announcements

**USER PLAY-TEST CONFIRMED 2026-07-13** (same pass also confirmed v2.9's
command menu and submenus): enemy names with duplicate-letter suffixes spoken
correctly in-game.

Target selection and enemy-turn announcements now speak the actual enemy name
("Guard Hound", "MP A") instead of positional "enemy N"/"enemy" labels â€” for
both BattleMenuThread targeting and BattleActionThread turn announces, via a
shared `EnemySlotName()` helper in proxy.cpp.

**Derivation â€” fully static, no live scan needed**: the 2026-07-11 consumer
disasm had dumped the first half of an unexplained branch inside get_kernel_text
(sub_41963C); `ff7_target_name_disasm.py` (2026-07-13) completed it and printed
the section jump table at 0x419A38, which proved sections 6â€“9 are the BATTLE
text sections: 6 = summon-attack names, **7 = TARGET NAMES (handler 0x4197D3)**,
8 = item-namespace, 9 = enemy-attack names (0x9A9484, matching v2.7). Section 7
is the exact code the on-screen targeting window renders from, so its tables
are authoritative by construction:

```
record = movsx( u16[0x9A8794 + enemy_idx*0x10] )   ; enemy_idx = actor slot âˆ’ 4
name   = 0x9A8E9C + record*0xB8, bytes 0â€“0x1F       ; 0xB8 = scene.bin record
letter = u8[0x9A8B1F + actor_slot*0x44]             ; 0xFF = unique, else
append FF7-char( dword[0x9AB070] + letter )          ; "MP A" / "MP B"
```

Implementation notes: record âˆ’1/out-of-range (scene holds 3 records) or a
blank decoded name falls back to the old generic labels; the name field can
occupy all 0x20 bytes with NO 0xFF terminator, so it is decoded per byte via
`FF7Text::DecodeChar` under the length cap (the game itself copies max 0x20
then writes its own terminator at 0x41999B) â€” never `Decode()` the record in
place. Party slots are untouched by section 7 (idx â‰¥ 6 returns the empty
default), so leader-name/"ally N" labels stay; party members 2/3 by name
remain a follow-up. Bonus finds documented in Â§4/Â§14: per-actor Sensed flag +
HP pair (a future "Sense readout" feature), per-actor status dword 0x9AB0E0,
and the game's target-name scratch buffer 0x9A80F0 (render-time only, not
pollable).

### v2.11 (2026-07-13): Sense HP readout during targeting

Target announcements now append "HP \<current\> of \<max\>" whenever the
sighted target window would show HP: party slots always (party HP is
permanently on-screen in battle), enemy slots once Sense has set their
display flag. "Guard Hound A, HP 120 of 460". `TargetHPText()` in proxy.cpp,
spoken by BattleMenuThread's targeting path; no new config key (it is part
of `speak_battle_menu`).

**Derivation â€” fully static again** (`ff7_sense_hp_static.py`): the missing
piece from v2.10 was WHICH battle struct the Sense path's HP word `0x9AB10C`
belongs to. FFNx's own resolution chain (`battle_context =
get_absolute_value(battle_sub_41CCB2, 0x5F)`) read off the exe gives
`battle_context = 0x9AB0A0` â†’ `actor_vars[0] = +0x3C = 0x9AB0DC`, stride
0x68 = exact `sizeof(battle_actor_vars)` from FFNx ff7.h. Cross-checks that
all landed: the operand sits inside `mov edi, 0x9AB0A0 / rep stosd` â€”
sub_41CCB2 is the battle-state init memset, and its sibling memsets clear
exactly the v2.10 regions (formation slots, enemy records, attack names);
and with this base, section 7's two unexplained reads become named fields
(`0x9AB0E0` = stateFlags+0x04, `0x9AB10C` = maxHP+0x30 low word â€” so the
window's "cur/max" takes cur from the display struct's u16 cache at
`0x9A8B4C+slotÂ·0x44` and max from actor_vars).

The mod reads the full i32 `currentHP`/`maxHP` pair at +0x2C/+0x30 instead
of the game's u16 display words (Ruby/Emerald-class HP would truncate), and
gates on the Sensed flag byte `u8[0x9A8B39 + slotÂ·0x44] & 0x40` for enemies
â€” exact information parity with the sighted window. Plausibility gate
(max in (0, 10M], 0 â‰¤ cur â‰¤ max) drops garbage during battle init. MP
(+0x28/+0x2A u16) is available in the same struct if a Sense MP readout is
ever wanted.

### v2.12 (2026-07-13): Enemy defeat announcements + Sense-gate override

Two user requests after the v2.11 play test (user has no Sense materia yet):

1. **`speak_enemy_hp_always` config key** (default false): overrides the
   Sense parity gate in `TargetHPText` so enemy HP speaks during targeting
   without Sense. Added to the shipped cfg template; set to TRUE in both
   installed configs for the user's testing (documented inline there).
2. **Enemy defeat announcements** ("Guard Hound A defeated"): a liveness
   watcher in BattleActionThread (gated on `speak_battle`, GAME_MODE==2)
   polls each enemy slot's actor-vars every 50ms. Death = `currentHP <= 0`
   (primary) OR statusMask bit 0x01 = kernel Death status (secondary), and
   only announces after the slot was previously SEEN alive (plausible max HP,
   cur > 0, no Death bit) â€” battle-init memset zeroes and empty formation
   slots can therefore never false-positive; the tracker resets whenever
   GAME_MODE leaves 2 (between battles). Names via v2.10's EnemySlotName
   with "enemy N" fallback. Bonus static confirmation this session: PSX
   decomp battle.h `SceneEnemy \ size:0xB8` matches the v2.10 enemy-record
   stride exactly.

**USER PLAY-TEST CONFIRMED 2026-07-13** (after v2.12.2): enemy HP without
Sense and "defeated" announcements both working in-game.

**v2.12.1 fix â€” defeats must speak in a QUIET GAP, not at detection.** The
first play test heard no defeats; the debug log showed detection perfect but
the speech cancelled within the same millisecond: the killing blow's tick
also fires action announcements (pending-flash resolution + next-turn), and
their interrupt=true wipes queued speech â€” every time, reproducibly (two
kills, two identical traces). Detected defeats now accumulate in a pending
string and speak (interrupt=false) once no thread has issued ANY speech for
600ms (new cross-thread stamp `TTS::LastSpeakTick()`), with a 5s overdue cap
and an immediate flush on leaving battle so a battle-ending kill is never
dropped. **v2.12.2 completed the fix**: the first quiet-gap version passed
its test AT the death tick (nothing had spoken for 2.2s BEFORE it) and got
cancelled by the burst that follows microseconds later in the same
iteration â€” the gap must be measured FORWARD from detection too (pending
defeat must itself be â‰¥600ms old). General lesson recorded: **any
low-priority battle announcement must use this two-sided quiet-gap
pattern** â€” the battle threads' interrupt=true bursts arrive in same-tick
clusters, and the triggering event IS the burst. (Same trace also showed
the phase-2 flush "MP B, attacks" being instantly clobbered by "Cloud,
Attack" â€” fixed in v2.13 below.)

### v2.13 (2026-07-13): Chained action announcements (enemy actions no longer clobbered)

The v2.12 traces showed BattleActionThread's own announces clobbering each
other: the pending-flash flush ("MP B, attacks") and the next turn's
announce ("Cloud, Attack") fire in the SAME 50ms tick, and the second's
interrupt=true cancelled the first before a syllable played â€” enemy actions
were routinely inaudible whenever the player's turn arrived at the same
instant. Fix: an announce within ANNOUNCE_CHAIN_MS (1500ms) of the previous
one now queues (interrupt=false) behind it instead of interrupting â€” the
player hears "MP B, attacks" then "Cloud, Attack" in sequence. Announces
farther apart keep interrupt=true (a fresh turn SHOULD cut off stale
speech). Debug log marks chained announces with "chained".

Party-KO announcements added to TODO.txt with full implementation notes
(same watcher + quiet-gap patterns; deferred at the user's request until
their party has more members to test with).

### v2.14 (2026-07-13): Field PATHFINDER â€” first interactable-tracking feature

A destination browser on the FF1-6 accessibility mods' key scheme (source
of truth: `accessiblity_keys.txt` at the repo root â€” **key parity with the
FF4 screen-reader mod is a standing project requirement**, recorded in
memory feedback_key_parity): J/L (or [/]) cycle destinations, Shift+J/L
(or -/=) cycle categories (All/Exits today), K announces the selection,
Shift+K resets to All, \ or P speaks directions ("Exit 2: up-left,
3 seconds" â€” d-pad terms, seconds of walking), M announces the map name.
Destinations are numbered by gateway slot order so "Exit 2" keeps its name
as the player moves. New FieldNavThread in proxy.cpp; config key
`pathfinder_keys` (the original same-day name `field_exit_scan` â€” a
one-shot N-key scan â€” was reworked to this scheme within hours when the
user supplied the key file; the old cfg key parses as an alias).
Unmapped FF4 keys and their prerequisites are listed in TODO.txt.

**Direction calibration (same day)**: first play test reported directions
reversed ("down" for an exit dead ahead) and the NAV calib log lines
solved it in one read â€” Up moved the player at world bearing 5.6Â°, Down at
âˆ’174.4Â°, with control_dir 174.4Â°, i.e. **control_direction is the world
bearing of screen-DOWN** and screen angle = world + control âˆ’ 180 (the
guess had been world âˆ’ control: 180Â° off). M announcing "md1stin"
confirmed the header field-name read (that IS the internal field name;
friendly names via the savemap location string are a TODO).

**PLAY-TEST CONFIRMED same day**: after the rotation fix the user confirmed
directions correct INCLUDING left/right â€” the mapping is a pure rotation,
no mirror (the mirrored-candidate debug output was removed). Known accepted
limitation: story-locked exits are still listed (detection routes in
TODO.txt: gateway unknown bytes +0x14, or show_arrow_flag[12] at header
+0x1B8 for arrow-visibility parity).

### v2.15 (2026-07-13): People category in the pathfinder

The destination browser gains its third category: **People** â€” every
non-player model standing on the walkmesh (field_event_data array, the
same structs the v2.6 wall tone reads). Party members' field models are
announced BY NAME via the struct's character_id (+0x6C, 0-8 â†’ Cloud..Cid);
everyone else is "Person N" numbered by MODEL SLOT, so a person keeps
their number as models around them come and go. Off-mesh models
(field_triangle_id +0x78 < 0 â€” hidden/despawned) are filtered out. A
person is stored as a degenerate exit line (both vertices = its position)
so the direction/distance math is shared unchanged; positions re-read at
every query, so moving NPCs track correctly. Struct offsets are anchored
by the live-verified movement_speed +0x76 (v2.6). Debug log prints every
model's tri/char/entity/talk/pos when enabled â€” the dataset for future
refinement (talk_radius gating, save-point identification).

**v2.15.1 â€” wandering cue** (user request, same day): the thread samples
every model's position each 50ms poll; announcing (J/L/K/\) a person who
moved within the last second appends a short 880Hz/70ms beep (distinct
from the 220Hz wall tone) â€” the cue that the target is WALKING and the
spoken direction is a snapshot. Tracker resets on field change so the
position jump between fields can't read as movement.

**USER PLAY-TEST CONFIRMED 2026-07-13** (after v2.15.2): categories,
counts, People browsing, and the wandering cue all working as intended.

### v2.16 (2026-07-13): Model names + Save points category

**USER PLAY-TEST CONFIRMED 2026-07-14: the model-loader people names are
correct in-game.** The Save points category remains heuristic-only â€” the
player has not yet reached a field with a real save point (see TODO).

The pathfinder now names people from the field file's MODEL LOADER section
(raw section index 2 â€” the June Â§5 dump had mislabeled it "(empty)"; the
md1stin live dump decoded the full format, see Â§5). The .char entries carry
DESCRIPTIVE developer names that strip to speakable labels: "main ballet"
(Barret), "shinra hei", "midgal avawoman", "shinra guard"... Duplicates get
slot-order ordinals ("shinra guard", "shinra guard 2", "shinra guard 3" â€”
same idea as the battle MP A/B letters). Parse failure falls back to
"Person N". `FieldModelLabel()` in proxy.cpp walks the section with every
step bounds-checked against its size prefix; the walk was live-verified
model-for-model against md1stin (ff7_field_models_verify.py: 10/10 labels
clean, walk ended exactly at the section boundary).

Fourth category **Save points**: a model whose label contains "save" is
classified as a save point (named "Save point", excluded from People).
~~âš  HEURISTIC until the player reaches the first real save point~~
**CONFIRMED game-wide 2026-07-14 by the v2.18 offline flevel catalog**:
"fieldbg saveicn" (HRC AVFE.HRC, Ã—57) is the ONLY label containing "save"
across all 720 field files â€” the substring match is exact, not heuristic.

**v2.15.2 â€” two play-test bug fixes** (same day):
1. character_id naming REMOVED: an ordinary reactor NPC announced as
   "Red XIII" â€” the +0x6C field carries 0-8 values for regular NPCs too
   and is NOT a party-membership indicator (Â§4 row amended). Everyone is
   "Person N" again; a validated naming signal is a TODO.
2. Category-change counts were direction-dependent ("Exits, 6" via
   Shift+J but "Exits, 8" via Shift+L): the destination list was built
   BEFORE key dispatch, so a category switch announced the count of the
   list built for the PREVIOUS category. State mutations (field-change
   reset, category changes) now happen before the build, and the
   announcement uses the list actually built for the new category.

**Derivation â€” fully static** (`ff7_field_triggers_static.py`): the engine's
parsed field-file section 8 sits behind ONE global, FFNx's
`field_triggers_header`. FFNx resolves it from `field_main_loop` (needs a
live game object â€” the old session-3 dead end), but `field_sub_6388EE`'s
NAME embeds its address, so the chain anchors there and self-validates via
THREE other name-embedded FFNx externals resolved off the same function
(0xCFFE3C, 0xCFF3D8, 0x623C0F â€” all matched):
`FIELD_TRIGGERS_HEADER_PTR = 0xCFF454`, landing in the known 0xCFF3xx-0xCFF5xx
field-statics cluster exactly as Â§14's cluster rule predicts.

Three deliberate design choices:
- **control_direction (+0x09) instead of the camera matrix**: the header
  byte is the per-field rotation the ENGINE applies to d-pad input, so
  subtracting it from the world bearing yields the d-pad direction to press
  â€” no 3D math against 0xCFF3D8 needed. (Also unblocks the deferred
  wall-slide feature, which stalled on exactly this inputâ†’world mapping.)
- **Coordinate scale from FFNx's own code**: model_pos Ã· 4096 = walkmesh
  coords (background.cpp), so player pos >> 12 compares directly to gateway
  vertices; v2.6's measured 32768 highres units/50ms walk â†’ 160 walkmesh
  units/sec for the seconds estimate.
- **Distance to the nearest point of the exit LINE SEGMENT** (2D, Z
  ignored), not to a vertex â€” exits are walked into anywhere along the line.

âš  Direction sign/zero convention is PROVISIONAL until one play test: the
debug log prints both candidate rotations (worldâˆ’ctrl vs world+ctrl) per
gateway plus a once-per-second input-vs-motion calibration line while
walking â€” one debug-logged walkabout pins the true convention if the first
guess reads wrong.

### v2.17 (2026-07-14): Triggers category â€” LINE trigger zones

**USER PLAY-TEST CONFIRMED 2026-07-14 (same day): the Triggers category
works and trigger zones are announced correctly in-game.**

Fifth pathfinder category **Triggers**: the script-created LINE zones
(ladders, elevators, touch/cross zones) that sighted players infer from
scenery. Lines are real segments, so the exit direction/distance math is
reused unchanged; disabled lines (LINON 0) are skipped for information
parity (the zone would do nothing for a sighted player either). Each line
speaks its owning entity's 8-char dev name from the section-0 entity-name
table ("evb", "drE") â€” the v2.16 model-naming trick applied to script
entities â€” falling back to "Trigger N" by array slot.

**Derivation â€” fully static in one pass** (`ff7_line_triggers_static.py`):
resolved `execute_opcode_table` from the exe ON DISK via the mod's own
Resolve() chain (grc(0x60BACF,0x80) â†’ gav(^,0x10D) = 0x9055A0; validated by
FFNx's own MESSAGE-handler check, E8 CALL at table[0x40]+0x3B), then
capstone-disassembled the three line opcode handlers. All three agree on
one array (see Â§4 FIELD_LINE_ARRAY row) â€” LINE 0x6111D8 creates (flag=1,
entity id stamped, count++ at 0xCC088C, cap 0x20), LINON 0x6115AD writes
its arg to the same +0x0C flag, SLINE 0x6114D0 rewrites the same six
vertex words. Bonus finds from the same listing: the LADER handler
confirmed field_event_data +0x63 movement-phase byte and +0x7C/+0x80/+0x84
as the <<12 movement target â€” and script arg coords are plain walkmesh
units (LADER shifts them <<12 before comparing to model_pos), which is why
the line vertices compare directly to player pos >> 12.

**LIVE-VERIFIED same day** (`ff7_line_triggers_verify.py`, read-only
attach while the player walked the reactor route): fields 116â€“119 report
0 lines, field 120 reports 2 â€” both enabled, sane on-mesh segments at
plausible distances, entity ids < nEntities, names 'evb'/'drE' clean
ASCII via the +0x20 table, count stable on field re-entry. Every check
green on the first run; no code changes needed after verification.

Design note: the browse read is gated on GAME_MODE==0 like the rest of
the pathfinder; a keypress racing a field transition can at worst read a
stale line once (bounds are enforced by the 0x20 cap on both count and
index). Lines don't participate in the wandering-cue tracker (SLINE moves
are rare scripted events, not continuous NPC motion).

### v2.18 (2026-07-14): Items category â€” chests, materia, pickups, keys

Sixth pathfinder category **Items**, classified from the COMPLETE game
dataset rather than play-collected guesses: a new offline pass
(`ff7_flevel_models_catalog.py`) parses flevel.lgp directly â€” LGP TOC,
LZS decompression with early stop at the end of the model section, then
the exact v2.16 model-loader walk â€” and catalogs every model label in all
720 field files (557 distinct labels). The developer convention fell
straight out: interactable props are prefixed **"fieldbg"**, and item
props use consistent role words:

| Label pattern | Meaning | HRCs | Count |
|---|---|---|---|
| `fieldbg trb wood/mety/glow/metb`, `trbox k` | treasure chests | AVHE/BYDD/AWAE/HRCE/HJGA | ~110 |
| `fieldbg mtra3â€“8`, `hmtra`, `kuromtra*` | materia orbs | ATEB/BYIB/DABF/AWBE/AUDE/CTBE/â€¦ | ~70 |
| `fieldbg potion` (+b/g/r/1â€“4 variants) | pickup bottles | CCHA/BYGF/DCFB/FAAE/FABE/FABB/FSDD/FADC | ~50 |
| `fieldbg sparkle` | sparkle pickups | GWIB | 4 |
| `fieldbg key`, `fieldbg coralkey` | key items | EOAC/HOBD | 4 |
| `fieldbg saveicn` | save points | AVFE | 57 |

No other label in the game contains "trb"/"mtra"/"potion"/"sparkle"/
"key"/"save" â€” so `fieldbg` + substring is EXACT classification, and the
v2.16 save-point heuristic is retroactively confirmed. Spoken names are
friendly ("Chest", "Materia", "Item" for bottles/sparkles â€” the bottle
model is only the visual, the script decides the actual item â€” "Key"),
and the existing duplicate-ordinal pass yields "Chest 2"/"Materia 3".
Items are excluded from People; each model belongs to exactly one of
Save points / Items / People.

**State tracking**: collected FLOOR pickups (potion/materia/sparkle/key)
despawn â€” the existing off-mesh filter (triangle_id < 0) drops them from
the list automatically, so "still listed" = "still collectible", exact
parity with what a sighted player sees. Chest lid state: v2.18.1 below.

### v2.18.1 (2026-07-14): "Chest, opened" â€” lid state live-derived

Same-day follow-up at the player's first chest (nmkin_1, "fieldbg trb
mety", model slot 8). `ff7_chest_state_watch.py` diffed the chest's FULL
field_event_data (0x88B) + field_animation_data (0x190B, ptr 0xCFF738 â€”
address doubly confirmed: FFNx ff7.h comment AND our own LADER-handler
disasm reads it with the same 0x190 stride) across the open event,
against a stand-still baseline that auto-excludes churning bytes.

The open left 4 persistent changes; FFNx's struct names decode them: the
chest "opens" by playing its single lid animation to the end and HOLDING
(currentFrame 0â†’0x1D0, lastFrame 0â†’0x1D = frame 29) while the glow
effect flips off (apply_kawai 1â†’2, anim kawai_opcode 0x0Dâ†’0xFF).

`ff7_chest_reentry_check.py` then established the state matrix. FIRST
RUN WAS INVALID â€” the game had been restarted in between (pid changed)
and the "open" reference actually read closed; the guard added after
that lesson (refuse to proceed until the open values are observed in the
CURRENT session) made the second run clean:

| | apply_kawai | currentFrame | lastFrame | kawai_opcode |
|---|---|---|---|---|
| closed | 1 | 0 | 0 | 0x0D |
| just opened | 2 | rampsâ†’0x1D0 | 0x1D | 0xFF |
| leave+return (same session) | 0 | 0x1D0 | 0x1D | 0 |

**THE SIGNAL: lastFrame (+0x6A) != 0 = opened** â€” the field init script
re-poses looted chests open from savemap flags, so it also catches
chests opened in previous sessions. The glow bytes read differently in
all three states â€” never use them. The mod appends ", opened" AFTER the
ordinal ("Chest 2, opened") so chest numbering stays stable when a chest
opens (identity-stability rule). âš  Confirmed on the metal variant;
wood/glow variants share the script mechanism, expected identical
(TODO.txt watch item). v2.18.2 tightened the test to lastFrame != 0 AND
currentFrame == lastFrame<<4 (held at final frame) â€” see below.

### v2.18.2 (2026-07-14): code-review fixes (8 angles, 21 verified findings)

A full /code-review pass over v2.17â€“v2.18.1 (8 finder angles, per-cluster
verification) surfaced 2 CONFIRMED behavior bugs, 3 PLAUSIBLE risks, and a
set of verified cleanup items â€” all fixed:

1. **Ordinal stability across despawns (CONFIRMED)**: duplicate ordinals
   were counted over currently-eligible models only, so collecting "Item"
   silently renamed the surviving "Item 2" to "Item". Labels/class are now
   assigned to ALL labeled models and ordinals count eligible-or-not, so a
   despawned pickup keeps reserving its ordinal. Corollary (accepted): a
   never-on-mesh labeled model can make a field list "guard 2" with no
   "guard" â€” slot order IS the identity.
2. **Trigger duplicate names (CONFIRMED)**: two same-named lines spoke
   identically. The trigger build now gathers first, then emits with the
   same ordinal scheme as people/items ("ev1", "ev1 2").
3. **Entity-name read hardening (PLAUSIBLE crash risk)**: the old
   FieldEntityName probed only the script base page and name+7. Split into
   FieldEntityNameTable (resolves + span-validates header AND the whole
   name table ONCE per build â€” also the review's efficiency fix) +
   EntityNameFromTable. New shared IsReadableSpan() walks every region of
   a span; it replaced the ~9 inline single-byte VirtualQuery probes in
   the nav path (wall-bump/battle threads untouched).
4. **Chest false-open narrowing (PLAUSIBLE)**: is_open now requires
   lastFrame != 0 AND currentFrame == lastFrame<<4 (lid HELD at final
   frame â€” true in both confirmed open states), so a non-lid animation
   that returns to rest can't read as opened; residual risk flips to a
   missed "opened" (safer direction).
5. **Cross-field stale-name guard (PLAUSIBLE)**: a line is only NAMED when
   the engine's own entityâ†’slot map (0xCBF600) confirms the slot belongs
   to that entity; mismatches (mid-transition staleness, or an entity that
   re-declared its line) fall back to "Trigger N" instead of a
   plausible-but-wrong dev name. Stale geometry for one keypress remains
   the accepted v2.17 tradeoff.
6. **Classification altitude (CONFIRMED)**: one ClassifyModelLabel()
   returns {class enum, friendly name}; CategoryForModelClass() makes the
   emit filter a single comparison (the old sv/it boolean chain and the
   wcscmp(friendly, L"Chest") state-on-display-string coupling are gone).
   Sanitize policy unified: both name readers now REJECT non-ASCII data
   (FieldModelLabel used to speak a truncated prefix).
7. **Catalog evidence machine-checked (CONFIRMED)**: the flevel catalog
   now validates its parse against the 10 live-dumped md1stin labels
   (exact order) and asserts the shipped classifier substrings
   (save/trb/mtra/potion/sparkle/key) appear ONLY in fieldbg props,
   exiting nonzero on failure. Re-run 2026-07-14: both checks PASS on the
   real archive. Dead code removed from the investigation scripts (unused
   OPEN dict, summary dict, md1 placeholder, tautological condition) and
   all five now restore stdout/close the log via atexit (script-logging
   rule compliance).
8. **Docs-rule omissions**: 0xCFF738 added to Â§4 + Â§14 field-statics
   cluster; LINE/LINON/SLINE/LADER handlers added to Â§14's code table;
   technique ranking updated (offline data catalog + opcode-handler
   disasm entered at ranks 2â€“3).

### v2.19 (2026-07-15): Real party names everywhere â€” "ally 2" retired

Play-test report (reactor run): Barret was announced as "ally 2" in every
battle. Root cause: only party slot 0 had a name source (PARTY_LEADER â†’
hardcoded defaults); slots 1-2 were positional.

**Address derivation, no scan needed** (both anchors already in Â§1b of
ff7_addresses.h from the 7thHeaven.var work): the equipment blocks start at
savemap+0x70 with the weapon byte first, and the community savemap struct
puts weapon at record offset 0x1C â†’ records start at savemap+0x54, stride
0x84. Nine records end at exactly savemap+0x4F8 â€” precisely where the same
community layout puts the three party-member ID bytes. Two independent
anchors agreeing pins SAVEMAP_CHAR_RECORDS (0xDBFD8C) and
SAVEMAP_PARTY_IDS (0xDC0230) without a live scan.

**Runtime self-verification instead of a Frida session**: party slot 0 IS
the leader by definition, so PartySlotLabel() only trusts the derived
array while u8[SAVEMAP_PARTY_IDS] == u8[PARTY_LEADER] (0xDC09E5, live-
proven since v2.7). On mismatch every caller falls back to the old
positional labels â€” a wrong name can never be spoken by a wrong layout.

Changes:
1. **SavemapCharName(id)** (proxy.cpp): decodes the 12-byte FF7-encoded
   name from the character's savemap record â€” the LIVE name, so player
   renames carry through. Flashback aliases mapped (9=Young Cloud â†’ Cait
   Sith's record, 10=Sephiroth â†’ Vincent's record, community-documented).
2. **PartySlotLabel(slot)** shared by BattleActionThread (actor labels)
   and BattleMenuThread (target labels): savemap name â†’ default English
   name (blank savemap, i.e. no save loaded) â†’ "ally N" (guard failed /
   empty slot / unknown ID).
3. **Dialog tokens speak live names too**: FF7Text gained a NameProvider
   callback (registered in InitThread) so speaker prefixes ("Barret:"),
   the mid-string 0xEA Cloud token, and 0xF1/0xF2 (Vincent/Cid) all read
   the savemap â€” closing the old "v2: read from savemap" TODO in
   ff7_text.cpp. Decoder stays memory-agnostic; defaults remain the
   fallback while no provider is set or the record is blank.
4. Three duplicate hardcoded name tables collapsed into one
   (FF7Text::DefaultCharName).

### v2.20 (2026-07-15): Dev-label translation â€” People and Triggers speak English

User request: field People/Trigger names were developer shorthand ("main
ballet", "shinra hei", "ladd0"). Both TODO.txt residuals had planned a
translation table built "from the complete label list"; this ships it.

**New evidence artifact**: investigate/ff7_flevel_entity_names_catalog.py â€”
offline game-wide catalog of SCRIPT ENTITY dev names (section 0 header
walk over all 720 fields in flevel.lgp; companion to the v2.18 model
catalog). 2412 distinct names / 1582 digit-stripped stems
(flevel_entity_names_20260715_122652.log). Validation: nmkin_2 (the
reactor ladder field the player is on this week) parsed to
['dir','time','timeo','cl','av j','ladu0','ladd0','slp0'] â€” the ladder
lines themselves, plus Jessie as 'av j' (which also anchored
'ava*' = AVALANCHE, naming the station trio models Biggs/Jessie/Wedge).

**TranslateDevLabel / TranslateEntityName** (proxy.cpp): labels split on
spaces; tokens stripped of leading/trailing digits; single-char stems
dropped; character stems ("ballet", "cait", "ycl", "fearith") resolve
through the v2.19 live savemap names (renames carry through); a ~150-stem
word table translates romaji/shorthand ("hei"â†’soldier, "narazu"â†’thug,
"ladd"â†’ladder down, "ladu"â†’ladder up, "slp"â†’slide, "takara"â†’treasure,
"esca"â†’escalator, "av j"â†’Jessie); category/location prefixes
(main/std/midgal/â€¦) drop; UNKNOWN words speak their stem unchanged â€”
a wrong translation is worse than a terse one (v2.18.2 principle).
Applied to People labels (before the ordinal pass, so duplicates group on
the SPOKEN name: "man", "man 2") and Trigger entity names. Items/Save
friendly names and classification are untouched (raw-label substrings).

**Verified by full-catalog dry run** (scratchpad replica of the C++ over
all 557 model labels + all 2412 entity names) before shipping; the dry
run caught the draft appending raw tokens instead of stems ("man6") and
supplied a second batch of stems (zax/mizu/mihari/shain/baba/turara/â€¦).

Watch items in TODO.txt: Biggs/Jessie/Wedge model reuse on later fields
(cargoin), and the ladu/ladd = up/down reading.

### v2.21 (2026-07-15): Right-analog-stick pathfinder input

Documented in gamepad.h (full native-function evidence trail) rather than
here: the right stick + R3 drive the same destination browser as the
keyboard keys. User play-test confirmed same day.

### v2.22 (2026-07-16): TURN-BY-TURN directions over the walkmesh

User direction: "get turn-by-turn directions into the navigation system;
keep as-the-crow-flies and let the user choose." The FF4 screen-reader mod
(accessiblity_keys.txt, the binding parity source) already treats `\`/P as
a *validated step-by-step path* when in range with straight-line as the
out-of-range fallback â€” so turn-by-turn on the SAME key with a config
style switch is parity-correct, no new bindings.

**Data source** (Â§5 table, section index 4): the raw field file's walkmesh
â€” triangle pool + ACCESS (adjacency) pool. Count/triangle layout is
production-confirmed by FFNx's renderer; the access pool was **confirmed
game-wide offline the same day** (see the dry run below). `LoadWalkmesh`
still self-guards it (every neighbor id in range, â‰¥90% of directed links
reciprocal) and any failure falls back to straight-line â€” fail-closed,
never a confidently wrong route.

**Pipeline** (proxy.cpp, all per-keypress, nothing cached): snapshot mesh â†’
start = player's live triangle (`+0x78`), goal = target model's triangle
(exact even on stacked layers) or 2D point-location for exits/LINE zones â†’
A* over the adjacency graph (centroid costs, linear-scan open set â€” fields
are a few hundred triangles) â†’ portals between path triangles recovered by
GEOMETRIC shared-vertex match (deliberately not by the access pool's
edge-order convention, the one fact runtime can't verify) â†’ funnel
algorithm (string pulling) so corners exist only where the route bends â†’
legs quantized to the 8 d-pad sectors via the play-test-confirmed
`world + control_direction âˆ’ 180` rotation, same-sector legs merged,
sub-step jogs folded into their predecessor (first move never folded â€”
it's the move the player makes now), max 5 moves spoken:
"Exit 2: up 4 seconds, then right 2 seconds."

**Style choice**: `direction_style = turns` (default) `| line` in the cfg.
`line` is exactly the pre-v2.22 announcement. In turns mode, a healthy
mesh with NO route (story-locked area, other layer group) speaks
"No walkable path found." + the straight line â€” information parity with
the FF4 mod's out-of-range message; an unreadable mesh falls back
silently.

**Offline dry run** (investigate/ff7_walkmesh_route_dryrun.py, 2026-07-16
â€” the v2.18-catalog/v2.20-dry-run method): parsed all 720 fields'
walkmeshes from flevel.lgp (same bytes FIELD_FILE_BUFFER holds) and
**CONFIRMED the access pool game-wide**: 184,358 directed links, 100% of
ids in range, 100% geometrically adjacent (every named neighbor shares an
edge), 100.00% reciprocal (2 one-way links in the whole game). The run
also replicated the exact C++ route pipeline and **caught a real bug
before it ever reached the game**: `Tri2` is cross(ab,ac) = the NEGATIVE
of Recast's `triArea2D`, so the funnel comparisons needed their signs
flipped â€” unfixed, 9 of 11 demo routes zigzagged with corners at nearly
every portal ("left 1 second, then right 2 seconds, then leftâ€¦") and
taut > midpoint lengths. After the flip: 0 problems, every taut path â‰¤
midpoints, md1stin's 30-triangle crossing speaks as "up 12 seconds, then
up-left 1 second", and nmkin_2's ladder-separated levels correctly
report NO PATH between layers (the ladder is a Triggers destination â€”
exactly the announcement a blind player needs).

**Status**: builds clean (/WX); dry-run-verified; PENDING PLAY-TEST for
route QUALITY only (do spoken turns land where walls are â€” data
correctness is settled). debug_log writes a `NAV route` line
(tris/start/goal/path/corners + spoken text) per request.
LIVE PARTIAL CONFIRMATION 2026-07-16 (first session log): on nmkin_2 the
loader parsed `tris=175` â€” exactly the dry run's triangle count â€” and a
same-triangle route spoke "very close"; guards passed. A multi-turn route
has not been exercised in-game yet.

### v2.22.1 (2026-07-16): battle-menu garbage fix â€” kernel2 sections revalidated per use

User bug report, same session that live-ran v2.22: after "Grunt B
defeated", TTS spoke binary garbage ("-Ã›+! ' $ â€¦" â€” bytes 0x01-0x18
decoded through the FF7 table). The debug log identified it in one line:
`BMENU cmd slot=0 col=0 row=0 id=0x01 => <garbage>` â€” the battle menu's
COMMAND-name announce (`CommandMenuName(0x01)`), on every menu open in the
affected battles.

**Root cause** (log forensics): the 12:16 kernel2 scan found
magic/item/weapon (stable at 0x232Bxxxx all session) but
`command=00000000` (not decompressed yet â€” menus spoke "Attack" via the
generic fallback, correct). The 12:20 rescan cached `command=0x0BD39985`.
That allocation is TRANSIENT: it held the real command-name table in some
battles ("Attack" spoke correctly at 12:20 and 12:31) and freed-and-reused
binary in others (garbage at 12:27, 12:28, 12:46 â€” three DIFFERENT
garbage strings, proving live-changing memory). v2.9's "kernel2 stays
resident, one scan is permanent" assumption is true for the main kernel2
block but FALSE for the command section, which the battle menu module
evidently rebuilds per battle. `SectionEntryText`'s structural checks
(table size, offset range, non-blank) cannot reject reused binary.

**Fix**: `ValidatedSection()` (proxy.cpp) â€” before EVERY lookup, re-verify
the section's head signature: u16[base] must point at the exact encoded
first strings the scanner matched ("Attack|Magic|" etc.), the same
self-validating rule FindSectionBase used at discovery, now applied at
read time (readability-probed with IsReadableSpan first). On mismatch the
cached pointer is NULLED (logged: "kernel2 section STALE"), the
rate-limited rescan re-finds the live copy, and the caller speaks its
generic label â€” degraded, never garbage. Applied to ALL FOUR sections
(command via CommandMenuName; magic/item/weapon via ResolveActionName),
since the same reuse class could bite any of them. Cost: one ~13-byte
encode+memcmp per menu/action event.

Deployed to the 2026 install 2026-07-16 13:03. Expected observable
behavior in affected battles: command menu says "Attack"/"Magic"/â€¦ from
the fallback table instead of garbage, and the log shows the STALE line
followed by a successful rescan when the section is live again.

### v2.23 (2026-07-16): journey planning ("which ladder first?"), screen-change cue, "up and left"

User play-test feedback on v2.22 (turn-by-turn CONFIRMED WORKING in-game:
"turns do seem to land at the walls" â€” the session log shows multi-turn
routes all through the reactor). Three items:

**1. Diagonals spoken "up and left"** (was "up-left"): the hyphenated
forms were confusing; "and" states directly that the move is both arrows
held together. One string-table change (kDpadSectors), applies to both
direction styles.

**2. Screen-change announcement** ("Screen: nmkin 2", new cfg key
announce_map_change, default true): the user experienced directions
"shifting as if the perspective changed" â€” which is exactly what happens:
each field has its own fixed camera and its own control_direction, so
crossing an exit rebases what "up" means. Sighted players get the camera
cut as their cue; this is the audio equivalent, spoken (interrupt=false,
queues politely) the first poll after field control returns on a new
field id. Also fires for the first field after launch â€” an orientation
freebie. Underscores speak as spaces.

**3. Cross-layer JOURNEY planning** (the user's request: "where I need to
traverse ladders, indicate which one is first, second, etc."): when a
direct route fails because the target is on another walkmesh COMPONENT
(levels are disconnected by design; the join is a scripted LINE trigger
that MOVES the player), the mod now BFS-es a component graph whose edges
are CONNECTOR pairs: two enabled LINE triggers on different components
whose XY midpoints are within 300 units â€” the ladder bottom/top zone
pattern, measured on the user's own nmkin_2 session log ('ladder up'
bottom line to 'ladder down' top line: 134 XY units, 217 height units).
Lines whose own endpoints span components count too. The announcement
walks the player to the FIRST connector with a normal turn-by-turn route
and names the rest in order: "Exit 1: on another level. First take
ladder up, up and right 3 seconds. Then slide. Then ask again." No
connector chain â†’ the old "No walkable path found." + straight line
(correct for regions entered only from another screen, e.g. nmkin_2's
slide platform). PREREQUISITE PLUMBING: the walkmesh snapshot now keeps
centroid HEIGHT, WalkmeshLocate takes a z and scores xyÂ² + dzÂ² (stacked
layers resolve to the layer the point is on â€” also upgrades exit/trigger
goal location generally), and NavDest carries line endpoint heights.

**Offline validation** (journey sim appended to
ff7_walkmesh_route_dryrun.py, using the REAL nmkin_2 trigger lines from
the live log, since LINE triggers are runtime script state): nmkin_2 =
3 components; z-aware location puts ladder-up on comp 0 / ladder-down on
comp 1 / slide on comp 2; the pair rule finds exactly the ladder
connector (134 < 300); a lowerâ†’upper journey speaks the full message;
lowerâ†’slide-platform correctly reports no chain. Run clean, journey sim
OK, all v2.22 invariants still green.

Deployed to the 2026 install 2026-07-16 13:27 (installed cfg updated with
the two new keys). PLAY-TEST same day: screen announcements CONFIRMED,
turn-by-turn + diagonals CONFIRMED, no battle garbage since v2.22.1;
journey sequencing still untested in play.

### v2.24 (2026-07-16): FRIENDLY location names â€” "Screen: Sector 1 Station"

User request during the v2.23 play test: the screen announcements speak
internal names ("nmkin 2"); they wanted the real names. One evening
session, full pipeline:

**1. Live scan disproved the savemap-preview theory**
(ff7_location_name_scan.py): savemap+0x00..0x53 stays ALL ZERO during
play, across screen changes and a menu open â€” the preview block is
generated at save time only. (Side lesson: the script's pywin32 SAPI
path silently degraded to console-only on this box â€” investigation
scripts now speak via a PowerShell System.Speech subprocess, which needs
nothing installed.)

**2. Static hunt** (ff7_mpnam_static.py, the v2.17 opcode-table method):
MPNAM = opcode 0x43 (FFNx enum counting anchored on live-proven
MESSAGE=0x40). Handler 0x618E33 â†’ storage callee 0x633691, which reads
the text entry via a NEW pointer global 0xCC08E8 (u16 offset table at
+2), decodes tokens (0xE2-family jump table at 0x6338CF; char-name
tokens via 0x6CB9B8), and writes â‰¤0x17 FF7-encoded bytes to
**0xDC0C44** â€” savemap+0xF0C, which is why saves remember the caption.

**3. Live verify** (ff7_mpnam_verify.py, minutes later): the buffer read
"Sector 1 Station" on field 117 and "Platform" on 116, tracking the
player's own screen crossings in real time. Also observed: bytes past
the 0xFF terminator keep the previous caption's tail â€” decode must stop
at the terminator.

**Mod changes**: FriendlyLocationName() (proxy.cpp) reads/decodes the
buffer; the v2.23 screen-change announce speaks the caption ("Screen:
Sector 1 Station"), internal name only as fallback; the M key speaks
BOTH ("Sector 1 Station, nmkin 2") â€” several screens share one caption
and M is the precision key. A field without MPNAM keeps the previous
caption, exactly like the sighted menu â€” information parity, accepted.

Deployed to the 2026 install 2026-07-16 19:46. **PLAY-CONFIRMED same
evening: "the screen and map names work as advertised."**

### v2.25 (2026-07-16): exits named by DESTINATION â€” "To Sector 1 Station"

User request right after confirming v2.24: "hear the destination rather
than exit 1 or exit 2". Gateways have always carried their destination
FIELD ID (+0x12, v2.14) â€” what was missing was names for ids. Two layers:

**1. maplist** (investigate/ff7_maplist_catalog.py): flevel.lgp contains
the engine's own idâ†’filename table â€” the "maplist" file: u16 count +
32-byte zero-padded ASCII names, index = field id (format hypothesis
picked by the live anchor: entry 122 must read "nmkin_2", known from the
session logs; it did, under the count-prefix layout). 788 entries.
Generated into AccessibilityMod/src/ff7_field_names.h (checked in;
regenerate with the script if flevel ever changes). Neighbors
double-confirm: [116]=md1stin (the opening "Platform" screen),
[117]=md1_1 ("Sector 1 Station"), [121]=elevtr1.

**2. Visited-places cache** (proxy.cpp): the friendly caption for ANOTHER
field cannot be read at runtime (it lives in that field's own script) â€”
but while the player stands on field X the mod sees X and X's caption
(v2.24 buffer), so it LEARNS Xâ†’caption and persists it to
ffvii_accessibility_places.txt next to the DLL. Exits to anywhere the
player has ever been speak the friendly name; the file is the player's
own growing map knowledge, kept across sessions. Inheritance caveat
accepted: a no-MPNAM field records its inherited caption â€” exactly what
the sighted menu displays while standing there.

**Exit naming** (DestinationName): learned caption ("To No. 1 Reactor") â†’
maplist internal name ("To nmkin 2"; wm* = "To World map") â†’ "Exit N"
only when the id resolves to nothing. Duplicate destinations get
slot-order ordinals ("To Platform 2"); a name may upgrade mid-session
(internal â†’ caption after first visit) â€” slot order, and therefore
identity, never changes.

Deployed to the 2026 install 2026-07-16 20:05; both cfgs updated.
**PLAY-CONFIRMED same evening ("Yes, that's much better").**

### v2.26 (2026-07-16): ", talk disabled" â€” the Jessie incident

Play report: the pathfinder led the player to Jessie at the nmkin_2
ladder tutorial, but she would not talk â€” the player doubted the
pathfinder. The live talk diagnostic (ff7_talk_diagnostic.py, new tool:
speaks nearest-NPC distance / talk-radius verdict / height difference as
a hot-cold beacon) proved the pathfinder RIGHT: 17 units away, same
triangle, inside her 80-unit talk radius â€” the game had script-disabled
her dialog at that moment. ~~(the tutorial belongs to the ladder
trigger, not to her)~~ **CORRECTED by play-test 2026-07-17: the ladder
tutorial DOES come from talking to Jessie herself** â€” the player
confirmed it on a fresh pass, with Jessie and the ladder far enough
apart to rule out the line trigger. So TLKON on her is a temporary
script state (disabled around the moment of the original incident,
enabled when she is ready to teach), not a permanent "she never talks"
flag â€” which is exactly why the suffix must always be read live from
the byte, never cached per NPC.

The missing information was the game's own talkability flag. Static hunt
(TLKON = opcode 0x7E by the proven enum-count rule; scratch disasm of
handler 0x618A80): TLKON writes its 1-byte arg RAW to field_event_data
**+0x61** (0 = talkable default, 1 = disabled), resolving its entity
through a NEW map â€” **0xCBFB70**, u8 entityâ†’model slot (0xFF = none).
Live confirm minutes later: Jessie read tlkon=1 through the whole
diagnostic, including at 120 units as the player re-approached.

**Mod change**: People announcements append ", talk disabled" when the
byte is set ("Jessie, talk disabled") â€” the body-language cue sighted
players read. DELIBERATELY one-sided: a 0 byte does not guarantee a talk
script exists, so the enabled side stays silent (never promise dialog
that may not come â€” the v2.18.2 "safer direction" principle).
NavDest.name widened 32â†’48 for the suffix on long labels.

Deployed to the 2026 install 2026-07-16 ~20:55. Play-test progress
2026-07-17: Jessie confirmed talkable AND the tutorial's source on a
fresh pass (the correction above) â€” so her TLKON state genuinely
toggles over the scene. STILL PENDING: actually HEARING ", talk
disabled" at a moment an NPC has dialog switched off, and confirming
ordinary talkable NPCs stay suffix-free.

### v2.27 (2026-07-16): interaction proximity chirp

User request (follow-on from the Jessie incident): "a quick audible tone
when the user gets near something they can interact with or talk to â€”
fire once and reset in case the user walks away and back."

One 1175 Hz / 60 ms chirp on ENTERING an object's interaction range â€”
the sighted player's passing glance, as an earcon. Ranges are the
game's own: a model's talk_radius (the exact circle the OK press
tests, so chirp = OK will reach), or 35 units to an enabled LINE
trigger. Eligibility mirrors the v2.26 lesson: talk-disabled people
(+0x61) never ping; off-mesh models and anything beyond a Â±150-unit
height gate (other walkway layer) are excluded.

EDGE SEMANTICS (per the user's spec): per-object armed flag â€” chirp on
entry, re-arm only after leaving range + 25 units of slack (boundary
jitter cannot stutter), full re-arm on screen change. Suppressed (state
still tracked, so no deferred spurious ping) during scripted scenes
(UC lock) and within 500 ms of dialog activity; a global 250 ms minimum
gap spaces the pings when entering a crowd. Tone family now: 220 Hz
repeating = wall, 1175 Hz single = usable in reach, 880 Hz post-announce
= wandering target.

New cfg key proximity_tone (default true). Implemented in
FieldNavThread's 50 ms poll (all inputs â€” positions, talk radius,
talk-off byte, LINE array â€” were already being read there).

Deployed to the 2026 install 2026-07-16 ~21:05; both cfgs updated.
Play-test 2026-07-17: chirp on approach CONFIRMED, and the re-arm
edge semantics CONFIRMED (approach -> walk away -> return chirps
again, no boundary stutter). STILL PENDING: crowd spacing with
several clustered interactables, and no pings from the walkway
overhead in the reactor.

Side effect: walkmesh pathfinding now exists, which unblocks the deferred
FF4 keys Shift+\ (valid-path-only filter â€” A* reachability is a byproduct)
and Ctrl+\ (layer filter â€” triangle awareness exists). See TODO.txt.

### v2.28 (2026-07-17): dev-name cleanup second pass â€” "ev"/"dr"/"jp" and friends

User report: the Triggers browser still spoke two/three-letter internal
names ("ev", "dr", "jp", "sp"...) that the v2.20 word tables never
covered â€” the game-wide stem catalog listed them, but a 2-letter stem
can't be translated from frequency alone.

**New evidence artifact**: investigate/ff7_short_entity_context.py â€” for
every short cryptic stem, prints the COMPLETE entity list of each field
where it occurs (same LGP/section-0 parser as the v2.20 catalog). The
neighbouring names identify the stem:
- `dr` = door â€” blin671b/blin67_1 list dr1..dr6 beside door1..door6,
  crcin_2 has dr1..dr5 beside 'door'.
- `jp` = jump (with ujp/mjp/sjp/jpj/jpr) â€” colne_b1 has jp0 beside the
  ldu/ldd ladder lines; nmkin_3/mds6_1/elevtr1/games; matches evjp.
- `ev` = event â€” used interchangeably with 'event1/event2' (rcktin6
  names them event*, ealin_1/gldst/mds6_1 say ev).
- `ldu`/`ldd` = ladu/ladd contractions; `esc` = esca (listed beside
  'esca' in blin68_1/blin69_1); Shinra-HQ elevator family
  eleu/eled/elel/eler + eledr/eleldr/elerdr (car doors).
- `mes`/`meskun`("message-kun")/`bmes` = message lines; matching
  `checkun`/`chekun` = check lines (ealin_1, gldgate).
- `ln`/`lin` = 'line' spelled shorter (blin66_1, sandun_1).
- Party shorthands `cl ti ba ea re rd yuf ket vin` â€” loslake1 lists the
  whole roster in slot order ('cl ti cid ba ea re ket vin yuf'); wired
  into kDevCharWords so live renames carry through.
- Full-name interceptions (word pass would mistranslate): `dr an`/`tr an`
  (train-car door/train animation lines, tin_1..4), `op cl` = open-close
  paired with door1/door2 (blin60_2) â€” NOT Cloud; `cl a` (fship_22/24)
  is also not Cloud (both fields have a separate 'cloud' entity) and its
  meaning is unknown, so it maps to itself.

**Verified by full-catalog dry run before shipping** (v2.20 method,
scratchpad replica over all 2412 entity names + 557 model labels):
88 entity names improve, ZERO model labels change, and the dry run is
what caught the 'op cl' â†’ "op Cloud" collision. **Deliberately left
untranslated**: `sp` (only jail2 + rcktin6, and jail2 already has
save/savel0 so it is NOT the save point â€” meaning unidentified, and a
wrong translation is worse than a terse one), the `ad`/`dir`/`dic`/
`drctr`/`produce` film-crew controller family (almost certainly never
own LINE triggers), `jl`, `se`, `lg`, `mat`, `mate` (evidence
insufficient). Deployed to the 2026 install 2026-07-17 ~10:46.

### v2.29 (2026-07-17): SAVE / CONTINUE menus speak â€” files from disk, cursors from one scan

User request with screenshots (Screenshots/Menus/): the save-point SAVE
menu and title-screen CONTINUE menu were silent. Both are one module:
a 10-file grid ("Save 1".."Save 10") then a 15-slot list per file.

**Two-source design.** (1) The slot PREVIEW data needs no memory at all:
the menu renders from `save\saveNN.ff7`, and the layout was derived
EMPIRICALLY from the player's own save00.ff7 against screenshot ground
truth in the same session (Â§5 table: slot = 9+nÃ—0x10F4, +0x04 level,
+0x05 portraits, +0x08 lead name as SAVED text, +0x20 gil, +0x24
seconds, +0x28 location, empty slot all-zero). The mod re-reads the
65 KB file per announce â€” no cache, so a fresh save can never speak
stale. (2) Cursor/phase state from ONE guided scan
(ff7_save_menu_scan.py, log save_menu_scan_20260717_114908): press-and-
revert rounds (wrap-immune, start-position-independent) intersected to a
SINGLE candidate for each cursor, grid cursor live-verified by the
scan's own speak-back pass. SAVEMENU_GRID_CURSOR 0xDC6AE0,
SAVEMENU_SLOT_CURSOR 0xDC6B1C (grid+0x3C), SAVEMENU_PHASE 0xDC1210
(Â§4 + Â§14).

**SaveMenuThread** (proxy.cpp, 150 ms, speak_menus-gated): save mode
gates on FIELD_IDâ‰ 0 âˆ§ MENU_OPEN=1 âˆ§ MENU_CURSOR frozen at 9 â€” the
Config-submenu frozen-row signature observed through the entire scan;
load mode on FIELD_ID=0 (world-map/victory overlap defused by
change-only + range guards: phase>1 âˆ¨ grid>9 âˆ¨ slot>14 = other module's
bytes, stand down â€” the TitleCursorThread lesson). Announcements:
grid move = "Save 3, 1 save"/"Save 3, empty" (used-slot count from
disk); entering the slot list = "Game 1. Slot 1: Cloud, level 7,
No.1 Reactor, 21 minutes, 376 gil, with Barret" (grid byte still holds
the file index there â€” scan-verified); slot move = the same per-slot
line; back to grid = the grid line. Offline replica over the real save
file reproduced the screenshots' preview exactly before shipping.

KNOWN LIMITATION (documented, change-only rule): no "menu just opened"
flag is known, so the first grid screen is silent until the first
cursor move â€” same behavior the main menu has always had.

Deployed to the 2026 install 2026-07-17 ~12:05. PENDING PLAY-TEST:
save menu grid/slot announces at a save point; the actual SAVE
confirmation flow; phase byte 0xDC1210 behaving (runners-up
0xDCA028 / 0xDD7700 ready if not).

**v2.29.1 follow-up (same day): Continue menu is a DIFFERENT module â€” found and wired.**
Player report: title-screen Continue silent. Live verify
(ff7_continue_menu_verify.py, log continue_menu_verify_20260717_120914)
DISPROVED the shared-module assumption: through 90 s of Continue-grid
navigation all three SAVEMENU_* bytes sat frozen (grid=0 slot=0,
phase=16 = title-module data; FIELD_ID=0, MENU_OPEN=1, MENU_CURSOR=0,
GAME_MODE=0, TITLE_CURSOR=1 throughout â€” none move either, so nothing
observable distinguishes the Continue grid from the plain title
screen; that pane stays change-only).

Second scan at the title (ff7_continue_menu_scan.py, log
continue_menu_scan_20260717_121456, ranges extended to FFNx's AF3DN.P
per the SOUND_CURSOR lesson): the Continue menu's OWN state instance in
the TITLE block â€” LOADMENU_GRID_CURSOR 0xDD6D98 (live-verified by
speak-back, the FFNx-range co-candidates were churn), LOADMENU_SLOT_CURSOR
0xDD6DD4 = grid+0x3C (single candidate; the SAME +0x3C spacing as the
save-menu pair â€” the struct echo corroborates both instances), pane from
LOADMENU_LIST_PTR 0xDD7700 (u32 heap ptr, 0 = grid / nonzero = slot
list, identical behavior in both menus' phase passes; nonzero-check
only). SaveMenuThread is now mode-aware: save mode = frozen-row gate
PLUS SAVEMENU_PHASE â‰¤ 1 (it reads 16 at the title, so a stale
MENU_CURSOR=9 after game-overâ†’title falls through to load mode instead
of muting â€” and dropping the FIELD_IDâ‰ 0 requirement also covers the
world-map save menu); load mode = FIELD_ID==0 with the LOADMENU_*
sources. Same disk-preview announcements in both. Deployed 2026-07-17
~12:20.

**v2.29.2 (same day): two play-reported corrections.**
(1) Slot lists only counted 3 slots: the scanned "slot cursors" are the
VISIBLE-ROW index of a 3-row scrolling window, not absolute slots (both
scans pressed Down/Up once from the top, where the two are
indistinguishable â€” scan-design lesson: exercise a list PAST its
window before trusting a cursor candidate). ff7_slot_scroll_probe.py
(windowed byte-diff around both structs, log 20260717_123245) found the
scroll offset at row+0x10 in the title instance (0xDD6DE4: stepped 0â†’12
and back exactly per press while the row byte pinned at the window
edges; +0x74/+0x80 are scroll-animation noise, never read). Absolute
slot = row + scroll; the save instance's scroll INFERRED at the same
member offset (0xDC6B2C, the struct echo's third data point).
(2) The save menu alternated its two pane announcements endlessly:
SAVEMENU_PHASE 0xDC1210 is DISPROVED â€” it oscillates in real use and
passed the A/B/A scan by coincidence. Both menus' pane now reads
LOADMENU_LIST_PTR != 0 (the loaded-file heap pointer both scans
observed independently and the shipped Continue menu already proved in
play); the save-mode gate reverted to the plain v2.29 frozen-row form
(FIELD_IDâ‰ 0 âˆ§ MENU_OPEN=1 âˆ§ MENU_CURSOR=9 â€” the world-map save menu
stays a TODO until a world-map GAME_MODE value is sampled). Deployed
2026-07-17 ~12:45. PENDING PLAY-TEST: save menu no longer repeats;
slot lines correct past slot 3 in BOTH menus (the save-side scroll
address is the one inference left unconfirmed).

**v2.29.3 (same day): the file grid had the same window-blindness.**
Play-test of v2.29.2: slot list now counts to 15 correctly, but the
FILE grid's second row misannounced. Grid probe run (the same
ff7_slot_scroll_probe.py with grid movements, log slot_scroll_probe_
20260717_171930): the "grid cursor" is the COLUMN 0..4 â€” it recounted
0..4 on the bottom row â€” and the row lives at grid+4 with INVERTED
values (1 = top, 0 = bottom; flipped 1â†’0 on the player's Down press,
0â†’1 on Up). The original 0..9 reading came from speak-back passes that
only ever walked the top row â€” the second instance of the same lesson
in one day: a verified cursor is only verified for the RANGE it was
exercised over. Save-menu row byte inferred at the same +4 (0xDC6AE4).
Deployed 2026-07-17 ~17:25.

**v2.29.4 (minutes later): row polarity was backwards.** Play report:
top row spoke Save 6, bottom spoke Save 1. v2.29.3 had read the
probe's baseline row byte of 1 as "player on top row" â€” but the player
had started the probe already PARKED on the bottom row (they had been
manually reproducing the second-row bug there). Polarity settled by
the play observation itself: 0 = top, 1 = bottom, file index =
rowÃ—5 + column. Lesson recorded: a probe baseline is only meaningful
if the starting state was independently known â€” ask the player to
re-home the cursor (or have the script speak the assumed start) before
trusting which absolute state a baseline value maps to. Deployed
2026-07-17 ~17:40. **PLAY-CONFIRMED the same evening**: both grid rows
correct in both menus, and a deep-slot round-trip verified end-to-end
(player put a save in file 6 / slot 15; announcements matched the
game's own "GAME 15" header). The field probe run (slot_scroll_probe_
20260717_200802) also LIVE-CONFIRMED the save side's grid-row
(0xDC6AE4, 0â†’1 on Down) and slot-scroll (0xDC6B2C) â€” no inferred
addresses remain in the save/continue menus. Same run turned up list
metadata (0xDC6B34 = slot count 15, 0xDC6B24 = visible rows 3) and
confirmed 0xDD7700 goes nonzero in SAVE mode live.

### v2.29.5 (2026-07-17): the "Are you sure you want to save?" dialog speaks

The last silent piece of the save flow (screenshot save_menu_3.png).
The windowed probe had shown its state was NOT in the DC6Axx cursor
window, so a full-BSS scan ran (ff7_save_confirm_scan.py, log
save_confirm_scan_20260717_201751) â€” both finds were SINGLE candidates
and speak-back verified in the same session:

- **SAVEMENU_WIDGET_STATE 0xDCA028 == 7** while the dialog is open
  (1 = slot list; 1â†’7 on Confirm, reverted on Cancel). This byte is
  the save menu's own mode variable â€” it was the runner-up in the
  original phase pass (0 = grid â†’ 1 = slot list), now with its dialog
  state observed too. Only value 7 is acted on.
- **SAVEMENU_CONFIRM_CURSOR 0xDC6C6C**: 0 = Yes, 1 = No, resets to
  Yes on open; live speak-back tracked every toggle. The slot-row byte
  held still throughout â€” the earlier ambiguity (dialog reusing the
  slot cursor) is settled: it does not.

SaveMenuThread announces "Are you sure you want to save? Yes" on the
1â†’7 transition, then Yes/No on cursor change, and short-circuits the
pane/slot logic while state == 7 (save mode only â€” Continue loads
without a confirm). Deployed 2026-07-17 ~20:30.

**PLAY-CONFIRMED same evening ("Everything works"):** dialog announce
and Yes/No tracking correct, a real save committed through Yes, and
the overwrite watch item is CLOSED â€” the player overwrote an existing
save and the game shows NO second confirmation; the one dialog already
handled covers both fresh and overwrite saves. The save/continue menu
feature (v2.29â€“v2.29.5) is complete.

### v2.30 (2026-07-18): party KO / revival announcements

The feature the user requested 2026-07-13 ("Cloud is down"), deferred
until the party had a second member â€” the latest save preview
(save00.ff7 slot 0, portraits `00 01 FF`) shows Cloud + Barret, so the
deferral condition is met. No new addresses: the v2.12 enemy liveness
watcher in BattleActionThread now has a party-side twin over actor
slots 0â€“2 (same BATTLE_ACTOR_VARS reads: statusMask bit 0x01,
current/max HP i32s, same max-plausibility gate â€” an empty third party
slot never becomes plausible and never announces).

Design differences from the enemy watcher, both deliberate:

- **Three states, not a bool** (`Unseen`/`Alive`/`Dead`): a member can
  *start* a battle already KO'd (carried over from the previous
  fight). Unseenâ†’Dead records silently (seen-alive-first rule: no
  spurious "is down" at battle init), but the recorded Dead state
  means a later Phoenix Down still announces. Revival ("X is back up")
  is the Deadâ†’Alive transition â€” enemies never needed it.
- **Distinct phrasing**: party = "is down" / "is back up", enemies =
  "defeated", so the player knows which side lost someone from the
  verb alone.

Delivery rides the SAME pending_defeats quiet-gap buffer as enemy
defeats (two-sided 600ms window, 5s cap, flush on battle exit) â€” a KO
lands in the killing action's announce-burst tick (the v2.12.1
lesson), so speaking at detection time would be cancelled within the
millisecond. Names come from PartySlotLabel (v2.19 savemap machinery).

Deployed to both installs 2026-07-18 (hash-verified). **PLAY-CONFIRMED
same day**: "The party member down and back up message works."

### v2.30.1 (2026-07-18): wall-bump tone looped through the game-over screen

Play report (same session that confirmed v2.30): after a full party
wipe, the 220 Hz wall-bump tone repeated continuously from the wipe
until the New Game / Continue screen appeared.

Diagnosis: this is exactly the Gate-2 stale-input scenario the
WallBumpThread comments already describe â€” the field module freezes
with `current_key_input_status` stuck at whatever direction was held
when the fatal battle triggered (random encounters usually trigger
mid-walk, so a direction is almost always stuck) and the model
position frozen â€” except the game-over screen evidently leaves the
GAME_MODE byte reading as field (0), so the mode gate that closes
during battles never closes. All six gates pass, `dir_held && !moved`
holds every poll, tone loops until the title screen finally zeroes
FIELD_ID.

Fix is behavioral, not another module-state gate (no game-over flag is
known, and finding one would cost a live scan round for a state the
player has to die to reach): the tone is now **armed only by real
observed movement** â€” two consecutive valid position samples that
differ â€” within the current gate-open episode, and re-disarmed
whenever any gate closes (mode/menu/uc_lock/movie/dialog/config, or
the event-data array going unreadable). A frozen module can fake
"direction held" forever but can never fake the player actually
walking; a live player must take at least one step to reach a wall, so
the detector arms before any legitimate bump. Known accepted cost: if
a battle ends with the player flush against a wall AND the direction
never released, the first bump tone waits until they move once. A
suppressed episode writes one debug-log line ("WALL tone suppressed")
at the moment the streak crosses the threshold unarmed, so future
reports can distinguish "suppressed" from "gate closed".

Deployed to both installs 2026-07-18 (hash-verified). Awaiting
play-test: normal wall bumps should be unchanged; a party wipe should
now be silent through the game-over screen.

### v2.31 (2026-07-18): the ITEM menu speaks â€” one static morning + one guided scan

User request with screenshots (Screenshots/Menus/items_menu_1/2.png =
ground truth for captions and layout). Everything except the cursors
came without touching the running game:

**Static (ff7_item_menu_static.py + ff7_menu_dispatch_disasm.py):**
- Inventory data: savemap items[320] at 0xDC0234 (savemap+0x4FC, pinned
  by the live-verified party_members at +0x4F8), word = id | qty<<9,
  EMPTY = 0xFFFF â€” format from FFNx's own menu_decrease_item_quantity
  reimplementation. Key-item bitmask at 0xDC0894 (+0xB5C). Screen row
  order = array order.
- Sub-screen dispatcher: menu_sub_6CB56A (FFNx name-embedded) calls
  menu_subs_call_table[16] @0x91AB98 (operand at +0x2EC; table read
  cross-checked against FFNx's [10]=0x6FEDB0 save menu) indexed by u32
  [0xDC12EC] ([0xDC12E8] during transition frames). Bonus: the same
  disasm shows the dispatcher XOR-toggling 0xDC1210 every tick â€”
  closing the v2.29.2 "why did the phase byte oscillate" question.
- METHOD LESSONS (both cost a wasted run): (1) the first sweep filtered
  memory operands to plain [imm32] â€” but array access compiles as
  [reg*2+disp], so the items-array discriminator found ZERO refs
  anywhere; indexed operands must be kept (tagged) for array evidence.
  (2) A depth-4 call sweep converges on shared menu helpers and scores
  every sub-screen equally â€” discriminate SHALLOW (depth 2), mine deep
  only inside the chosen entry. (3) The static caption evidence picked
  table[3]; LIVE dispatch reads 1 â€” table[1] also had the most direct
  items refs, and the live value wins (the 0xDCA7F8 "exclusive block"
  of table[3] stayed 0 all session â€” belongs to some other screen).

**Live (ff7_item_menu_scan.py, log item_menu_scan_20260718_114427, run
by the player):** every pass produced exactly ONE candidate â€” the
cleanest scan of the project. ITEMMENU_MODE 0xDD19C8 (0 top bar / 1
item list / 2 target pane; BOTH A/B/A toggles landed on it),
TOPBAR_CURSOR 0xDD1A18, LIST_CURSOR 0xDD1A54 (speak-back verified;
rides empty rows), TARGET_CURSOR 0xDD1A8C. Player flow correction:
the menu OPENS in the item list; Cancel goes up to the top bar.

**Implementation (ItemMenuThread, proxy.cpp):** gate = MENU_OPEN &&
FIELD_ID!=0 && [0xDC12EC]==1. Speaks "Item menu" on entry then the
current row; item rows as "Potion, 4. Restores HP by 100" (three NEW
kernel2 sections: armor "Bronze Bangle|", accessory "Power Wrist|",
item descriptions "Restores HP by 100|" â€” the screenshot's own caption
is entry 0's head; names cover the full inventory id space 0-319);
empty rows as "Empty"; top bar as Use/Arrange/Key Items; target pane
via PartySlotLabel + savemap HP/MP (offsets +0x2C/+0x38/+0x30/+0x3A
from FFNx savemap_char â€” heal-target parity with the sighted pane);
repeated uses in the pane speak "N left" from the inventory word
changing under the held cursor. Unmapped mode values stay silent and
debug-log for harvesting. Config gate: speak_menus (no new key).

Deployed both installs 2026-07-18. **PLAY-CONFIRMED same day
("everything we can test works")**: list/top-bar/target announces,
descriptions, counts â€” and no spurious "Item menu" on the plain main
menu, so the dispatch-index gate holds in practice. Remaining
residuals are the story/state-gated ones in TODO.txt: list-cursor
window-vs-absolute (needs >1 screen of items), Arrange popup + Key
Items pane (unmapped modes, silent + debug-logged), equipment
description sections, key-item names.

### v2.31.1 (2026-07-18): main-menu labels one row off from Materia down

Player report, row by row: "equip, status, order, and limit all need
to move down 1; the selection directly under magic is not available
yet." The unavailable row under Magic is the grayed MATERIA row â€” the
original 2026-07-01 label table was built without in-game row
comparison and omitted it, so Equip through Limit announced one row
early ever since. The corrected table (Item, Magic, Materia, Equip,
Status, Order, Limit, Config, PHS, Save, Quit) also retroactively
identifies BOTH old "unlockable, identity TBD" slots: 6 = Limit
(shifted), 8 = PHS ("P H S" spaced so TTS spells it). Config=7 and
Save=9 were coincidentally correct in both tables, which is why the
config sub-menu work and the v2.29 save-mode gate (MENU_CURSOR==9)
never surfaced the error. Deployed both installs same day.
**PLAY-CONFIRMED same day**: "I did indeed hear Materia and PHS in the
correct places" â€” the full corrected row order is verified in-game.

### v2.32 (2026-07-18): the ORDER menu speaks â€” and the player's ear beat the scanner

User request: announce each member's position when selected and explain
how to change the order. Three-step investigation, each step forced by
the last:

1. **Guided scan** (ff7_order_menu_scan.py, log order_menu_scan_
   20260718_152825): party cursor 0xDC11C4 (single candidate, speak-back
   verified, rides the empty third slot), selection latch 0xDC1320
   (0â†”1), row byte = **char record +0x20** flipping 0xFFâ†”0xFE (single
   toggle candidate 0xDBFDAC = Cloud's record â€” the community's +0x1F
   claim is one byte off), swap = PARTY_IDS bytes exchanged. BONUS: the
   dispatch index read **0 on the plain main menu** (closing the v2.31
   caveat â€” Item's 1 is genuinely distinctive)â€¦ and 0 inside "the Order
   screen" too.
2. **The player's observation**: "the order menu does not make an
   in-game chime like the other menus â€” perhaps it's not actually going
   into another menu screen." Exactly right, and it explained why the
   follow-up A/B/A entry probe (order_entry_probe_20260718_153813)
   found nothing: there is no screen entry to detect.
3. **Disasm of the main-menu sub** (menu_subs_call_table[0] = 0x6CA346;
   ff7_order_block_disasm.py): the whole confirm handler decoded.
   **MENU_FOCUS_MODE 0xDC1324** (0 = menu bar, 1 = character-select
   pane with confirm chime 0x74580A(1), **2 = Order pane with NO sound
   call** â€” the missing chime is literally in the code). Also decoded:
   first-selected slot 0xDC110C, row-toggle = XOR 1 on record+0x20,
   **MENU_DISABLED_ROWS 0xDC1130** (u16 bitmask gating row activation =
   what grays Materia/PHS), char-select pane cursor 0xDC118C + chosen
   slot 0xDC1288 (pre-solves Magic/Equip/Status), and the game's own
   char-idâ†’record table 0x919928.

**Implementation (OrderMenuThread + MenuCursorThread change):**
- Focus 0â†’2: spoken how-to ("Confirm one member, then another, to swap
  places. Confirm the same member twice to change rows.") + current
  member. Cursor moves: "Barret, position 2, front row" ("Empty,
  position 3" on the empty slot).
- Latch set: "<name> selected. Confirm another member to swap, or
  <name> again to change rows." Latch clear: outcome READ FROM THE DATA
  (party-ID array â†’ "Swapped. <new order>"; row byte â†’ "<name>, back
  row"; nothing changed â†’ "Cancelled") â€” a missed press can never
  announce a wrong result.
- Focus 0â†’1 (Magic/Equip/Status char-select): "Choose a member." +
  name announces on the 0xDC118C cursor.
- Main menu rows now append ", not available" when their
  MENU_DISABLED_ROWS bit is set â€” the gray the sighted player sees.

Deployed both installs 2026-07-18. **PLAY-CONFIRMED same day: "It
works perfectly."** â€” which live-validates the static-derived
MENU_FOCUS_MODE semantics (0 = bar, 1 = char-select, 2 = Order) along
with the whole flow: entry how-to, position/row announces, swap and
row-toggle outcomes, "not available" rows, and the mode-1 "Choose a
member." pane.

### v2.33 (2026-07-18): the STATUS screen speaks â€” zero user scans

The "easy get" it was predicted to be (user request + screenshot
status_screen_1.jpg = ground truth), assembled entirely from prior
finds plus two read-only live dumps run while the player sat in the
menu â€” no guided scan:

- **Gate**: dispatch index 5 â€” FFNx's ff7_data.h itself names
  menu_subs_call_table[5] "status_menu_sub" (0x703ABD in our table
  dump). Character shown = CHARSEL_CHOSEN (v2.32's mode-1 commit).
- **Record verify** (ff7_status_record_verify.py): every claimed
  savemap offset checked against the screenshot â€” level, limit level,
  HP/MP, EXP 856 / next 93 exact, weapon/armor 0 = Buster Sword /
  Bronze Bangle, accessory 0xFF, row 0xFF. ONE productive surprise:
  +0x02/+0x04 read 22/20 vs screen's 20/24 â€” **the record stores BASE
  stats; the screen shows EFFECTIVE** (Cloud's materia at work).
- **Effective-stats hunt** (ff7_status_stats_hunt.py): pattern-scanned
  the whole BSS for the screen's exact stat run (20,16,24,17,9,17) â€”
  **exactly one hit: 0xDBA49A = BATTLE_CHAR_BLOCK+2**. The v2.9
  "battle" block is really the game's shared char-data block, menu-
  populated too. Follow-up dump mapped the stat head: effective u8
  stats at +0x02, derived u16 Attack/Defense/Magic atk/Magic def at
  +0x08..+0x0E, HP/MP pairs at +0x10..+0x16 (all seven screenshot
  values matched in place).
- **StatusMenuThread**: on entry (and on viewed-slot change) reads the
  whole sheet in screen order â€” name, level, HP/MP, EXP + to-next,
  limit level, six effective stats, the derived four, equipment names
  via the v2.31 weapon/armor/accessory sections ("Accessory, none"
  for 0xFF). Staleness guard: the block's HP pair must equal the
  savemap record's, else it speaks base stats and skips the derived
  four (degraded, never wrong â€” the block is battle-shared, so a
  stale-after-battle mismatch must not misreport).

RESIDUALS: Attack%/Defense%/Magic def% (drawn from kernel equipment
records at render time, present nowhere in memory â€” needs kernel
weapon/armor data parsing if wanted); status pages 2/3 (elemental /
added-effect tables) unmapped and silent â€” page-cycle input isn't
detected. Deployed both installs 2026-07-18. **PLAY-CONFIRMED same
day: "Status menu works as expected."**

### v2.34 (2026-07-18): countdown-timer announcements + freeze â€” shipped BEFORE the first timer exists

User request ahead of the No.1 Reactor timed escape (after the one-shot
scorpion boss): minute-boundary announcements, 30-second mark, final-10
countdown â€” then a way to DISABLE the timer for players who find the
pressure too much. The planning problem: the first timer in the game is
behind a boss the player must beat, so live scanning was off the table.
The whole feature was therefore proven statically and shipped
speculatively, with the player's first real escape run as the live
verify:

- **STTIM opcode (0x38** â€” FFNx FieldOpcode enum counted to MESSAGE=0x40,
  the LINE/MPNAM rule): handler 0x61FCD8 reads the h,m,s script args and
  stores **hÂ·3600 + mÂ·60 + s to 0xDC08BC = savemap+0xB84** â€” the field
  FFNx's savemap struct ALREADY NAMES `countdown_timer`. Two independent
  sources agree on the address; the handler's arithmetic settles the
  units (whole seconds) without a single live sample.
- **0xDC08C0** (next dword) = FFNx `millisecond_counter` (operand at
  timer_menu_sub+0xD06) â€” the sub-second accumulator behind the 1/sec
  tick. WSPCL (0x36) creates the on-screen clock window that renders
  from the seconds value: freezing the VALUE freezes the DISPLAY and
  keeps field-script time checks satisfied â€” no game-over while frozen.
- **TimerThread (v2.34)**: behavioral running-detection (nonzero AND
  recently decreased â€” a stale savemap value from a load can never
  false-start it, the v2.30.1 lesson applied to data). Announces per
  the user's spec; battle announces queue behind battle speech EXCEPT
  the final-10 countdown, which always interrupts. First-run
  diagnostics: logs the first 5 tick intervals (cadence proof) and all
  start/stop/jump transitions.
- **T / Shift+T** exactly per accessiblity_keys.txt ("Announce active
  timers" / "Toggle timer freeze" â€” the FF1-6 scheme already defined
  this pair). Shift+T is the mod's FIRST GAMEPLAY MEMORY WRITE: while
  frozen the countdown value is rewritten every 250ms poll (plain
  savemap data, no protection change). T works in any mode, battle
  included.

Deployed both installs 2026-07-18; installed cfgs get the
timer_announcements block and debug_log=true until the escape run
verifies the static assumptions (tick cadence, menu/battle pause
behavior â€” the log will show both).

**LIVE RESULT (2026-07-19, first escape): address CONFIRMED** â€” plain
T reads the remaining time correctly, so 0xDC08BC is the live ticking
timer and the announcements work. But **Shift+T (freeze) did nothing**,
fixed as v2.34.1.

### v2.34.1 (2026-07-19): Shift+T freeze â€” 50ms poll + pin the ms counter

The freeze silently failed on first use: T read the time, Shift+T
produced no speech at all. Since both freeze branches speak, the T
EDGE itself was being lost specifically for Shift+T. Cause: TimerThread
polled at 250ms while FieldNavThread (whose Shift+J/L category switches
work fine for the same player) polls at 50ms. A two-key Shift+T
releases faster than a plain T tap, so its brief T-down often fell
entirely between two 250ms samples â€” no edge. Fix: TimerThread now
polls at 50ms.

Also hardened the freeze: it pinned only the seconds (0xDC08BC), but
the game keeps advancing the ms accumulator (0xDC08C0) and decrements
seconds when it rolls past 1000, so a seconds-only freeze would creep.
v2.34.1 zeroes the ms counter every poll too, so the game never
completes a second and the clock truly stops. One debug line now logs
every T press (shift/frozen/running/live/val). Deployed both installs
2026-07-19; the No.1 reactor escape is a one-shot, so freeze re-tests
at the next timed sequence. **PLAY-CONFIRMED 2026-07-20** ("the timer
pause has been play tested and works").

### v2.30.2 (2026-07-19): wall + proximity tones dead during a timed escape

Player report: neither the wall-bump tone nor the proximity chirp
worked during the reactor escape. The escape log (debug_log on from the
timer work) pinned it precisely: both tones gate on "no dialog activity
in the last 250-500ms" (`Hooks::LastDialogActivityTick`), and
`hook_message` stamped that timestamp UNCONDITIONALLY on every call.
That hook sits on the message-window UPDATE loop, which runs every frame
while ANY field window is open â€” including the **countdown-clock special
window (WSPCL)** the escape puts on screen. The log's `MSG heartbeat`
proved the loop ran ~30/sec for the whole escape with ZERO dialog state
transitions (a steady non-text window), so the dialog tick was fresh
every frame and both tones stayed suppressed the entire time. (Also
visible in the same log: the v2.34.1 Shift+T freeze now works â€”
"frozen=1"/"TIMER frozen at 582".)

Fix: stamp `s_last_dialog_tick` only when the window genuinely holds
message text â€” `is_valid_dialog_rawptr(raw_text)`, the same validity
check the speak path already uses. A real MESSAGE dialog has valid
rawptr text; the numeric clock does not. OOB banked window_ids still
stamp (rare real dialogs, field frozen; the clock is never OOB â€” log
shows in-range 0-7). Suppression during real dialogs is unchanged
(needed because the field freezes and a held direction would otherwise
false-fire the dead-stop wall tone). A throttled "MSG steady win/state/
text" diagnostic now logs the clock window's signature so the next
timed sequence confirms the fix. Deployed both installs 2026-07-19.
**PLAY-CONFIRMED 2026-07-20** ("wall and interaction tones now work
during the escape scene").

### v2.30.3 (2026-07-19): long-dialog paging no longer re-reads the message

Player report: long dialogs re-read parts of the message when pressing
to continue. Cause: FF7's dialog rawptr holds the COMPLETE multi-page
message (page-break bytes 0xE8/0xE9 included), and FF7Text::Decode
reads all pages as one string (breaks â†’ spaces) â€” so the START speak
already covers every page. The paging state machine (14â†’2 / 4â†’8) then
spoke the whole decoded message AGAIN on each page advance = the
duplication. Fix: per-window `last_spoken` string; `speak_incremental`
speaks only text not already covered â€” a page advance over the same
text says nothing, and if the message ever grows (streamed load) only
the new suffix is read. Cleared on new dialog / close. Deployed both
installs 2026-07-19.

**SUPERSEDED by v2.30.4** (below): this fix correctly stopped the
literal re-speak, but play-testing showed the real symptom was
different from what it looked like â€” see v2.30.4.

### Battle/choice/trigger issues reported 2026-07-19 (train graveyard)

Three reports, triaged:
- **Paging duplication** â€” FIXED v2.30.3 above.
- **Choice menus read only the first option, no cursor tracking** â€”
  needs the ASK current-option address. STATIC (ff7_ask_cursor_static.py):
  the ASK handler 0x618E83 keeps the live selection in a STACK LOCAL
  ([ebp-4], &it passed as the 5th arg to update loop 0x6310A1), so no
  fixed global; the update loop keys off a per-window struct at
  0xCFF5D3 + window_idÂ·0x30 (state at +0x11 = 0xCFF5E4) where the
  option byte also lives â€” offset TBD by a guided scan
  (ff7_ask_cursor_scan.py: move the choice cursor, watch the struct).
  Then hook_ask announces the highlighted option line on change.
  DEFERRED to the scan (needs the game + a 3+ option choice).
  **Scan run 2026-07-20** (ask_cursor_scan_20260720_102217.log, two
  press-and-revert rounds intersected): ONE candidate, **0xCC14D1**.
  NEXT: wire as ASKMENU_OPTION in ff7_addresses.h, have hook_ask track
  it and announce the option line on change (still keep "Choose: " +
  full text as the intro on open).
- **Train-graveyard triggers all say "line N"** â€” NOT a bug: the log
  shows those trigger entities are literally dev-named 'line'
  (vs other fields' 'border'/'save point'), so they translate to
  "line" and get slot ordinals. No descriptive name exists in the
  field data; the pathfinder's direction/distance is the real
  distinguisher. Accepted data limitation (noted in TODO).

### v2.35 (2026-07-19): battle VICTORY screens speak â€” pools, level-ups, drops

User request + screenshots (BattleScreen/victory_screen_1..3.jpg).
All static, anchored on FFNx's menu_battle_end_sub_6C9543 +
menu_battle_end_mode externals:

- **BATTLE_END_MODE 0xDC1300** (u16, operand at 0x6C9543+0x2C). FFNx's
  own achievement hook brands the phases: 0 = won/init, 1 = EXP/AP
  screen, 3 = gil/items screen (its checks fire per phase). The OK-press
  handler at 0x6C6B3F shows mode 2's exit applying gil.
- **Results pools** (battle module 0x431541 accumulates per enemy slot
  from actor_vars +0x68 stride): **0x99E2C0 gained EXP, 0x99E2C4 gained
  AP, 0x99E2C8 gained gil** (u32s). âš  CONSUMED ON APPLY â€” the menu does
  `SAVEMAP_GIL += pool; pool = 0` entering mode 3 (0x6C6B8F), so the
  announcer captures all three at results entry (modeâ†’1), never at
  screen time.
- **Drops**: count u32 0x9AE12C, entries at 0x99E2F0 **stride 6** (the
  battle fill loop's `imul 6`), u16 item id at +0 (0-319 namespace â†’
  InventoryEntryName), +4 word = compaction-copied field (qty/taken?
  logged, not spoken, until live data names it).
- Bonus find: 0x6C6AEE = the dispatcher-index setter â€” it copies
  currentâ†’0xDC12E8 before writing 0xDC12EC, so **0xDC12E8 = PREVIOUS
  screen index**, refining the v2.31 "transition twin" reading.
- Search lesson: the victory captions ("Gained EXP and AP.") are NOT
  findable FF7-encoded in the exe â€” they live in runtime-loaded kernel
  text. Caption-string discrimination only works for exe-resident
  strings ("Arrange" was; these aren't).

**VictoryThread**: modeâ†’1 (inside MENU_OPEN, the v2.8.3 results
context): "Victory! Gained X experience and Y A P." + pool capture +
party level snapshot; savemap level bytes watched through the window â†’
"<name> grew to level N!" (queued, never clobbers the victory line;
catches multi-level-ups with no new addresses); modeâ†’3: "Gained X gil,
total Y. Received Potion, Potion." / "No items." Sanity gates on pools
and count; every transition and drop entry debug-logged. Gate:
speak_battle. Deployed both installs 2026-07-19. **PLAY-CONFIRMED same
day ("It works")** â€” with one regression, fixed as v2.35.1 below.

### v2.35.1 (2026-07-19): stale menu-row announce over the victory screens

Player report: the victory screens still triggered the main menu's
open-re-announce with the STALE cursor row ("Item", "Config") â€” the
v2.8.3 "MENU_OPEN is also 1 on post-battle results" observation biting
a new thread. The results context can't be identified by GAME_MODE
(its value there has never been sampled, and the mod only trusts
live-observed values), so two in-process signals gate it instead:

- **g_last_battle_tick**: BattleActionThread stamps GetTickCount()
  every poll while GAME_MODE==2. A "menu open" within 4s of battle
  mode can only be the results screens â€” the real main menu is
  unreachable that fast through the fade and results. This covers the
  race before the results mode byte first moves.
- **g_victory_active**: VictoryThread publishes its in_results state,
  covering however long the player reads the screens.

MenuCursorThread stands down (seeding its trackers silently) while
either signal is live; the same guard went into the Item and Status
menu gates, whose dispatch-index test would false-open over the
victory screens if the matching screen was the last one visited (a
latent bug of the same shape, caught by inspection). Deployed both
installs same day. **v2.35.1 PLAY-CONFIRMED same day ("That worked")**.

### v2.35.2 (2026-07-19): victory announces re-timed to the SCREENS, not the presses

Player report: "you hear the game chirp as the exp gained goes up,
THEN it says victory and numbers" â€” the announcements trailed the
flow. Root cause: **BATTLE_END_MODE advances on the player's OK
presses, not when screens appear.** Corrected phase map (the player's
description is the source): mode 0 = EXP/AP screen SHOWING (waiting
for OK), mode 1 = the roll-up itself (chirps, EXP draining into
characters, levels applying â€” consistent with FFNx's level
achievements firing at 1), mode 2 = gil/items screen SHOWING, mode 3 =
after its OK (gil applied â€” consistent with the disasm's apply-on-
mode-2-exit and FFNx's gil achievement at 3).

Fix: the victory line now fires at the RESULTS WINDOW OPENING â€” the
post-battle MENU_OPEN rise, identified by the v2.35.1 battle-recency
signal, while mode is still 0 and the pools are untouched (captured at
the same instant). The gil/items line fires ENTERING mode 2 (fallback:
3, whichever appears first); the savemap gil total read there is
pre-apply, which is exactly the number the sighted screen shows. The
level-up watcher is unchanged (it catches the mode-1 roll-up whenever
it happens). Deployed both installs same day; awaiting re-test.

### v2.36 (2026-07-19): battle-list layout fix + scene-message (tail-warning) reader

Two player reports: (1) some items/magic mis-announce when selected in
battle; (2) the scorpion's "tail's up" warning isn't spoken.

**(1) List-widget layout â€” the v2.9 formula was one case of three.**
Disassembling the Confirm paths of BATTLE_MENU_FN_TABLE[5]/[6]
(ff7_kernel2_text_disasm.py) showed the three battle lists differ:
- ITEM (state 5, global 0x9AC354): single column, entry STRIDE 6, u16
  id at +0, empty = **0xFFFF**. The v2.9 code also skipped `id == 0` â€”
  but **item id 0 is Potion**, so every Potion went silent. Fixed:
  skip 0xFFFF only.
- MAGIC/SUMMON (state 6/7, per-slot char block +0x108/+0x2C8):
  **3-column grid**, entry STRIDE **8**, u8 id at +0, empty = 0xFF.
  Selected index = `horiz + (vert+scroll)*3`, not the linear
  `w0+w4+scroll`. The two formulas agree only for a single row of â‰¤3
  spells â€” exactly the v2.9 test's list, which is why it passed then
  and broke once the player carried a full spell list.
The list-cursor code now branches on list type for stride, id width,
empty-marker, and index formula. (Summon shares the magic widget
family; assumed identical, flagged for verification when summons
exist.)

**(2) Scene messages â€” an untapped text channel.** Enemy AI dialogue
(the tail warning and all scene.bin messages) reaches the screen
through the battle text DISPLAY QUEUE, which no announcer read (v2.7
speaks ability names from the flash struct â€” different text).
Addresses static (ff7_battle_text_static.py): BATTLE_TEXT_QUEUE
0xBF1EB8 (battle_text_data[64], s16 buffer_idx at +0, -1 = empty,
stride 6). Text lookup replicates GET_KERNEL_TEXT section 8 (handler
0x4199AD â†’ 0x41D2E5): for buffer_idx â‰¥ 0x100 (the scene-dialogue
class), text = SCENE_MSG_BASE 0x9AD1E0 + u16[SCENE_MSG_OFFSETS 0x9AD9E0
+ (idx-0x100)*2], FF7-decoded. Section-7 in the same jump table matches
v2.10's target-name derivation exactly â€” cross-check that the table
read is right. BattleMessageThread scans the queue at 150ms while
GAME_MODE==2, dedups by buffer_idx VALUE (survives FFNx's queue
compaction; a message that leaves and returns re-speaks), speaks
queued (never clobbers action speech). Shipped speculatively (the
scorpion is a one-shot) with debug logging, like the timer.

Gate: speak_battle. Deployed both installs 2026-07-19 (hash-verified).
**PLAY-CONFIRMED 2026-07-20** ("the battle item/magic list has been
play tested and appears to work" â€” list-layout fix (1) confirmed; the
scene-message reader (2) wasn't separately called out, no report of a
missing scorpion warning either).

### v2.37 (2026-07-19): "whose turn is it" on battle-menu open

User request: announce the character when their battle menu pops up, to
pick actions faster. No new addresses â€” BATTLE_ACTIVE_SLOT (0xDC3C7C)
already gives the party slot whose menu is open, and PartySlotLabel
already names it. The only real design work is firing exactly once per
turn:

- A "turn session" is defined as the command menu plus its submenus
  (item/magic/summon/limit) plus targeting. When the state leaves all
  of those â€” menu closed (0xFFFF) or ATB idle (state 0 with targeting
  NOT armed, the same 0-is-ambiguous resolver the targeting logic uses)
  â€” the announce rearms. So cancelling among submenus back to the
  command menu does NOT re-announce, but a genuinely new turn (even the
  same character again) does.
- The name attaches to the FIRST real command announce of the turn as
  one utterance: "Cloud's turn. Attack." A separate interrupt=true
  "turn" line would clobber the command that follows in the same poll;
  folding them avoids that entirely. Empty transient cursor cells are
  skipped before the prefix attaches, so it lands on the first real
  command.

Gate: speak_battle_menu (with the rest of the battle-menu TTS).
Deployed both installs 2026-07-19. **PLAY-CONFIRMED 2026-07-20** ("the
character turn announcement has been play tested and works").

### v2.30.4 (2026-07-20): dialog reads pace to the SCREEN, and stop gluing words

Two player reports from the train-graveyard session, both traced to
`ff7_text.cpp`.

**(1) "Duplicate" speech was actually a PACING bug, not a re-read.**
Player's own diagnosis, confirmed by re-reading the v2.30.3 code: FF7's
dialog rawptr holds the COMPLETE multi-page message the instant the
window opens â€” there's no "page 2 doesn't exist yet" state to wait
for. v2.30.3's fix (speak only text not already covered) correctly
stopped literal re-speaking, but the START speak still decoded and
read the ENTIRE message â€” every page â€” before the player had advanced
past page 1. The words were right; the pacing wasn't: TTS ran ahead of
the screen, so page 2 "sounded like" a repeat of what had already been
read once the display caught up to it. Fix: `FF7Text::DecodePages()`
splits the decode on page-break bytes (0xE8/0xE9) instead of
flattening them to a space, returning one string per on-screen page.
`hook_message` now decodes the whole rawptr once at START (into
`WindowState::pages`) but speaks only `pages[0]`; each later PAGE
transition (14â†’2 / 4â†’8) speaks the next cached page
(`WindowState::next_page`, the index the struct's `page_count` field
was reserved for since v1). No more re-decoding â€” or re-speaking â€” on
each advance; TTS says exactly one page per screen, in step with what
the player is looking at. `speak_incremental` and `last_spoken` are
gone; `DecodePages` supersedes them entirely, so v2.30.3's mechanism
is retired rather than layered under this.

**(2) Word-boundary gluing: "Hey[item name]What about our money?" /
"Uhnothin'.sorry."** Both are the same root cause in `decode_walk`
(nee the loop inside `Decode`): several branches inserted or consumed
content with NO compensating space, unlike the newline/page-break
branch which always guarded one. Concretely:
- Dynamic tokens (0xEB-0xF0 mid-string: item name, number, target,
  attack, special, target-letter) spliced their `[placeholder]` text
  directly between whatever bytes sat on either side â€” the placeholder
  is much longer than the icon/number FF7 actually renders inline, and
  the original bytes often have no explicit space around the
  substitution point (the icon itself is the visual separator).
- Inline character-name references (0xEA/0xF1/0xF2 mid-string) had the
  same gap.
- **The unknown/unhandled control byte branch appended NOTHING at all
  â€” not even a placeholder space** â€” unlike the tail canonicalization
  filter, which already does this for discarded *wide characters* (see
  its own "WHY NOT STRIP-ONLY" comment) but never sees bytes that were
  dropped before reaching it. A stray control byte (something outside
  every other case: 0xE1-0xE6, 0xF3-0xF5, 0xFA-0xFE) sitting between
  two words with no explicit space byte around it â€” because the
  original renderer never needed one for a non-printing code â€” glues
  them: "Uh" + âŸ¨dropped byteâŸ© + "nothin'" â†’ "Uhnothin'", matching the
  Wedge-line report exactly.

Fix: a shared `guard_space()` helper (ensure the output ends in a
space before inserting/skipping) is now called at every one of these
points, both before inserted text and (for tokens/names) after it too.
Newline/page-break already had equivalent guarding; this just extends
the same discipline to every other content-affecting branch. Refactor
note: `Decode()`'s inner loop was pulled out into `decode_walk()` (used
by both `Decode()` and the new `DecodePages()`) plus a `filter_and_trim()`
helper for the tail canonicalization pass, so the two entry points
share one walk instead of duplicating the byte-decode logic.

No new addresses; pure text-decode logic. Built clean, deployed both
installs 2026-07-20 (hash-verified). VERIFY next play session: long
dialogs speak one page per screen (no reading ahead); no more glued
words around item/number substitutions or stray control bytes.

**(3) ASK choice-menu option cursor wired** (closes the DEFERRED item
above). ASKMENU_OPTION 0xCC14D1 (the scan candidate, see above) is now
read every frame after the choice's intro speaks; on change it
announces `FF7Text::DecodeLines(raw_text)[option]` â€” a new decode
entry point that splits on EVERY newline (not just page breaks like
DecodePages), since ASK answers are conventionally one line each
where MESSAGE prose is not. `hook_ask` assumes the cursor starts on
option 0 (already covered by the intro) so only a cursor MOVE
re-announces. **SPECULATIVE**: whether decoded line[i] actually lines
up with cursor option i (a leading question line could shift the
index by 1+) is unverified â€” the scan session didn't have
speak_choices instrumented to check live. Debug-logged (`ASK win=%u
option %d->%d`) for the next multi-option choice to confirm or name
the offset. No crash risk either way: the option read is bounds-
checked against the decoded line count, so a wrong index just no-ops.

### v2.30.5 (2026-07-20): two dialog audio cues â€” "waiting for you" and "a choice appeared"

User request: a short high tone when a story dialog is waiting for the
player to press the confirm button, and a short high DOUBLE tone when a
choice menu is presented. No new addresses; both are logic layered on
the existing MESSAGE/ASK hooks plus one new background thread.

**Threading**: `hook_message`/`hook_ask` run on the GAME's main thread â€”
`Beep()` blocks for its whole duration, so beeping directly from a hook
would stall the game itself every time it fires. Same pattern as every
other tone in this mod (`WallBumpThread`, the proximity/wander chirps):
the hooks only SET edge-triggered flags (`s_dialog_wait_pending`,
`s_dialog_choice_pending`, both `volatile LONG` in hooks.cpp), and a new
`DialogToneThread` (proxy.cpp, 50ms poll, same cadence as
WallBumpThread) consumes them via `Hooks::ConsumeDialogWaitTone()` /
`ConsumeDialogChoiceTone()` â€” `InterlockedExchange(&flag, 0)`, so the
read-and-clear can't race a fresh set from the hook and drop it. Both
cues use the same pitch (1568 Hz, distinct from this mod's other three
tones: 220/880/1175 Hz) and differ only in count â€” one beep vs. two
60ms-apart â€” matching the request verbatim.

**WAIT tone (MESSAGE)**: fires the instant a window's dialog state byte
STOPS CHANGING while it holds real text â€” not by hardcoding the
`paging` transition's specific "about to page" values (14/4), because
the "about to close" hold uses OTHER values that vary by window
(observed: win=0 held at 6 for ~1.2s before its 6â†’7 close in the
2026-07-19 log). "Stopped changing" is the one signal common to every
hold, since this mod's own state-machine comments already establish
that the byte visibly advances every frame while the typewriter is
still revealing text. Edge-triggered per window
(`WindowState::wait_tone_armed`): fires once per hold, disarmed the
moment state changes again OR a fresh dialog_id arrives (needed
because win=2/3's state byte "never transitions" â€” research Â§6 â€” so
CLOSE never fires there to reset it; without the DLGID-branch reset
too, those windows would get exactly ONE wait tone ever, for their
first dialog, then silence for the rest of the session). Independent
of `speak_dialog` (voice-acting-mod players still get no other cue for
when the game is actually ready for their button press). Guarded by
`was_pending` (captured BEFORE the DLGID/PENDING/PAGE/CLOSE chain runs
each frame) so it can't fire on the very frame the intro just started
being announced â€” win=2/3's state is stuck at a single value forever,
so without this guard the tone would coincide with, rather than
follow, the TTS intro on those windows.

**CHOICE tone (ASK)**: fires directly off "a new dialog_id was detected
on the ASK opcode" â€” simpler, since a choice menu's presentation IS
that event, no state-hold heuristic needed. Independent of
`speak_choices` for the same reason the wait tone is independent of
`speak_dialog`.

New config: `dialog_wait_tone` / `dialog_choice_tone`, both default
true, both documented in the shipped `ffvii_accessibility.cfg`
template. Built clean, deployed both installs 2026-07-20 (hash-
verified). VERIFY next play session: the wait tone lands once per hold
across ordinary multi-page AND single-page dialogs (not per frame,
not missing); the choice tone fires once per ASK menu, distinguishable
by ear from the single wait tone.

### v2.30.6 (2026-07-20): wait tone retuned, ASK cursor's real starting line found, comma decoded

Same-day play report on the v2.30.4/v2.30.5 build surfaced three
findings, all resolved from the SAME session's debug log
(`ffvii_accessibility.log`, debug_log=true) â€” no new live scan needed.

**(1) Wait tone fired early and sometimes twice per box.** The log
explained it precisely: win=0's dialog state byte does NOT advance
every frame like win=1's does â€” it PARKS at value 2 for the entire
typing duration (~900ms observed: `1->2` then nothing until `2->14`
933ms later) before jumping, in ONE atomic transition, straight to 14
(the real "waiting to page" hold) or similarly to 6 (observed holding
~1.2-3.4s before `6->7` close). v2.30.5's "state unchanged this frame"
heuristic could not tell "parked at 2 because still typing" from
"parked at 14 because done" â€” both are just holds â€” so it fired almost
immediately after typing started (a false EARLY tone), then fired a
SECOND time when state legitimately reached 14/6 (a true but redundant
tone): exactly the player's "beeps multiple times... for every dialog
box" and "have to press 2-3 times" reports (the first press landed
while the game was still mid-typewriter and did nothing).

Fix: three-tier evidence-based classification instead of one generic
"unchanged" rule (`WindowState::state_change_tick`, updated whenever
`current_state != last_state`):
- **{4, 6, 14}** â€” confirmed terminal "waiting" values (14/4 already
  known from the `paging` transition; 6 newly confirmed from this
  log's `6â†’7` close pattern) â€” fire after a SHORT hold (80ms, ~2-3
  polls). Not zero-delay: win=1's climb passes THROUGH 14 transiently
  (one poll) en route to its own higher resting value, so requiring it
  to still be there on the NEXT poll is what separates "genuinely
  parked" from "just passing through".
- **{1, 2}** â€” confirmed NON-terminal (opening animation / actively
  typing, direct evidence from win=0's ~900ms hold) â€” NEVER fire here
  regardless of hold duration; time alone cannot distinguish "still
  typing a long message" from "done", only the value can.
- **anything else** (0, 3, 5, 8, win=1's arbitrary data-dependent
  resting values, win=2/3's permanent 0) â€” fall through to a 300ms
  debounce, comfortably longer than any observed per-poll climb step
  (~33ms) so it never fires mid-climb, short enough to stay responsive
  for windows that settle quickly.

This is genuinely two different window behaviors (win=0-style small
discrete state machine vs. win=1-style dense per-tick counter), not
one number to retune â€” a value-based whitelist is required for the
first, a debounce for the second, and neither alone covers both.

**(2) ASK choice cursor spoke the right text at the wrong position** â€”
closes the SPECULATIVE flag from v2.30.4. Player report: "only one
will speak and it is the first choice but... at the end of the choice
set instead of the beginning." Root cause found by extending
ff7_ask_cursor_static.py's disassembly of
`field_opcode_ask_update_loop_6310A1` much further
(`ff7_ask_lines_static.py`, dumped 0x800 bytes instead of 0x140): the
ASK opcode carries **FOUR** script-byte parameters, not two â€”
window_id(+2)/dialog_id(+3) as already known, PLUS **first_line(+4)**
and **last_line(+5)**. The cursor-move case bodies explicitly clamp
the live option value to `[first_line, last_line]`
(0x631311-0x63136F: compare/clamp against `[ebp+0x14]`=last_line and
`[ebp+0x10]`=first_line). Choice text routinely has one or more
leading QUESTION lines before the selectable options begin (log
evidence: win=0 id=6's 4-line text was `["", "Buy one", "",
"Forget it..."]` from `FF7Text::DecodeLines`, and the FIRST live
ASKMENU_OPTION read was 1, not 0 â€” pointing straight at "Buy one",
skipping the leading blank). v2.30.4 assumed the cursor always starts
at option 0 (`ask_lines[0]`), which is only true when there is no
leading line at all â€” otherwise it silently pointed at the WRONG
`ask_lines` entry from the very first cursor move onward.

Fix: read `first_line` via `FF7Addr::get_opcode_param_byte(3)` (and
`last_line` via index 4, for debug visibility) when the choice's intro
speaks, and seed `ask_last_option = first_line` instead of hardcoding
0. `ask_lines[N]` already lines up with the game's own line N (both
split on the identical newline bytes), so no other index transform
was needed â€” just the correct starting baseline. This is no longer
speculative: the fix is derived directly from the game's own clamp
logic, not a guess.

**(3) `0xE2` decodes as a comma, not a gap.** Cross-checked ~20
independent raw dumps from the same session's log â€” 0xE2 appears
exactly where a comma belongs in every one ("Fine, I'll do it",
"What's wrong, Cloud?", "Come on, let's go", "Heads up, here it
comes", "Say, do you...", zero counterexamples). Previously it fell
into the generic "unknown control byte" branch (v2.30.4: guard a
space, no character) â€” technically non-gluing but silently dropped
real punctuation, and was almost certainly the deeper truth behind the
Wedge "Hey [item name] What about our money?" line's second half:
`Wedge: "Hey` + [0xE2] + `[0xEB dynamic token]` + `What about...` reads
correctly as `"Hey, [something], what about our money?"` once the
comma is restored. `decode_walk` now emits `,` for this byte directly
(no source table names it â€” this is a live-corpus finding).

**Residual, NOT fixed this pass â€” scoped for a dedicated
investigation**: the `[item name]`/`[number]`/`[target]`/etc.
placeholders for 0xEB-0xF0 mid-string dynamic tokens are STILL
generic stand-ins, and are very likely often WRONG (the Wedge line's
token is almost certainly Barret's name, not an item, given "Hey,
[???], what about our money?" â€” Wedge addressing the party leader
about their pay is the well-known scene). This is a PRE-EXISTING v1
limitation, documented in ff7_text.h's own header comment since day
one: "the game resolves them at render time from script memory banks
that are not trivially accessible from our hook context" â€” i.e. the
same 4-byte token header may represent an item, a number, OR a name
depending on what value the game's own variable bank currently holds,
which our static byte decoder cannot see. A live sample
(`08 0A 3E 05 01` before a page break, from the same log) also
decoded as pure garbage under the "always ASCII" assumption for
bytes â‰¤0x5E, suggesting there may be YET MORE control-code structure
in this range that isn't captured by ff7tk's table either. Properly
resolving either needs a dedicated investigation into FF7's live
variable-bank system (bank/address resolution, likely reading the
same bank memory the field script VM itself uses) â€” out of scope for
this pass; noted in TODO.txt.

No new addresses beyond ASKMENU_OPTION's already-documented first_line
sibling (a param index, not an address). Built clean, deployed both
installs 2026-07-20 (hash-verified). VERIFY next play session: wait
tone fires once per hold, not early, not doubled; ASK choice cursor
announces the CORRECT highlighted line as you arrow through, including
nested choice-leads-to-choice trees; commas read naturally.

### v2.30.7 (2026-07-20): pagination actually splits on-screen now; ASK bug still open, better diagnostics shipped

Same-day play report on the v2.30.6 build: the wait tone now fires
correctly once per hold ("no longer beeps multiple times"), but two
bugs remained.

**(1) MESSAGE pagination went silent after page 1 â€” root cause: not
every on-screen page break has a byte marking it.** Player description
matched a dialog whose STATE MACHINE still fired real `PAGE`
transitions (confirming multiple actual screens), but
`FF7Text::DecodePages()` (v2.30.4) returned only ONE page for it â€” no
`(N pages)` in the log for N>1, meaning there was no 0xE8/0xE9 anywhere
in that string. DecodePages() could only ever catch AUTHOR-PLACED hard
breaks; it had no way to know where the RENDERER would additionally
soft-wrap a long unbroken passage once it ran out of the ~4 lines FF7's
standard dialog box can show at once. Confirmed independently in the
2026-07-19 log too: `id=4`'s (1 pages) result coexisted with a real
`4â†’8 [PAGE]` transition â€” the exact mismatch this explains.

Fix: `FF7Text::DecodePages()` is retired; `FF7Text::DecodeMessagePages()`
replaces it, built on the SAME line-splitting `decode_walk` uses for
DecodeLines (extended with a new optional `hard_break_out` vector
tracking which boundary was a page-break byte vs. a plain newline).
Lines are grouped into pages of up to **4** (FF7's documented standard
message-window line capacity â€” an ASSUMPTION, not something read from
the game; the first thing to revisit if a future report shows pages
breaking early/late relative to the screen), but an explicit page-break
byte still forces an early close regardless of line count, so
deliberately short hard-broken passages (dramatic pauses) are still
respected. `speak_page()`'s existing bounds check
(`next_page >= pages.size()` â†’ silent no-op) means an imperfect line-
count guess degrades gracefully â€” worst case a page or two is
mistimed, never a crash or garbage speech, and it can never be WORSE
than the prior all-silent failure mode.

**(2) ASK choice-menu cursor: still wrong, cause NOT YET FOUND â€” but
the v2.30.6 first_line fix is confirmed at least partially correct.**
The session log for the Aeris flower-girl choice shows:
```
ASK win=2 lines=6 first_line=2 last_line=3
ASK win=2 option 2->3
ASK win=2 option 3->2
ASK win=2 option 2->3
```
first_line/last_line (2/3) are exactly what the player's own
description implies (a 2-option choice), AND the cursor-change
DETECTION is firing correctly for both directions (2â†’3 and 3â†’2) â€” so
the v2.30.6 fix's mechanism is doing what it was designed to do. The
player report ("first choice spoken at the bottom instead of the
beginning; arrowing back up to it, nothing at all") means
`ask_lines[2]`/`ask_lines[3]` likely do NOT hold the two answers the
way assumed â€” but WITHOUT the actual line CONTENT (the log only had
counts, not text) this can't be pinned down further, and a third blind
index guess isn't warranted after two misses.

Shipped instead: `log_raw_bytes()`'s capture cap raised from 18 to 256
bytes (the truncated dumps in the 2026-07-19/20 logs repeatedly cut off
exactly where the interesting bytes were), and a new `log_lines()`
helper dumps every decoded page/line's FULL TEXT (not just a count) for
both MESSAGE pages and ASK lines â€” the next session's log shows the
actual mismatch directly, no hex hand-decoding required. The nested
"choice leads to another choice tree, not spoken at all" report is a
SEPARATE, more severe symptom (not just wrong-line, but silent
including the intro) with no log evidence yet to explain it â€” flagged
for the same next-session diagnostic pass.

Built clean, deployed both installs 2026-07-20 (hash-verified). VERIFY
next play session: MESSAGE dialogs speak one beat per real on-screen
page turn, no dead silence; capture a fresh debug log through an ASK
choice (ideally the SAME Aeris scene) so `ASK[i]: '...'` lines pin down
the exact indexing mismatch.

### v2.30.8 (2026-07-20): countdown timer no longer resurrects itself from a stale save

Player report: "When I load the game from the slums, the timer from
the escape starts again immediately. It should be cleared or
something."

**Root cause, confirmed exactly by the same-session debug log**:
```
TIMER value jump 4294967295 -> 596 (re-detecting)
TIMER started: 595 seconds
TIMER tick 595 -> 594 (1000ms)
TIMER tick 594 -> 593 (1063ms)
...
```
`COUNTDOWN_TIMER_SECONDS` is savemap state (ff7_addresses.h's own doc
comment already flagged this when the address was found: "Being
savemap state, the timer persists in saves"). The No.1 Reactor escape
was completed with ~596 seconds still on the clock â€” FF7 never resets
this field to 0 once the escape ends, and nothing in vanilla gameplay
cares, because the on-screen clock window (WSPCL) that renders FROM
it closes with the escape and nothing ever reads the value again. But
the field keeps ticking down once per real second IN THE BACKGROUND,
FOREVER, completely invisibly in vanilla play â€” and that ongoing
countdown is exactly what got written into every subsequent save. On
a fresh game launch loading that save, TimerThread's `have_last`/
`running` state (a background thread, lifetime = process run) starts
fresh, reads 0xFFFFFFFF once (pre-init garbage, the "value jump" line),
then reads the REAL leftover value (596) and â€” because it's still
actively decrementing â€” announces "Timer started" the instant the next
real tick registers, deep in the slums, nowhere near the reactor.

**Fix**: a live opcode hook, not a value heuristic. STTIM (opcode 0x38,
handler 0x61FCD8 â€” already statically located when this address was
found in v2.34) is the ONLY code that writes a fresh countdown value;
hooking it (same `execute_opcode_table` patch pattern as MESSAGE/ASK)
gives an unambiguous "a real countdown just (re)started" signal that a
stale savemap value alone cannot provide. `Hooks::SttimSeen()` is a
sticky latch â€” false until a live STTIM fires THIS PROCESS RUN, true
for the rest of the session once it does. TimerThread's tick-processing
branch (the one that sets `running=true` and announces) is now gated
on it: while unseen, `last_val`/`have_last` still track the raw value
silently (so a genuine STTIM later doesn't misread as a spurious
"jump"), but `last_change`/`running` are left untouched â€” which also
correctly makes `timer_live` (used by both the automatic announcements
AND the T/Shift+T on-demand readout) false the whole time, so pressing
T while unarmed correctly says "No active timer" instead of reporting
the stale number.

**RESIDUAL RISK, not fixed speculatively**: if a player deliberately
saves WHILE mid-escape (a checkpoint before a hard timed section) and
later reloads that save, this fix would ALSO suppress announcements
until a live STTIM fires again â€” and it's unconfirmed whether the
field's re-entry/resume logic calls STTIM again on a mid-escape load,
or only on the ORIGINAL trigger (a scripted event, likely NOT part of
the field's basic init script that runs on every entry/load). If a play
report shows a genuine mid-escape reload going silent, the fix is
detecting that specific resume case as an ADDITIONAL arm signal, not
reverting this change (the reported bug â€” a stale timer haunting
completely unrelated, already-finished areas â€” is real and confirmed;
this trade-off is a hypothesis about an untested edge case).

No new addresses (STTIM's handler address 0x61FCD8 was already known
from the original v2.34 investigation; opcode 0x38 was already
documented as its opcode number). Built clean, deployed both installs
2026-07-20 (hash-verified). VERIFY next play session: loading a save
well past a completed timed escape stays silent; the NEXT genuinely
new timed sequence (whenever next reachable) still announces normally
(confirms the STTIM hook itself fires correctly, not just that it's
suppressing things).

### v2.30.9 (2026-07-21): ASK choice cursor â€” actual root cause found (suppression, not misalignment)

Two prior attempts (v2.30.4, v2.30.6) both left the SAME symptom alive:
"first choice spoken at the bottom... arrow back up to it, not spoken
at all" for the Aeris flower-girl choice. Instead of another debug log,
the player supplied screen-by-screen CAPTURES of the exact scene
(`Screenshots/Dialogs/flower_girl/`, one image per button press) â€”
ground truth for what each ASK window actually displays.

**What the captures prove**: `fg_2_t1`/`fg_3_t2` show a 4-line window â€”
`Flower girl` (name) / `"What happened?"` (lead-in quote) / `You'd
better get out of here` (option A, cursor here by default) / `Nothingâ€¦
heyâ€¦` (option B) â€” matching the disasm-confirmed `first_line=2,
last_line=3` for a 2-option choice exactly. `fg_5_t3` (a later choice in
the SAME scene, "Buy one" / "Forget it") has NO name or quote line at
all, just the two options. Together these confirm `first_line`/
`last_line` are read correctly and vary legitimately per window â€” the
index math (`ask_lines[first_line]` through `ask_lines[last_line]`) was
right all along. There was no misalignment bug to find.

**Actual root cause** (`hooks.cpp`, `WindowState::ask_last_option` +
`hook_ask`): both v2.30.4 (seeded to `0`) and v2.30.6 (seeded to
`FIRST_LINE`) deliberately initialized `ask_last_option` to the
STARTING option, specifically so the OPTION CURSOR block wouldn't
"re-announce" an option already mentioned inside the `"Choose: ..."`
intro sentence. That suppression was the bug. The intro speaks the
ENTIRE window as one run-on sentence â€” name, lead-in, then every
option, in order â€” so the default-highlighted option only ever gets a
buried, mid-sentence mention, never a clean, isolated announcement the
way every subsequent cursor move gets one. With exactly 2 options and
the cursor starting at the TOPMOST option (no legal "up" move from
there), a player hears nothing but that one buried mention and then
silence on Up â€” exactly "spoken at the bottom [of the run-on intro]...
arrow back up to it [a no-op, already at the top], not spoken at all."
No index misalignment is required to produce that report.

**Fix**: stop seeding `ask_last_option` from `first_line`. Leave it at
the `-1` sentinel the new-dialog branch already sets, so the OPTION
CURSOR block fires once, immediately after the intro finishes, for the
starting option too â€” identically to how it already fires on every
later cursor move. `first_line`/`last_line` are still read and logged
for diagnostics; they're just no longer forced into the change-detector.

No new addresses; pure logic fix in `hooks.cpp`. Built clean, deployed
both installs (hash-verified). VERIFY next play session: the Aeris
2-option choice (and others) now speak the starting/default option once
right after the `"Choose:"` intro, with no other regressions to the
cursor-move announces that already worked.

**Also confirmed by the SAME screenshot set, a SEPARATE unfixed bug**:
`Screenshots/Dialogs/reactor_scene/` (rs_1..rs_12) shows `rs_6` ("Watch
out!") and `rs_7` ("This isn't just a reactor!!") are two distinct
on-screen pages â€” a borderless, centered, no-name window style, unlike
the framed name/quote boxes elsewhere in the same sequence â€” but the mod
spoke both as one utterance on `rs_6` then went silent on `rs_7`.
`DecodeMessagePages`' `kLinesPerPage=4` heuristic (v2.30.7) never forces
an early page break for a 2-line total, so absent an explicit
0xE8/0xE9 page-break byte between the two lines, they merge into one
page. This is the first concrete proof that the `kLinesPerPage=4`
assumption (always flagged as unverified) is wrong for at least this
window style. NOT fixed this pass â€” two competing explanations (a
missed explicit break byte vs. a genuinely smaller per-window capacity)
that only a raw-byte log through this exact moment can distinguish; see
TODO.txt for the full writeup and what to capture next.

### v2.30.10 (2026-07-21): ASK choice cursor â€” the REAL misalignment, found from a raw byte dump

Player re-tested the exact same Aeris scene the SAME DAY v2.30.9
shipped: "still broken, same pattern as before." v2.30.9's claim above
("no index misalignment required... there was no misalignment bug to
find") was WRONG â€” it was reached from screenshots alone, which show
what's ON SCREEN, not the raw byte stream. A fresh `debug_log=true`
replay of the identical scene supplied the actual raw dump, and it
overturns that conclusion completely.

**The raw bytes** (from the log, `MSG raw(ASK/PENDING)` lines):
- Aeris 2-option choice: `"Flower girl" E7 '"What happened?"' E7 E0
  "You'd better get out of here" E7 E0 "Nothing...hey..."`
- "Buy one"/"Forget it" (later choice, same scene): `E0 "Buy one" E7 E0
  "Forget it"`

`decode_walk` (`ff7_text.cpp`, shared by `Decode()`, `DecodeLines()`,
and `DecodeMessagePages()`) treated 0xE0 and 0xE7 as independent,
unconditional segment-enders when `split_lines` is true. An `E7`
immediately followed by an `E0` â€” or a bare leading `E0` â€” is TWO
breaks with NOTHING between them, so decode_walk inserted a spurious
EMPTY entry before every real option. Logged proof
(`log_lines`/`ASK[i]`): the Aeris window decoded to **6** entries â€”
`'Flower girl'`, `'"What happened?"'`, `''`, `"You'd better get out of
here"`, `''`, `'Nothing.hey.'` â€” with the two real options landing at
indices **3 and 5**, not 2 and 3. The "Buy one" window decoded to
**4** entries â€” `''`, `'Buy one'`, `''`, `'Forget it'` â€” real options at
**1 and 3**, not 0 and 1.

But the game's own `FIRST_LINE`/`LAST_LINE` opcode params count REAL
CONTENT lines (the Aeris window visually has exactly 4: name, quote,
option A, option B â€” matching the screenshots), not raw break-byte
count. So `first_line=2` pointed at OUR blank artifact (silently
no-op'd by the existing `if (!line.empty())` guard â€” explaining why the
very first announce was silent) and every subsequent cursor move
announced the PREVIOUS option's text, one slot behind the game's actual
selection. This â€” not the v2.30.9 suppression bug, which was real but
insufficient on its own â€” is what reproduced "spoken at the bottom...
not spoken at all" even after v2.30.9 shipped: v2.30.9 fixed the
missing *first* announcement's suppression, but the announcement it
un-suppressed was still reading the WRONG array slot.

**Fix** (`ff7_text.cpp`, `decode_walk`'s newline case): a newline-class
byte (0xE0 or 0xE7) now only ends the current segment when that segment
already holds real content; two in a row (or a leading one with nothing
preceding it) collapse into a single break instead of manufacturing an
empty entry. This is a `decode_walk`-level change, so it also affects
`DecodeMessagePages` (MESSAGE pagination) â€” reviewed and judged safe/
likely beneficial there too: a genuinely empty rendered line is not
something normal dialogue ever intentionally produces, and collapsing
it stops such an artifact from silently consuming a slot toward
`kLinesPerPage`'s cap.

**Verified OFFLINE before redeploying** (per this project's established
dry-run practice â€” see the Method Playbook): a standalone Python
re-implementation of the new `decode_walk` logic, fed the EXACT two raw
byte dumps above, reproduced the game's own line count precisely â€”
6â†’4 entries for Aeris (`first_line=2` now correctly indexes `"You'd
better get out of here"`, `last_line=3` â†’ `"Nothing...hey..."`) and 4â†’2
for Buy one/Forget it (`first_line=0`/`last_line=1` now index each
option directly, no leading blank). No new addresses; pure decoder
logic fix. Built clean, deployed both installs (hash-verified). VERIFY
next play session: the Aeris 2-option choice (and others) now speak the
starting option once right after the intro AND track the cursor
accurately as it moves in both directions.

LESSON: screenshots are ground truth for what's ON SCREEN, but this
bug lived in the RAW BYTE STREAM between screen-rendered lines (an
artifact of how two control bytes combine) â€” no screenshot could ever
have revealed it. When a fix based on visual evidence doesn't hold up
on immediate re-test, that is the signal to go back for the actual byte
data, not to re-interpret the same screenshots differently.

### v2.30.11 (2026-07-21): the "silent nested choice" was a cross-field dialog_id collision

Same-evening play-test of v2.30.10 (log 20:13â€“20:14) CONFIRMED the
decode fix â€” Aeris choices 1 and 3 decoded to exactly the right line
counts (6â†’4 and 4â†’2), spoke the starting option, and tracked the cursor
both directions. But choice 2 ("Don't see many flowers around here" /
"Never mind") was totally silent â€” no intro, no choice tone, no cursor
announces â€” and the log caught the whole thing:

```
[20:14:01.916] ASK win=0 7->0 [skip]
[20:14:01.950] ASK win=0 0->1 [START]      <- opened fine
[20:14:02.982] ASK win=0 2->6 [skip]
[20:14:11.383] ASK win=0 6->7 [CLOSE]      <- closed fine
```

A full openâ†’close lifecycle with **no `[DLGID] pending` line between
them**: `is_new_ask_dialog` (`dialog_id != last_dialog_id`) never fired.
The stale value is visible earlier in the same log â€” the last win=0
dialog before entering the flower-girl field was `MSG win=0 id=3` at
20:12:15, on a DIFFERENT field. dialog_id is a field-local script
parameter; the flower-girl field's second choice evidently also carries
id=3 (its scene neighbors are ids 0/1/5/6), colliding with the
leftover. Every downstream action gates on that one detector â€” the
intro speak, `dialog_choice_tone`, and `ask_lines` population (whose
emptiness also no-ops the OPTION CURSOR block) â€” producing total
silence. This retires the old "nested choice tree is silent" theory:
nesting had nothing to do with it, and the same collision could
equally silence a MESSAGE on any field.

**Fix**: `reset_windows_if_field_changed()` (hooks.cpp) â€” on every
`FIELD_FILE_BUFFER` pointer change (a new field always allocates a new
buffer; the exact signal `log_field_header_if_changed` has relied on
all along), clear every `s_window[]` slot's dialog tracking:
`last_dialog_id` back to the 0xFF sentinel, pending/pages/ask state
cleared, tone arming reset. Called at the top of BOTH `hook_message`
and `hook_ask`, so the reset executes on the new field's first dialog
opcode, strictly before that opcode's own dialog_id comparison â€” and
since that call IS the new field's first dialog, no open dialog can
predate it: clearing every slot is safe by construction. Logs
`FIELD changed: window dialog tracking reset.` for future traceability.

LESSON: a detector keyed on a SCRIPT-LOCAL identifier must be reset at
the identifier's scope boundary. `last_dialog_id` was scoped per
window-slot but dialog_id itself is scoped per FIELD â€” the mismatch sat
latent for the mod's entire life (v1.4 onward) until two fields
happened to reuse the same id on the same window slot back-to-back.
The "nested tree" framing was a red herring from correlation: nested
choices simply make back-to-back same-window ASKs (and thus collisions)
more likely to be noticed there first.

Deployed both installs (hash-verified). VERIFY: replay the Aeris tree
(after at least one field crossing) â€” all three choices should speak;
watch generally for dialogs that used to go silent right after screen
changes.

### v2.30.12 (2026-07-22): ASKMENU_OPTION demoted â€” the cursor global was never a global

Play-test confirmed v2.30.11 (all Aeris trees now correct), but the
soldier fight-or-flee choices right after went silent. The log
(09:29:32 + 09:30:11) shows a NEW failure mode, different from every
previous ASK bug: decode was perfect (`ASK[2]: 'Fight them!'`,
`ASK[3]: 'Later!'`, first_line=2/last_line=3 correct), but the cursor
read `option -1->0` â€” index 0 = the 'Cloud:' NAME line, not the
highlighted option â€” and then **never changed again** for the entire
choice, both times. Meanwhile the Aeris choices in the SAME session
(including on the same window id, win=2) had tracked flawlessly.

**Root cause â€” re-reading the two existing static logs together**:
`ff7_ask_cursor_static` (0x618E83) had already proven the live cursor
is a STACK LOCAL: read in from a script variable via helper 0x60F750,
passed by address (`lea ecx,[ebp-4]; push ecx`) into update loop
0x6310A1, written back via 0x60FA7D on exit. The variable it syncs
with is the ASK opcode's own bank/address parameter â€” PER DIALOG.
`ASKMENU_OPTION` (0xCC14D1), found by live scan against one particular
dialog, is simply THAT dialog's script variable. Dialogs that name the
same variable track "perfectly" (all the Aeris-field choices); dialogs
that name a different one leave 0xCC14D1 stale and frozen (the soldier
field's). The scan could never have distinguished a true global from
the scanned dialog's output variable â€” only cross-field play could.

**The dialog-independent readout was sitting in the OTHER static log
all along**: `ff7_ask_lines_static` (0x631384â€“0x63139C) shows the
update loop mirroring the clamped cursor into the ASK per-window
struct EVERY accepting frame (not just on key presses):
`u16[0xCFF5DE + winÂ·0x30] = lineÂ·16 + 6` â€” the highlight's pixel Y
(16 px per line, 6 px top margin). Window-indexed, dialog-independent,
already-clamped.

**Fix**: new `ASK_CURSOR_PIXEL_Y`/`ASK_WINDOW_STRIDE` +
`get_ask_cursor_line()` (ff7_addresses.h) â€” `line = (yâˆ’6)>>4`, with
yâ‰¥6 and 16-px-boundary validity checks returning âˆ’1 (caller skips the
frame; ask_lines bounds check unchanged). hook_ask's OPTION CURSOR
block now reads that instead of ASKMENU_OPTION, which is demoted in
Â§4/Â§14 to provenance-only. Also mapped in passing, same struct stride
0x30: 0xCFF5D2 input-armed byte, 0xCFF5DC = 5 while choosing,
0xCFF5E4 = 7 on confirm, 0xCFF5E6 state-flag word (bit 0 gates the
input branch).

LESSON (two): (1) a live scan finds A memory cell that correlates with
the probed behavior, not THE authoritative source â€” when a scanned
address works for some content and freezes for other content, suspect
a per-CONTENT variable (script var, bank cell) rather than a broken
read; (2) the decisive disasm line (0x63139C) had been sitting in an
already-captured log since 2026-07-20 â€” when a new failure mode
appears, re-read the EXISTING static logs against the new question
before launching new investigations.

Deployed both installs (hash-verified). VERIFY: the soldier
fight-or-flee choice (both the pre-battle 4-line and post-battle
2-line variants) speaks its options and tracks the cursor; Aeris trees
still work (regression check for the source swap).

### v2.30.13 (2026-07-22): stale-mirror double-speak fixed + question/choice pause

v2.30.12 PLAY-CONFIRMED same day ("All the dialog choices that I
encountered spoke properly now") with two polish reports: (1) some
trees spoke one choice multiple times instead of each once; (2)
request for an audible pause between the question ("What happened?")
and the first choice announce.

**(1) Stale mirror at window open â€” log-diagnosed (10:01:39)**: the
pixel mirror `u16[0xCFF5DE+winÂ·0x30]` keeps the PREVIOUS ASK's resting
position until the new window's update loop starts accepting input
(0.5â€“1.3s after open across the session's examples). At the soldier
choice's open, win=2's mirror still held 3 â€” the option picked in the
previous win=2 choice (Aeris tree) â€” so `option -1->3` announced
'Later!' spuriously, then `3->2` announced 'Fight them!' when the game
clamped the real cursor in ~900ms later. One choice heard twice. At
the post-battle 2-line re-ask the stale 3 fell OUT of ask_lines'
bounds and was silently skipped â€” which is why only SOME trees showed
the symptom. Fix: `ask_mirror_baseline` captures the mirror's raw
value at the PENDING frame (the last moment before tracking starts);
until the first announce, a reading equal to the baseline is presumed
stale and skipped, UNLESS it equals `first_line` â€” correct regardless
of freshness, because the update loop clamps the cursor into
[first,last] and a fresh variable starts there. Accepted residual
(documented in the struct comment): a re-asked dialog whose script
variable preserved a mid-range cursor that happens to equal the stale
baseline misses only its initial announce (first keypress recovers) â€”
indistinguishable from staleness without more state, and strictly
better than announcing a wrong option.

**(2) Intro restructure â€” also retires the intro/option double-read**:
the intro previously spoke the ENTIRE window (name + question + every
option) as one run-on utterance, which the immediate option announce
then interrupted at an arbitrary point (whenever the mirror happened
to become valid â€” same-frame at some windows, 1.3s in at others).
Now: intro = "Choose:" + only the CONTEXT lines (indices <
first_line), and the FIRST option announce uses interrupt=false so it
QUEUES after the intro â€” the TTS utterance boundary supplies the
requested pause with no timing games. Options are no longer read in
the intro at all: each choice is heard exactly once (the highlighted
one right after the question, the others as the cursor reaches them).
Subsequent cursor moves keep interrupt=true for snappy flipping. A
window with no context lines (first_line=0, e.g. "Buy one"/"Forget
it") gets a bare "Choose:" intro followed by the queued first option.

New per-window state: `ask_first_line`, `ask_mirror_baseline` (reset
on new dialog, close, and field change). No new addresses. Deployed
both installs (hash-verified). **PLAY-CONFIRMED 2026-07-22
("Everything seems to work now") â€” closing the entire ASK chain:
v2.30.9 (suppression) â†’ .10 (double-break split) â†’ .11 (cross-field id
collision) â†’ .12 (per-window cursor mirror) â†’ .13 (stale baseline +
intro restructure), all verified in play.**

### v2.30.14 (2026-07-22): stale-timer suppression play-confirmed; unarmed-tick diagnostic

Player bonus test of the v2.30.8 machinery: replayed the No.1 Reactor
escape, saved on the Sector 8 street fields AFTER completing it
(Slot 3, caption "No.1 Reactor" â€” a save that, per the v2.30.8
finding, carries the invisible still-ticking leftover timer), then
loaded that save from a FRESH LAUNCH (session log 10:44). Result:
completely silent â€” no spurious "Timer started", no announcements.
**That is the v2.30.8 stale-timer suppression confirmed in its
strongest form**: a cold-start load of a save with a ticking stale
value, the exact shape of the original 2026-07-20 bug report.

Log-quality gap found while verifying: the unarmed TimerThread branch
logged nothing, so the log alone couldn't distinguish "the save
carried no timer" from "a ticking value was correctly suppressed" â€”
the conclusion above needed field-trail inference (the loaded save's
position on the post-escape street fields). v2.30.14 adds a
once-per-process-run diagnostic when the gate suppresses a sane,
nonzero, actively-decrementing value:
`TIMER ticking value N suppressed (no STTIM this run: stale leftover,
or a mid-countdown save load)`. No behavior or speech change.

The v2.30.8 RESIDUAL stands but is likely moot for No.1: a save made
DURING a countdown and loaded fresh would also be suppressed (whether
FF7 re-fires STTIM on such a load is still unproven either way), but
the No.1 escape route has no save point, so the case can only arise at
a later timed sequence that allows saving. When one is reached, the
new diagnostic plus a play report will settle it conclusively.

### v2.30.15 (2026-07-23): win=1 false CLOSE + same-id re-talk blindness â€” two bugs, one log

Player reports with screenshots: some shop owners not read
(`unread_dialog_1.jpg`, Sector 5 "I'm not opening up. Go away!!"), the
7th Heaven bar conversation's choices silent
(`unread_choices_1.jpg`, "Did you fight with Barret?" Yeah/Not this
time), and the wait chime missing for some dialogs. The same-session
log split this into two distinct mechanisms:

**Bug 1 â€” false CLOSE on counter-style windows.** The 7th Heaven ASK
(win=1, id=4) decoded PERFECTLY â€” `ASK[1]: 'Yeah'`, `ASK[2]: 'Not this
time'`, first_line=1/last_line=2, intro spoken â€” and then:

```
[10:37:21.688] ASK win=1 3->5 [skip]
[10:37:21.721] ASK win=1 5->7 [CLOSE]   <- the counter PASSING THROUGH 7
```

win=1's state byte is the DENSE COUNTER style (0â†’1â†’3â†’5â†’7â†’9â†’â€¦â†’rest,
documented since the v2.30.5 wait-tone work). It passes THROUGH 7 one
frame after the intro speaks; the close detector (`current==7`) treated
that as the dialog closing: `TTS::Silence()` cut the speech ~270ms in
(same for the win=1 MESSAGE at 10:37:13 â€” spoken at .354, silenced at
.622) and cleared `ask_lines`, leaving the OPTION CURSOR block a
permanent no-op (empty lines) â€” the whole choice muted. Every win=1
dialog in the session shows the same `5->7 [CLOSE]` signature. Fix:
CLOSE now commits only on the SECOND consecutive frame at 7
(`close_handled` per-window latch, reset when the state leaves 7, plus
a `!pending_speak` guard for the new-dialog-arrives-during-the-7-hold
race). A counter never repeats a value, so it can never commit; the
discrete windows (win=0/2) genuinely park at 7 for the whole close
animation, so their close actions land one frame (~33ms) later â€”
imperceptible.

**Bug 2 â€” same-id re-talks never re-spoke.** The Sector 5 shop
dialogs (10:32:54, 10:33:06, 10:33:35) ran complete state cycles
(restâ†’0â†’climbâ†’rest) with ZERO `[DLGID]` lines â€” never spoken at all.
Re-talking to an NPC re-runs the same MESSAGE opcode with the SAME
dialog_id, and `last_dialog_id` â€” deliberately kept equal to the id
after close to stop one-frame re-fires â€” makes the detector
permanently blind to the repeat. This has been latent since v1.4;
nobody had re-talked to the same NPC during focused testing before.
Fix: from-idle RE-ARM â€” on the state edge out of 0 (a fresh window
open: win=0 goes 7â†’0 then 0â†’N, win=1 goes restâ†’0 then 0â†’N) with
nothing pending, `last_dialog_id` resets to the 0xFF sentinel so the
DLGID branch fires even for an identical id. The `!pending_speak`
guard keeps the normal different-id path (which pends on the xâ†’0 frame
itself) from being double-triggered. LIMITATION: win=2/3-style windows
whose state byte never moves produce no idle edge â€” their same-id
re-talks stay undetectable (pre-existing; would need a different
signal).

**Chime report â€” undiagnosable, now instrumented**: the wait tone had
NO log line, so "tone never armed" vs "tone armed but drowned out"
could not be distinguished for any dialog. Every arm now logs
`MSG win=N wait tone (state=X held=Yms)`. Note the false CLOSE also
reset `wait_tone_armed` mid-dialog on win=1, so Bug 1's fix may cure
some of the missing chimes by itself.

RESIDUAL to watch: whether win=1's ASK option-cursor announces work
now that `ask_lines` survives â€” the pixel mirror (0xCFF5DE+0x30 =
0xCFF60E) read invalid at the PENDING frame (`baseline=-1`) and no
option transitions were logged before the false CLOSE wiped the state;
if options still don't announce on win=1 choices, the win=1 mirror
instance needs its own look.

LESSON: the two window state-machine STYLES (small discrete enum vs
dense per-tick counter) were already a documented, hard-won fact from
the wait-tone work (v2.30.5/6) â€” but only the wait tone was audited
against both styles at the time. Every OTHER consumer of the state
byte (close detection, start detection) kept assuming the discrete
style. When a data source is discovered to have two behavioral modes,
audit EVERY reader of that source against both modes, not just the one
that prompted the discovery.

### v2.30.16 (2026-07-23): opcode-call-gap reopen detection â€” re-talks for every window style

Same-day play-test of v2.30.15: win=1 re-talks CONFIRMED working (the
log shows id=43 speaking on both talks, wait tones firing and logged)
â€” but "the last conversation I had didn't repeat," and the log
identified it as a **win=3** dialog: valid text on screen (the tone
block armed with `state=0 held=169281ms`), same id, and ZERO state
transitions â€” exactly the "state byte never moves" window style the
v2.30.15 entry had already flagged as beyond the from-idle re-arm's
reach. The same log also caught the from-idle re-arm DOUBLE-SPEAKING:
a window whose state byte is still parked at 0 when the dialog opens
can complete DLGID+PENDING (speak) BEFORE the 0â†’1 edge arrives, and
the edge then re-armed and re-spoke the identical dialog 200ms later
(win=1 id=43: `[PENDING] speaking` at 10:58:16.146 AND .345).

**Fix â€” `rearm_if_reopened_after_gap()`, the general mechanism**: the
MESSAGE/ASK opcode executes every frame (~33ms) while its dialog is on
screen and not at all in between (the field script blocks on the
opcode, then moves past it). Therefore the FIRST hook call for a
window after >500ms of call silence is, by construction, a brand-new
dialog â€” independent of dialog_id, independent of window style. Called
at the top of both hooks' in-range paths; resets `last_dialog_id` to
the 0xFF sentinel so the DLGID branch fires even for an identical id;
logs `MSG/ASK win=N reopened after Xms gap (re-armed)`. Structurally
immune to the double-fire (the gap exists exactly once per reopen â€”
every subsequent call refreshes `last_hook_tick`), and the
continuously-running special windows (WSPCL clock, gil) never present
a gap, so they can never spuriously re-arm. The from-idle state
re-arm stays as a backup (for any window whose opcode hypothetically
keeps running between dialogs), now guarded by a `last_speak_tick`
age check (>1500ms) that kills the observed double-speak.

Accepted trade-off, judged a FEATURE: a dialog interrupted mid-display
by anything that freezes the field for >500ms (battle transition)
re-speaks when it resumes â€” for a blind player that's context
restoration, not repetition.

New per-window state: `last_hook_tick`, `last_speak_tick` (stamped in
both PENDING branches; reset on field change). No new addresses.
Deployed both installs (hash-verified). VERIFY: the win=3-style
conversation re-speaks on re-talk; no double-speak anywhere; shop/bar
re-talks still work.

### v2.30.17 (2026-07-23): counter-window page pacing + the "[item name]" tokens were names all along

Same-day partial confirmation of v2.30.16 (gap re-arm working â€” win=3
re-talks spoke with `reopened after Xms gap` lines; **win=1 ASK cursor
now tracking** â€” `option 2->1` transitions at the 7th Heaven choice,
closing the v2.30.15 residual), plus two new fixes from one screenshot
+ log pass:

**1. First characters cut off per page on win=1 multi-page dialogs**
(player screenshot: `"I was worried."` heard as "was worried").
Counter-style windows re-run their ENTIRE state cycle per PAGE
(restâ†’0â†’climbâ†’rest, same dialog_id, never a 14â†’2/4â†’8 transition). The
v2.30.15/16 from-idle re-arm misread each page rerun as a fresh dialog
and re-decoded the rawptr â€” the live TYPEWRITER pointer, which on a
page rerun starts being consumed IMMEDIATELY (a fresh window open has
~2 frames of grace; a page rerun has none). The one-frame-deferred
PENDING read therefore lost ~3 chars per page. The log caught all
three stages of Tifa's 3-page dialog: `'"I should have known."'`
(complete â€” open race won), `''s always pushing...'` (lost `"He`),
`'was worried."'` (lost `"I `). Fix: the from-idle edge now branches
on cached state â€” unspoken pages remaining â†’ speak the NEXT CACHED
page (the first decode holds the whole message, v2.30.4): correct page
pacing for counter windows with zero re-decode; guarded >600ms since
last speak to skip the dialog's own opening 0â†’1 edge (~170ms after the
PENDING speak â€” the v2.30.16 double-speak's exact signature). No
unspoken pages â†’ the same-id re-talk re-arm as before (>1500ms guard),
backup for never-gapping windows.

**2. The 0xEB-0xF0 "dynamic tokens" are single-byte character names.**
Player note: "Barret's name is getting replaced with 'item 1'" â€” and
this session's raw bytes settle the long-deferred investigation. Tifa's
line: `57 49 54 48 00 EB 1F B3 E7 E0` = "WITH " {Barret} '?' '"' nl nl.
The 4-byte-token reading consumed the `?`, the closing quote, and a
newline as "data bytes" while speaking "[item name]" for what is
Barret's name; the Wedge line ("Hey [item name] What about our
money?") was "Hey, {Barret}..." all along, as the v2.30.6 residual
suspected. Mid-string 0xEAâ€“0xF2 is now one contiguous single-byte
character-name branch (ff7tk eng[]: CLOUD..CID â€” 0xEA/0xF1/0xF2 were
ALREADY handled this way; the split treatment of the middle of the
range was the error). `token_placeholder()` deleted; no variable-bank
investigation needed. If real multi-byte tokens exist in some other
text, their data bytes now decode as VISIBLE garbage in the debug log
â€” re-investigable with evidence, instead of silently eating text.

LESSON: both fixes came from the same principle â€” when the evidence
was re-read as a WHOLE (all three page dumps side by side; the token
byte in its full sentence context), the story was obvious. The
per-page truncation had looked like three unrelated glitches, and the
token bug had sat mislabeled for a week behind a plausible-sounding
"needs a big investigation" framing that two clean byte dumps
overturned in minutes.

### v2.30.18 (2026-07-23): scenery props out of the People list; "marine" = Marlene

v2.30.17 PLAY-CONFIRMED ("The dialog fixes are confirmed"). New player
report from the same bar: the People category listed "swordc, fieldbg
hana, fieldbg cash, fieldbg pinbl, camera, and marine" â€” all
unreachable, none of them people. Almost right: five props and one
mislabeled person.

**The props**: `ClassifyModelLabel`'s fallthrough sent any "fieldbg"
label that matched none of the interactable substrings
(trb/mtra/potion/sparkle/key/saveicn) to MC_PERSON. The offline flevel
catalog shows dozens of such labels game-wide (doors `â€¦dr`, the train
`kisya`, `cos`/`props`/`v2`/`zuta`â€¦) â€” all background scenery: hana =
flower vase, cash = register, pinbl = the pinball machine (its
elevator INTERACTION is a separate line trigger under Triggers; the
model is just its picture). Fix: new `MC_SCENERY` class for unknown
"fieldbg" labels plus a tight evidence-only list of prefix-free props
("camera" exact â€” 1 occurrence game-wide; "swordc*" â€” 3), excluded
from every category INCLUDING All. Proximity chirp unaffected (keys on
talk radius, which props lack).

**The person**: "marine" is Marlene (JP name "Marin") â€” 1 model + 2
entity occurrences game-wide, all in the 7th Heaven bar, standing
behind the counter off the walkmesh (so "no walkable path" was
CORRECT for her). Added `marine`/`marin` â†’ "Marlene" to the dev-word
translation table.

LESSON: the "unknown label â†’ person" default was right for v2.15's
first fields (their unknowns WERE people) but wrong as a fallthrough
for the "fieldbg" namespace, whose whole point is "not a character" â€”
the dev prefix was already carrying the answer; the code just wasn't
listening once the known-item substrings missed.

### v2.30.19 (2026-07-23): positional page turns for state-static windows; parked-model ghosts

Hideout play session (same day): pathfinder "a little buggy" + three
screenshots of unspoken dialog. The log resolved all of it into three
fixes:

**1. win=3 multi-page dialogs silent after page 1.** All three
screenshots were pages 2+ of multi-page dialogs on win=3 â€” the
never-moving-state style. Decode was perfect (Barret's 4-page "Yeah,
you're strong." speech fully cached; the President's 2-page TV
broadcast too), but NO page-turn signal exists for these windows:
no 14â†’2/4â†’8 transitions (win=0's signal), no state-cycle reruns
(win=1's v2.30.17 signal) â€” page 1 spoke, the rest never. Fix:
**positional paging** â€” `DecodeMessagePages` now optionally returns
each page's raw byte offset (decode_walk tracks segment start offsets);
`hook_message` captures the rawptr at decode (`msg_base`) and, for
STATE-STATIC windows only, compares the live typewriter pointer's
offset against the next unspoken page's start (+2 bytes slack for the
page-break-boundary park): entering page N's range = the display
turned to it â†’ speak from cache (no re-decode, so no typewriter race),
re-arm the wait tone with a fresh debounce (win=3 multi-pagers chimed
only on page 1 before). `state_static` starts true per dialog and any
observed state transition clears it, so the positional path can never
double-fire against the state-driven paths. Logs
`positional PAGE x/y (rel=â€¦)`. ASSUMPTION flagged for the next log:
win=3's rawptr advances like win=1's proved to (the v1 doc says the
typewriter pointer behavior is global); if the positional lines never
appear, the pointer is static on win=3 and a different signal is
needed.

**2. Parked-model ghosts in the browser.** The hideout dump showed
models the scene hadn't placed â€” Tifa (upstairs at that moment), the
camera dummy, an ungranted materia â€” ALL at exactly (0,0) with
triangle id 0, passing the off-mesh filter because tri<0 is the only
thing it checked and 0 is a valid triangle id. Visible models can also
read tri=0 (three did) but always with real positions â€” so the parked
signature is the COMBINATION `tri==0 && pos==(0,0)`, now skipped. The
scan re-runs continuously, so a model the script later places appears
normally the moment it gains a real position.

**3. v2.30.18's camera/swordc match missed** â€” the .char labels carry
location-word prefixes (`nible camera`, `modify swordc`), so the
exact/prefix match never hit. Switched to contains-match (both tokens
unique in the game-wide catalog). `sub marine` â†’ "Marlene" confirmed
working via the word-pass (the `sub` prefix is dropped).

### v2.30.20 (2026-07-23): multi-page ASK â€” the choices live on the LAST page

Player reports at Tifa's drink offer: the lead-in dialog was
tone-flagged as a choice, the "choices" spoke as "How aboutâ€¦" + wrong
text, and the real caption ("â€¦something to drink?") never spoke. The
log's raw dump has the whole story in one line â€” the ASK text contains
a PAGE BREAK:

```
EC E7 B2 [How about.] B3  E8  B2 [.something to drink?] B3 E7 E0
[I don't feel like it] E7 E0 [Give me something hard]
```

Page 1 is pure lead-in; the caption AND options are on page 2 â€” and
the game's FIRST_LINE/LAST_LINE params (1/2 here) index lines OF THE
DISPLAYED PAGE. The old code flattened all pages into one line list
and indexed that instead, announcing flat[1] `"How about."` and
flat[2] `".something to drink?"` as the "options". The per-window
pixel mirror is ALSO page-relative (it's the highlight's Y inside the
window), so the flattened list was wrong against both authorities at
once.

**Fix (hook_ask)**: scan for the LAST page-break byte at decode;
`ask_lines` = `DecodeLines(raw + last_break)` â€” page-relative, aligned
with the opcode params and the mirror. Lead-in pages speak as plain
narrative at open (no "Choose:", no tone). The choice page's arrival
is detected POSITIONALLY â€” the typewriter pointer entering the last
page's byte range (+2 slack), the same mechanism as v2.30.19's
positional message paging â€” and fires the choice tone, "Choose:" +
the caption (page-relative context lines), and unlocks the OPTION
CURSOR block, which then queues the highlighted option exactly like a
single-page ASK's opening. Single-page ASKs behave identically to
before (the tone moved from the DLGID frame to the PENDING frame â€”
one frame later, imperceptible); with speak_choices OFF there is no
decode to consult, so the tone keeps its old at-open timing there.

**Pathfinder into the bar counter** (same session): route to Tifa
walks the player into a wall â€” A* legitimately found a path (the
access pool connects the counter area; the game-wide dry run proved
the pool reciprocal), but the game blocks player entry. Hypothesis: a
triangle-locking overlay (the community-documented mechanism for
counters/doorways) that A* must learn to treat as walls â€” scoped
investigation filed in TODO.txt with the log evidence; the talk-radius
still reaches across the counter, matching how sighted players
interact with Tifa without walking behind the bar.

### v2.30.21 (2026-07-23): IDLCK triangle locks â€” the pathfinder learns the game's own walls

The investigation ran the same day (player: "it might fix other areas
where the pathfinder seems flawed or slightly off") â€” three static
scripts, one evening, zero live scans:

**Phase 1** (`ff7_idlck_static.py`): IDLCK = opcode 0x6D (FFNx enum,
counted against five already-hooked anchors). Its handler (0x61E29F,
via the validated execute_opcode_table chain) reads u16 triangle_id +
u8 flag from the script and sets/clears **bit (tri&7) of byte
[field_global_object_ptr 0xCBF9D8] + 0xB2 + (tri>>3)** â€” a
per-triangle lock bitfield.

**Phase 2** (`ff7_idlck_readers.py`): the exact `[reg+reg+0xB2]`
access form is unique to the handler â€” the consumer computes the
address differently. **Phase 3** (`ff7_idlck_bitmath.py`): scanning
the field module for the bitfield signature (sar/shr-3 + and-7 + byte
access) found exactly one non-handler site â€” the movement
edge-crossing code at 0x6369E8/0x636AAF/0x636B76 (one branch per
triangle edge): neighbor id from the game's own parsed access pool
(ptr 0xCFF748, stride 3Ã—u16 â€” matching the raw format the mod
parses), the identical bit math against **static 0xCC0E3A**, and
`test/jne` REFUSING the crossing when the bit is set. 0xCC0E3A =
MODULES_GLOBAL_OBJECT (0xCC0D88) + 0xB2 â€” the address equality proves
`field_global_object_ptr` points at the static modules block, ties
both sides to ONE bitfield, and confirms the polarity (1 = locked)
from the game's own branch.

**Mod change**: `TRIANGLE_LOCK_BITS` + `is_triangle_locked()` in
ff7_addresses.h; `LoadWalkmesh()` cuts every edge INTO a locked
triangle after the reciprocity self-guard (locks legitimately make the
graph asymmetric; the guard validates the raw pool's layout, not the
overlay). Destination-side only, mirroring the game's own test. A
target standing on a locked triangle (Tifa behind the counter) now
fails A* and falls back to the existing straight-line + "no walkable
path" announce â€” which walks the player TO the counter, where the
talk radius reaches across, matching sighted interaction. Debug log
line: `NAV walkmesh: N edge(s) cut by triangle locks`.

This should fix every field where scripts lock counters, shop desks,
and doorway thresholds â€” the player's hunch that the counter bug
explained other "slightly off" pathfinder behavior is likely right:
any route that previously threaded a locked region now routes around
it (or honestly reports no path).

### v2.30.22 (2026-07-25): solid NPC bodies â€” "Tifa is in the way"

Play report (7th Heaven hideout, mds7pb_2 = field 155, screenshot
7h_hidout_1.jpg): route to Barret said "left 1 second, then down and
left 1 second", but pressing left produced only the wall thud. The
whole diagnosis ran OFFLINE the same morning
(`investigate/ff7_hideout_firstleg_dryrun.py`, logs
`hideout_firstleg_dryrun_20260725_*`), replicating the shipped
pipeline over the flevel walkmesh:

- **Exact reproduction first**: same A* path (10 tris), same 4 funnel
  corners, same spoken text â€” including the IDLCK lock set, recovered
  from the field script bytes (tris 22/23/26; both flag polarities
  give the log's exact "7 edge(s) cut"). The v2.30.21 lock overlay is
  play-validated by the same log (locked-field cut lines on three
  fields, sane routes).
- **The route was RIGHT and unfollowable at once**: the exact
  first-leg bearing (input 282.5Â°) walks its full 108 units clean;
  the quantized "left" (270Â°) ray is what the player actually walks,
  and **Tifa stood on it**. The live log shows the player pinned at
  EXACTLY 64.0 units from her center for 3Â½ minutes, zero movement
  on any input with a positive component toward her: **FF7 models
  hard-block each other, radii â‰ˆ 32+32, no slide around bodies**
  (walls DO slide â€” the calib deflections in the same log). To every
  signal the mod reads, a body is byte-identical to a wall.
- **Rerouting needs real radii**: a flood fill over the mesh shows
  64-unit contact SEALS this room completely (Barret unreachable from
  anywhere â€” yet the room is playable sighted), while 56 opens it.
  So per-model radii differ and any body-aware A*/funnel work would
  be guessing. Arc-bypass detour prototypes also showed quantized
  8-way speech degrades badly on tight detours (zigzag corners fold
  into fictional long legs). DEFERRED until radii are mapped
  (TODO.txt entry has the full experiment log).

**Shipped instead â€” the honest layer** (all proxy.cpp):

1. **Bump naming**: when the wall tone fires and a person-class model
   stands within 90 units inside Â±60Â° of the held direction, speak
   "<Name> is in the way." once per contact episode (reset on
   movement/release). Names via the same labelâ†’translate pipeline as
   the browser (`CollectBodies`/`BodyInDirection`; FieldModelLabel is
   a pure parser, safe from the wall thread).
2. **Route caution**: the directions announce appends the same
   sentence when the FIRST quantized leg's ray (the d-pad word the
   player will actually hold â€” `RouteToSpeech` now returns the first
   folded segment) passes within 56 units of a body
   (`BodyOnRay`; 56 = the flood fill's "certainly matters"
   threshold). Straight-line style gets the equivalent check on its
   quantized bearing. The destination model itself is excluded.
3. **Radius hunt diagnostics**: the `NAV person` debug line now dumps
   the three unmapped words between character_id and talk_radius
   (`rc6E/rc70/rc72`, FIELD_EVENT_RADIUS_CAND_*) â€” one session's log
   should show ~32 in the real collision-radius slot; promote the
   winner to Â§4/Â§14 and revisit the deferred rerouting. A `WALL body:`
   line also logs each naming event with the measured distance.

### v2.30.23 (2026-07-25): line-trigger behavior catalog â€” "pinball, exit to Seventh Heaven"

Play report (same day as v2.30.22): trying to leave the hideout, the
player stood ON the 'border' trigger line ("Pathfinder says I am very
close") and nothing happened. Hand-decoding the field's script section
(`investigate/ff7_hideout_exit_script_dump.py`) answered the immediate
question â€” 'border2' is a CUTSCENE trigger (a bank-var state machine
dispatching Tifa/Cloud/Barret scene scripts; its [OK] script is an
immediate RET), while the actual way up is the 'pinball' line, whose
cross script REQSWs cloud's script #5 containing `MAPJUMP field=154`
(the lift). The Triggers category spoke both as bare dev names â€” no
way to hear the difference a sighted player sees.

**Generalized the same day** (`investigate/ff7_line_trigger_catalog.py`):
a real field-script opcode walker (opcode lengths, jump-target math,
and exit opcodes taken verbatim from cebix/ff7tools `ff7/field.py` â€”
the walker independently re-derived the hand-decoded REQSW/MAPJUMP
chain, validating both). For every entity whose init script declares
LINE/SLINE, each script slot (line semantics: 1=[OK], 2..6=cross/Go)
is flow-walked (sequential + branch targets, stop at ret/retto/gmovr)
with ONE REQ/REQSW/REQEW hop expansion, then classified:

- MAPJUMP reachable â†’ **EXIT** (dest field id kept only when every
  reachable MAPJUMP agrees â€” conditional multi-destination exits (50)
  speak plain "exit" instead of guessing); via-[OK]-only â†’ **EXIT_OK**;
- else LADER reachable â†’ **CLIMB**;
- else non-empty [OK] script â†’ **OK**; else non-empty cross scripts â†’
  **SCENE**; else **INERT**.

Game-wide results: 702 fields, 1,827 line entities, **zero opcode-walk
errors** (the length table is correct against every script byte in the
game); 465 EXIT + 17 EXIT_OK, 151 CLIMB, 202 OK, 964 SCENE, 28 INERT.
Validation: hideout pinball=EXIT dest=154 / border2=SCENE / TV=SCENE
(matches the hand decode), nmkin_2 'ladu0'/'ladd0'=CLIMB, and the
Sector 7 street 'border' lines the 11:02 live log listed classify as
CLIMB (the watchtower ladders) â€” three independent cross-checks.

**Mod change**: generated `ff7_line_trigger_catalog.h` ({field id,
entity id, kind, dest} sorted, binary-search lookup â€” keyed by the
same owning-entity id the engine's line array carries at +0x0D). The
Triggers build appends a behavior suffix: ", exit to <dest>" (v2.25
DestinationName; plain ", exit" when the destination is conditional),
", exit â€¦, press OK", ", climb" (skipped when the name already says
ladder), ", press OK", ", scene", ", inactive". NavDest.name widened
48â†’64 for the suffixes. Caveat spoken suffixes state what the SCRIPTS
contain â€” a cataloged exit can still be story-gated at any moment.

### v2.30.24 (2026-07-25): collision radius confirmed â†’ body-aware rerouting

The v2.30.22 diagnostic paid off in ONE session â€” no extra play needed.
The same morning's log held the whole answer:

- **+0x72 IS the collision radius** (rc6E â‰¡ 0, rc70 flaps 0/1 â€” both
  rejected): Tifa 30, Barret 48, Biggs/Wedge/Jessie 34, generic NPCs
  30/34. Cross-checked against BOTH behavioral anchors from the same
  log: frozen vs Tifa at 64.0 and vs Barret at 81.0 â€” one rule
  (player_r + npc_r, Cloud â‰ˆ 32) fits both within one movement step.
- **The radius is DYNAMIC**: scripts set it per state (Tifa 30 in the
  bar, 20 in a hideout scene pose; parked models 0 = intangible; the
  pinball prop briefly 120). This resolves cleanly: read it LIVE per
  use â€” 0 means "cannot block right now", exactly when a body should
  not be routed around or named.

**Mod changes** (all proxy.cpp + the promoted constant):

1. `FIELD_EVENT_COLLISION_RADIUS` (0x72) replaces the rc candidates;
   `CollectBodies` carries each body's live radius (â‰¤0 = skip;
   >200 clamps to 30) and `PlayerCollisionRadius()` reads the player's
   own (sane 8..120, else 32 â€” the solved-for value).
2. Every body test is now radius-true: bump naming searches to
   contact+26 slack in the Â±60Â° cone; the route caution's ray width is
   contact+8 per body (was a flat 56).
3. **Body-aware rerouting** (the deferred v2.30.22 design, now
   unblocked): after the funnel, route legs are tested against every
   body's contact circle (+6 margin). If blocked, the triangles each
   blocking body's circle overlaps are temp-avoided (start/goal
   exempt â€” same overlay shape as the IDLCK cut) and A* re-runs; the
   reroute is adopted ONLY if its own funnel comes back clear of ALL
   bodies, else the original route stands and the caution names the
   blocker. Debug line: "NAV route: rerouted around N bodies". Known
   limit (accepted): triangle granularity â€” a body in a large doorway
   triangle seals that corridor even when a foot-width squeeze exists
   (the hideout Tifa case falls back to the caution, correct for a gap
   the player must shimmy through anyway).

### v2.30.25 (2026-07-25): stale triangle hints + routes to off-floor targets

Play report (evening, hideout): routes to Biggs made no sense ("up and
right 1 second, then left 2 seconds" from the bottom-left corner; "left
2 seconds. Barret is in the way." while standing in the open). The log's
smoking gun: `NAV route start=0 goal=0 path=1 'left 2 seconds'` â€” the
player STOOD on triangle 0 while Biggs' live triangle field (+0x78)
ALSO read 0, yet he stands at (-191,46), a different corner of the room.
**Scripted idle models never update their triangle field** â€” the same
stale-0 signature the v2.30.19 parked-ghost work saw (aval/avaw/avafat
all read tri=0 with real positions). Every route to Biggs/Jessie aimed
at the wrong triangle, then the funnel appended the true position as a
final straight leg THROUGH walls, and Barret (who really stands near
that fictional line) triggered the caution.

Fixes (offline-validated against the exact failing positions before
deploying â€” the replica reproduced tri-72 unreachability and the fixed
speech):

1. **ResolveTriHint**: a model's triangle id is only a HINT â€” trusted
   only when the hinted triangle actually contains the model's 2D
   position (slack 8); otherwise WalkmeshLocate from the position.
   Applied to start+goal in both the route builder and the journey
   planner.
2. **Nearest-reachable routing** (`to_nearest`): with the hint fixed,
   Biggs' position locates to tri 72 â€” which is UNREACHABLE: he sits ON
   the crates, off the walkable floor (same class as Tifa behind the
   locked counter). Instead of the bare "No walkable path found" +
   straight line, the NO_PATH fallback now (after the journey planner
   declines) floods the player's component, picks the reachable
   triangle nearest the target, aims the funnel at its closest point,
   and speaks "<Name>, off the walkable area: <route>". For Biggs the
   stand point is 6 units from him â€” talk radius trivially covers it;
   spoken result from the failing position: "up and left 1 second".
3. **target_reach**: body tests and both cautions stop at the target's
   TALK RADIUS (live read, floor 20/cap 90; exits/lines keep 0) â€” the
   walk only needs to END within reach, so a companion shoulder-to-
   shoulder with the target (Barret 73u from Biggs) is no longer a
   blocker or a spurious "in the way".

Bonus log confirmations same session: v2.30.23 suffixes live ("border,
exit" in the lift field, "pinball, exit to 7th Heaven" â€” destination
naming through the v2.25 cache working), v2.30.22 naming firing
(Tifa/Jessie), col= radius values sane everywhere.

### v2.30.26 (2026-07-25): proximity chirp vs large bodies â€” contact counts as "in range"

Play report: no chirp near Barret waiting outside 7th Heaven. Root
cause is arithmetic, not a bug in the chirp: his talk radius is 70 but
his collision radius is 48 â€” the player's center bottoms out at ~80
from his (48+32) and can NEVER enter the 70-unit circle the v2.27
chirp tests. Yet talking at contact works (same log, hours earlier:
blocked at dist 81, the talk ushered the player inside) â€” so the
engine's own OK test cannot be center-distance â‰¤ talk_radius, which
v2.27 had assumed ("the exact circle the OK button tests" â€” WRONG for
big bodies).

Static hunt (`ff7_talk_range_static.py`, 3 passes: field-range +0x74
loads, game-wide word loads with a restartable sweep, +0x61 consumers):
found the WRITERS â€” talkR/tlkR2 handlers 0x618253/0x6182DF (arg Ã—
field_scale >> 9 â†’ +0x74) and the model-init defaults (+0x72 = 30Â·s>>9,
+0x74 = 80Â·s>>9, explaining the ubiquitous 70s at scale 448) â€” but not
the reader. Rather than guess the engine formula, shipped the
behaviorally PROVEN rule: **body contact always suffices to interact**,
so effective interaction range = max(talk_radius,
player_col + model_col + 8). Applied to:

1. the proximity chirp (unchanged for default NPCs â€” talk 70 > contact
   ~62; Barret now chirps at ~88);
2. the pathfinder's target_reach (routes to big-bodied people stop
   appropriately short; companions beside them stay non-blockers).

Intangible models (collision 0) contribute no contact term â€” the plain
talk circle remains. If a future play report shows chirps at clearly
un-talkable distances, revisit with the reader hunt (the engine may add
only the MODEL's radius, not the player's â€” one anchor cannot split
118 vs 150 and both cover every observed case).

### v2.30.27 (2026-07-26): menu tutorials â€” TUTOR hook + narration + chatter suppression

Play report (the Materia tutorial): "Text boxes explaining the process
were probably firing but not spoken... the cursor was jumping around."
The log shows exactly that: at 00:02 the tutorial script swept the
main-menu cursor Itemâ†’Order and back at ~300-470ms/step â€” every step
announced with interrupting speech â€” while the tutorial's explanation
windows never appeared in any hook. **Menu tutorials are a separate
byte-code script system interpreted by the MENU module**, invisible to
the MESSAGE/ASK hooks.

But the scripts live in the field file we already parse: the section-0
header's nAkaoOffsets table holds BOTH music blocks (magic "AKAO") and
tutorial scripts; the TUTOR opcode's (0x21) 1-byte arg indexes that
same table. Offline dump (`investigate/ff7_tutorial_dump.py`):
game-wide, 8 fields carry 40 tutorial entries (mds7pb_2's entry 3 is
the Materia lesson; mds7_w2/junpb_2 carry 9 each â€” the battle
tutorials). Script format (validated against the Materia lesson, every
sentence decodes cleanly with the standard field text table):
**0x12 = window (u16 x, u16 y), 0x10 = FF7-encoded text until 0xFF**,
other bytes = timing/simulated key presses (the scripted cursor sweeps
â€” the log's Itemâ†’Order sweep is literally `03 03 03 03 03` in the
data).

**Mod changes**:
1. **TUTOR hook** (opcode 0x21, the same execute_opcode_table pattern
   as MESSAGE/ASK/STTIM): on first fire (2s debounce), locate the
   indexed entry in the current field buffer (guards: readable, not
   "AKAO", bounded by the next table offset / section end), walk the
   byte-code, decode every 0x10 text run (only when its 0xFF terminator
   provably lies inside the block), and queue the lesson as ONE
   narration â€” "Tutorial. <first window>" interrupts, the rest queue in
   order (cap 40 windows). v1 pacing model: the tutorial waits for OK
   per step so the player paces the visual; per-window sync would need
   the menu module's live tutorial-position state (unmapped).
2. **Tutorial-active flag** (Hooks::TutorialActive, set by the hook,
   cleared by MenuCursorThread when MENU_OPEN returns 0, which also
   TTS-silences any unfinished narration): while set, the main-menu
   cursor announce, Order-focus lectures, and the Item/Status menu
   threads stand down â€” the scripted cursor sweeps are a demo, not
   user navigation.

The report's "slow and choppy" is expected to be the interrupt-storm
(speech restarted every 300ms); if choppiness persists WITH the
suppression in place, investigate separately (frame-rate, not speech).

### v2.30.28 (2026-07-26): shop menus + G gil key â€” entirely static, one session

**User request** (with screenshots Menus/Shop/item_shop_1/2.jpg): connect
the shop menus; add a key announcing current gil.

**The whole shop cracked offline in one static pass** â€” zero live scans,
zero play-test rounds spent on discovery (ff7_shop_static.py, log
shop_static_20260726_101315; all addresses in Â§4 + Â§14's new shop block):

1. **The shop is NOT a menu_subs_call_table screen.** FFNx's chain
   (ff7_data.h 1442-1444) reaches it through the menu-TYPE dispatcher
   0x6CDA83: chain verified on disk byte-exact (0x6CDA83+0xC1 â†’ 0x6CBD54
   +0x7 â†’ 0x71FF95 +0x84 â†’ menu_shop_loop **0x71AAA3**; FFNx's
   get_materia_gil call site at +0x327B present as E8 â€” date-stamp OK;
   the docs' other site +0x3373 is the non-US build's offset, absent
   here, as ff7_data.h's version switch itself says).
2. **The dispatcher's jump table decoded** (index bytes 0x6CDBE4, targets
   0x6CDBC4): GAME_MODE 6=name entry, 7=PHS, **8=SHOP**, 9=main menu â€”
   the two values already live-confirmed (6, 9) both match, validating
   the decode. Shop gate = GAME_MODE==8; shop id = the MENU opcode's
   param word 0xCC0D8A.
3. **7-state loop** switch on 0x92565C (jump table 0x71E193): full state
   map + every cursor widget (generic ctor 0x6F4D30: +0 col/+4 row/
   +0x14 scroll) + the ABSOLUTE-index formulas lifted from the shop's
   own confirm handlers (buy row+scroll; sell items col+(row+scroll)Â·2;
   sell materia row+scroll).
4. **Catalog + prices + sell rules**, all with cross-checks: catalog
   records 0x923418 stride 0x54; price table behind ptr 0xDD4720 (items
   Â·4, materia +0x600); item sell = buy>>1 (drawn AND committed that
   way); materia sell = get_materia_gil 0x71FCF9 replicated (mastered â†’
   baseÂ·70, else raw AP; base 1 = unsellable) â€” screenshot cross-check:
   Restore id 53, master price 52500 = 750Â·70 exactly; restriction
   bit 0 via helper 0x6C50DD (which also mapped the four kernel
   gear-data arrays, Â§14).
5. **Kernel2 ground truth for the new text sections** (materia names /
   materia+weapon+accessory descs): kernel2.bin LZS-decompressed offline
   â€” it is the F9-EXPANDED runtime text (why heap strings are plain and
   the existing decoder never hits kernel F9 back-refs). Weapon desc
   entry 0 is kernel2's "Initial equipment", NOT kernel.bin's PSX-era
   "Initial equiping" â€” signatures must come from kernel2. Armor descs
   are BLANK in the data (sighted parity: the bar shows nothing);
   accessory descs need a raw-byte signature (0xB2/0xB3 colour codes).

**Mod changes**: ShopMenuThread (greeting + shop title on open; per-state
intros; buy rows "name, price gil, own N"; sell-item rows "name, N owned,
sells for M gil / can't sell"; sell-materia rows with AP/mastered price;
quantity states "N, total M gil"; I key = ware description â€” FF4-scheme
parity); GilKeyThread (G = "<N> gil" whenever a game is loaded, suppressed
on the naming screen where G is text input); 4 new signature-scanned
kernel2 sections (+ raw-byte signature infrastructure for the accessory
head); SAVEMAP_GIL/SAVEMAP_MATERIA promoted to named constants.

**Residual risk for play-test**: state-numbering and cursor semantics are
static-derived only â€” debug log lines fire on shop open and every state
change; the sell-item 2-column index formula and the buy-list visible-row
behavior are the two most likely places live behavior could diverge.

### v2.30.29 (2026-07-26): per-slide tutorial narration â€” the live state mapped

**Play report on v2.30.27** (same day): "reads the entire tutorial in one
long buffer... once the text is read, the user is left to guess how to
move through each slide in silence. Sometimes you have to advance with a
direction, sometimes a button."

**Static session** (ff7_tutorial_static.py + writer sweeps, log
tutorial_static_20260726_110911) mapped the whole tutorial machine the
v2.30.27 comment had deferred:

1. **FFNx's anchors decoded first**: menu_tutorial_window_state 0xDC1310
   / _text_ptr 0xDC1214 (renderer 0x6C49FD operands +0x9/+0x18 â€” FFNx's
   own voice-acting hook keys on the same 0â†’1â†’2â†’3â†’0 state edges, an
   independent confirmation of the semantics).
2. **The renderer is a SHARED menu message-window system** â€” the save
   screens' "file corrupted"-class popups use it too (mode byte
   0xDC1318=0 â†’ timer auto-close; tutorials use modeâ‰ 0).
3. **The tutorial VM** (0x71832E, jump table 0x7185C7; PC 0xDD1BC8
   pointing INTO the field buffer; running flag 0xDBFD30): opcodes
   0x02-0x0D are INJECTED key presses â€” the menu input refresh
   (0x7186C8â†’0x71826E) overwrites the pressed/held digests
   0x9A85E0/0x9A85D4 with VM output every tick, so **real input never
   reaches menu navigation during a tutorial**. The ONLY player-paced
   element is the text window, and its close test is `pressed != 0` â€”
   **ANY key advances a slide** (after a 0x14/0x28-frame minimum
   display). The "sometimes a direction, sometimes a button" experience
   was the silent demo phases between slides, where keys do nothing.
   (Dead code note: 0x71826E computes a blocked-keys mask from a header
   blob at 0xDD1B9A, but its only caller discards the return â€” the mask
   never applies in this build.)

**Mod changes**: hook_tutor no longer narrates (flag + log only);
TutorialThread polls TUTORIAL_RUNNING + TUTWIN_*: each slide is spoken
when ITS window reaches state 2 ("Tutorial. <slide>" for the first),
followed by "Press any button to continue." (input-mode windows only);
"Tutorial finished." on the running-flag drop, which also clears the
menu-suppression latch (previously waited for MENU_OPEN=0). Bonus: the
save screens' info popups â€” previously silent â€” now speak under
speak_menus via the same state edge. SafeDecodeFF7At (page-safe bounded
copy-out) guards every text read.

### v2.30.30 (2026-07-26): H key â€” battle HP/MP/status for the current character

**User request**: attach health to its accessiblity_keys.txt binding ("H:
In battle, announce character hp, mp, status effects"), reading the
current-most character.

No new address hunting needed â€” everything was already mapped:
BATTLE_ACTIVE_SLOT 0xDC3C7C (the v2.37 whose-turn source; retains the
last acting slot through animations, i.e. exactly "the current-most
character"; >2 â†’ leader fallback), name via PartySlotLabel, HP/MP from
the v2.11 actor-vars fields with the same plausibility gate as
TargetHPText (garbage â†’ name-only, never wrong numbers), and statuses
from actor_vars +0x00 â€” FFNx's own battle_actor_vars.statusMask field
name, spoken through the standard kernel status bit table (bit 0 Death â€¦
bit 26 Darkness; Sadness/Fury 0x10/0x20 corroborate the savemap flag
convention; names walkthrough-verified â€” "M Barrier", "Slow numb",
"Death sentence"; internal bit 0x80000 "Dual" deliberately not spoken).
"No status effects" when the mask is clean. GilKeyThread generalized to
AnnounceKeysThread (G + H, same focus-gated edge pattern); H is
battle-only (GAME_MODE==2) per the FF4 scheme. Debug log line carries
the raw mask for verifying any surprising status callout.

### v2.30.31 (2026-07-26): wait tone â€” typewriter-pointer stillness ends the muted pages

**Play report**: "Not every dialog chimes when the user needs to press the
continue button... no pattern... more in long dialogs with several blocks
of text that just advance rather than change speaker boxes."

**Root cause â€” the pattern IS text length.** The v2.30.6 three-tier rule
blacklists state VALUES {1,2} as "never fire" (correct for win=0, which
parks at 2 while typing). But counter-style windows (win=1) rest on a
DATA-DEPENDENT value after typing each page (17/34/60 observed â€” the
counter tracks rendered text). A short block can settle on 1 or 2 â€”
landing exactly in the blacklist and permanently muting that page's
chime. Whether a given block chimes depends on its length parity â€”
invisible as a pattern from the outside, precisely as reported. This is
the v2.30.15 lesson's third act: the state byte's styles were documented
in v2.30.5, and AGAIN one reader (the wait tone) kept a single-style
assumption.

**Fix â€” a style-independent wait signal.** The typewriter pointer
(DIALOG_TEXT_PTRS[win], the same live pointer behind v2.30.17/19) moves
every frame while ANY window style is typing and parks when the page is
fully displayed. New rule, per window per dialog: count pointer changes
since DLGID; â‰¥3 proves THIS dialog's pointer is live (1 = the open
buffer swap; 2+ = actual typing). For live-pointer windows,
"pointer still for â‰¥300ms" IS the wait signal: it overrides the {1,2}
blacklist (the muted-page fix) and REPLACES the bare state-hold in the
fallback tier (also fixing a quieter defect: positional windows park
their state byte all dialog, so the old 300ms state-hold chimed
mid-typing, ~300ms after page-turn). Dead-pointer windows keep the old
value-tier behavior unchanged â€” the new path cannot regress a window it
has no evidence about. Discrete terminal values {4,6,14} keep their fast
80ms path. The tone log now prints ptrstill/chg so the next report
distinguishes which path fired or failed.

### v2.30.32 (2026-07-26): shop's false "Save" + the short-dialog chime hole

Two same-day play reports on the fresh builds:

**1. "Says save when it's on Buy the first time" (shop open).** The shop
raises MENU_OPEN while every main-menu byte stays STALE â€” and the
player's last main-menu visit had ended on the Save row, so MENU_CURSOR
was parked at 9: MenuCursorThread's open-re-announce spoke row 9's label
("Save") over the shop greeting. Same failure class as the naming
screen's false "Item" (v2.8.3), now generalized: MenuModuleForeignScreen
(GAME_MODE 6 name entry / 7 PHS / 8 shop) stands down ALL six main-menu-
family threads â€” cursor, config, save (whose whole mode gate is
"MENU_CURSOR frozen at 9", i.e. EXACTLY this stale signature), item,
order, status. The exclusion list stays narrow and live-evidenced.

**2. "Talked to a kid, single short box, no chime."** v2.30.31's
pointer-liveness test required â‰¥3 pointer changes â€” but a short message
can render in as little as ONE pointer jump (open buffer swap + whole-
page write = 2 changes), so the pointer was declared dead and the {1,2}
blacklist muted the wait again. Liveness is now proven by POSITION as
well: the live pointer sitting PAST the decoded message's start
(msg_base, the v2.30.19 capture) proves consumption no matter how few
steps it took; dead pointers sit AT the start forever. The tone log
gains rel= alongside ptrstill=/chg=.

### v2.30.33 (2026-07-26): materia menu connected â€” table[3]'s identity settled

**User request** (screenshot Menus/Materia/materia_menu_1.jpg): connect
the materia menu.

**Static session** (ff7_materia_menu_static.py, the shop recipe): the
materia menu IS menu_subs_call_table[3] = 0x70CF0B â€” the very screen the
v2.31 caption evidence scored for "Arrange" (that string belongs to this
screen's Check/Arrange bar; the item menu that stole the guess is index
1) â€” and its 0xDCA7F8 "exclusive block" is this screen's state block.
Full map in Â§4: mode machine 0x920FA0 (12-case jump table, semantics
read off each case's transitions), bar/slot/list/popup cursors, the
viewed character's record pointer 0xDCA810, and the equip-commit index
formula (materia[row+scroll]) lifted from the commit code itself. The
Arrange popup's four options came from the string run 0x920C63-0x920CA3
(Arrange / Exchange / Remove all / Trash).

**Mod changes**: MateriaMenuThread (dispatch index 3, the item/status
gate shape + victory/foreign-screen/tutorial stand-downs): entry
"Materia. <character>" (re-announced on page-up/down character flips);
Check/Arrange bar; slot navigation "Weapon slot 3: Lightning materia" /
"Armor slot 1: Empty" (contents from the record's +0x40/+0x60 arrays,
pointer layout-checked before every read); equip and arrange lists over
materia[200] with in-place rewrite detection (equipping speaks the
slot's new content without cursor movement); Arrange popup options; I
key = materia description + AP / "Mastered". Modes 5/6/7 stay silent
(transients); any unexpected mode logs.

**Known residuals** (deliberate v1 scope): materia LEVEL (star count)
and "to next level" need the kernel materia-data records' AP thresholds
â€” not yet located; linked-slot pairs and slot-count bounds (chardata
+0x21) not spoken; Exchange's two-phase flow narrated as plain list
navigation.

### v2.30.34 (2026-07-26): equip menu connected

**User request** (screenshot Menus/Equip/equip_menu_1.jpg). Same-recipe
static session (ff7_equip_menu_static.py â€” the materia script cloned
onto table[4]): the equip menu is menu_subs_call_table[4] = 0x705D16,
FFNx's own menu_sub_705D16 name AND the rowâ†’index pattern agreeing
(table[15] duplicates the pointer; the gate accepts 4 or 15). The sub
is mostly a renderer; the input handler at 0x707040..0x7076xx gave the
real state: category cursor 0xDCA4A4 (Â±1 wrap 0..2 â€” Weapon/Armor/
Accessory), candidate-pane flag 0xDCA6A0, list widget 0xDCA5F8, and
the commit's own candidate read u8[0xDCA6A8][row+scroll] (category-
relative kernel gear indices). Character = CHARSEL_CHOSEN, equipped
ids from the record's +0x1C/1D/1E bytes.

**Mod changes**: EquipMenuThread â€” entry "Equip. <character>" (+
re-announce on char page-flips); category rows spoken as "Weapon:
Gatling Gun" / "Accessory: nothing equipped", with in-place re-announce
when an equip commits; candidate list by name; I key = gear description
(weapon descs live via the v2.30.28 kernel2 section; armor descs blank
by data; accessory via the raw-byte signature).

**Residuals**: stat-compare deltas (Attack 14â†’16 pane) need the menu's
computed-stats scratch â€” not hunted; materia-slot/growth line of the
highlighted gear unspoken (kernel gear records; future); candidate
counts (Ã—N owned) unspoken.

### v2.30.35 (2026-07-26): limit menu connected â€” the day's fifth menu

**User request** (screenshot Menus/Limit/limit_menu_1.jpg). Same-recipe
static session (ff7_limit_menu_static.py): limit menu =
menu_subs_call_table[7] = 0x70212A (rowâ†’index pattern, fifth
consecutive hit). State: mode 0x9204D8 (0=Set/Check bar, 1-4
grid/confirm), bar cursor 0xDCA1D0 (Ã—0x50 highlight), TWO 2Ã—2 LEVEL
grid instances (0xDCA198/9C and 0xDCA208/0C, Ã—0x124/Ã—0x89 highlights),
party slot 0xDCA3C8 (the sub resolves characters through
SAVEMAP_PARTY_IDS + the game's own 0x919928 idâ†’record table â€” the
v2.32-documented aliasing table reused). Two data finds: the
limit-learned mask is charrec +0x22 with bit = levelÂ·3+technique (the
sub's own bit test), and the limit NAME layout in the magic text
section is 7 entries per character in KERNEL block order, which swaps
Aeris and Tifa relative to savemap record order (kernel2 decode: 142 =
Healing Wind = Aeris, 149 = Beat Rush = Tifa).

**Mod changes**: LimitMenuThread â€” entry "Limit. Cloud. Limit level 1"
(level from charrec +0x0E); Set/Check bar; every grid move speaks
"Level 2: Blade Beam, Climhazzard" or "Level 4: not learned" (exactly
what the sighted grid shows); character page-flips re-announce. Grid
tracking is mode-agnostic (both instances watched every poll) so the
static mode-value guesses cannot silence a pane; mode transitions log.

**Residuals**: per-technique Check-mode sub-cursor (if one exists
beyond the level blocks) unmapped; limit descriptions unspoken (needs
a magic-DESC kernel2 section â€” signature would be "Restores HP|
Restores HP|" to dodge the item-desc collision); the Aeris/Tifa block
swap should be EAR-VERIFIED the first time Tifa's or Aeris' limit
screen is opened.

### v2.30.36 (2026-07-26): review sweep â€” nine fixes from a workflow code review

A high-effort multi-agent code review of the whole unpushed branch
(v2.30.23â€“.35) surfaced 10 verified findings; 9 fixed, 1 skipped. NO new
addresses â€” every fix is mod-side logic. All static reasoning; awaiting
play-test alongside the features they harden.

**Dialog wait tone** (hooks.cpp, three fixes): (1) the CLOSE-commit
frame re-fired the tone â€” closing cleared `wait_tone_armed` but left
`msg_base`, so the v2.30.31 stillness fallback saw a live, long-parked
pointer at state 7 and chimed right after the player dismissed the
dialog; close now drops all pointer-liveness evidence AND the tone gate
excludes state 7 outright (nothing to wait for during a close hold).
(2) The per-dialog evidence reset (DLGID) was gated on `speak_dialog`,
so the voice-acting-mod configuration the tone explicitly serves never
set `msg_base` (v2.30.32's position liveness silently inert â€” the
short-dialog muted chime it claimed to fix was still live there) and
never reset `rawptr_changes` (stale cross-dialog liveness); tracking is
now unconditional, only the speech stays config-gated. (3) The {1,2}
never-wait override now needs 900ms of pointer stillness instead of
300ms â€” those are documented actively-typing values, and a scripted
mid-page pause parks the pointer past 300ms easily; a settled page's
wait is indefinite, so the legit chime just lands ~600ms later.

**ASK hook** (three fixes): (1) with `speak_choices` off, nothing wrote
`last_dialog_id`, so the choice tone's new-dialog test was true EVERY
frame â€” a ~30/s machine-gun double-tone for the life of every choice
window in the voice-mod config; the tone branch now consumes the edge.
(2) The from-idle re-arm lacked hook_message's v2.30.17 pages-remaining
guard: a counter window's per-page state rerun during a multi-page ASK
re-pended and re-decoded the mid-consumption typewriter pointer
(garbled duplicate lead-in); re-arm now requires the ASK to have fully
presented (`ask_lines` empty or choices shown). (3) Multi-page choice
detection was positional-only â€” a dead-pointer window (rel parked at 0,
the v2.30.32 class) never fired the tone/caption/option announces at
all; two fallbacks added, both gated on rel==0 so live windows are
untouched: the v2.30.12 cursor mirror waking to a non-baseline value
(choice is accepting input â‡’ page is up), and a 3s timeout floor that
QUEUES the caption (interrupt=false â€” last_speak_tick marks when the
lead-in STARTED, it may still be mid-utterance).

**Tutorial suppression** (proxy.cpp, two fixes): (1) "Tutorial
finished." was queued (interrupt=false) and the latch cleared in the
same poll â€” whichever menu thread matched the still-open menu then
spoke its fresh-open announce with interrupt=true within 50ms, wiping
the cue every time; the latch release is now deferred 1.5s (threads
keep tracking silently, their announce lands after the cue). (2)
MenuCursorThread's MENU_OPEN==0 branch cleared the latch level-
triggered â€” but TUTOR fires field-side BEFORE the menu opens (the
request gap the latch exists to cover), so a poll in the gap killed
the suppression and Silence()d in-flight speech; the clear is now
edge-gated on `last_menu_open != 0` (a genuine openâ†’closed
transition).

**G key** (proxy.cpp): `FIELD_ID != 0` was the wrong "game loaded"
test â€” the world map also reads 0, so G was silently dead exactly
where "can I afford the inn?" matters. Game-loaded is now proven by
the savemap caption (LOCATION_NAME_BUFFER first byte âˆ‰ {0x00, 0xFF} â€”
a fresh-boot title screen's zeroed savemap fails it, and world-map
saves pass because the caption IS savemap state). Accepted residual:
after quit-to-title a stale caption can let G speak the just-quit
game's gil on the title screen â€” cosmetic, chosen over a dead key.

**Skipped (1 of 10)**: the fieldbgâ†’MC_SCENERY fallback (unknown props
vanish from every browser category). Deliberate v2.30.18 decision from
a play report ("no scenery in People"); re-admitting unknowns would
resurrect that complaint on every field for a so-far-hypothetical
progress-blocking prop. The right fix is offline: extend the flevel
catalog to enumerate fieldbg variants whose entities carry talk/OK
scripts and whitelist those â€” queued as a future investigation.

**Verification**: review = 4 finder angles + 30 independent verifiers
(2 candidates refuted); fixes compiled clean and deployed to both
installs hash-verified. No addresses touched, so no Â§4/Â§14 changes.

### v2.30.37 (2026-07-27): game-over sequence accessibility â€” the silent death screen

**Play evidence** (Screenshots/game_over/death_1â€“3.jpg + session log
09:57â€“10:03): Cloud wiped in a train-graveyard battle (field 145).
The mod spoke "Cloud is down" (10:02:14, the v2.30 defeat announce
working), then NOTHING for the entire sequence that follows: the
GAME OVER film-reel screen (~40s), then the title NEW GAME / Continue
prompt â€” where, worse than silence, three stale menu threads woke up
at 10:03:03 and spoke garbage over it: `QUIT cursor=0 (Yes)` and
`MENU cursor=0 (Item)` (ORDER logged focus but spoke nothing). A blind
player heard "Cloud is down â€¦ Yes â€¦ Item" and had no way to know the
run had ended, what screen they were on, or that Continue was one
Down-press away.

**Root cause â€” FIELD_ID is never cleared by a game over.** Every
title/field context test in proxy.cpp assumed `FIELD_ID==0 â‡” title`:
the engine instead returns to the title with FIELD_ID stale at the
dead field (145 through the reel, the prompt, and beyond â€” WALL gates
log). So TitleCursorThread (wants 0) stayed dead while the six
main-menu threads (want nonzero) sailed through the prompt's
MENU_OPEN=1 with every byte stale. The reel itself is the v2.30.1
scenario byte-for-byte: mode=0, menu=0, movie=0, frozen field â€”
only the movement-arming kept the wall tone quiet there.

**The one positive signal**: GAME_MODE (0xCC0D89) blips to **26** for
~60ms at the battleâ†’game-over handoff (10:02:20.946â†’10:02:21.008,
caught by the wall thread's 50ms poll; Â§4 GAME_MODE row updated â€”
single-session evidence, provenance noted there). The reel and prompt
read mode 0 â€” the blip is all there is.

**Fix â€” GameOverWatchThread + title-context latch** (all proxy.cpp,
plus GAME_MODE_GAMEOVER=26 in ff7_addresses.h):
- **GameOverWatchThread** (new, 30ms poll â€” fastest in the file, two
  chances at the observed blip width): mode==26 sets
  `g_game_over_latch`, logs the dead field id, and speaks **"Game
  over."** (interrupt=false so a still-playing defeat announce isn't
  cut; speech gated speak_menus, the latch itself unconditional â€”
  its suppression duties must not depend on config).
- **Latch semantics**: "field state is a corpse; title sequence owns
  the screen." Consumers: TitleCursorThread accepts the latch as
  title context but additionally requires MENU_OPEN==1 (the prompt
  raised it at 10:03:03; during the reel the title cursor byte is
  boot residue and must stay quiet), and prefixes the first announce
  "**Title screen.** New Game" for orientation; all six main-menu
  threads + Config + Order stand down (the v2.30.32 foreign-screen
  rule â€” same stale-bytes class); SaveMenuThread's LOAD branch
  accepts the latch (post-game-over Continue grid IS the title-block
  instance) while save_mode requires !latch (a stale MENU_CURSOR==9
  would fake the save-menu signature); wall-bump + field-nav gates
  add the latch (J/L/K no longer browse the dead field over the
  reel); G key treats the game as not loaded (the dead run's gil).
- **Latch clear**: observed reload shape is reel (menu=0) â†’ prompt
  (menu=1, held through save-select per the boot log) â†’ load commit
  (menuâ†’0). So: MENU_OPEN=1 seen while latched arms the clear; the
  next MENU_OPEN==0 fires it. Safety net: FIELD_ID changing to a
  DIFFERENT nonzero value also clears (covers prompt-skipping paths;
  same-id reload is covered by the menu edge).

**Assumptions to verify in play-test** (log markers "GAMEOVER:"):
(1) the 30ms poll actually catches the blip on every wipe â€” a wipe
with no GAMEOVER line means the blip can be shorter and needs the
battle-side all-party-dead fallback; (2) the post-game-over prompt
uses the SAME title cursor byte 0xDD6F24 as cold boot (the
save-vs-title Continue lesson says separate instances are possible â€”
if "Title screen. New Game" never fires while the prompt is up, the
post-GO title has its own cursor to hunt); (3) MENU_OPEN=1 is raised
by the prompt itself, not first input (if the log shows a long
prompt-visible gap before menu=1, cursor announces are input-delayed
â€” acceptable but worth knowing); (4) Continue â†’ save grid speaks via
the LOAD instance. Quit-to-title remains an un-latched stale path
(G-key caption residual documented in v2.30.36) â€” future work if
reported.

Deployed both installs, hash-verified (3619DBD91C8B9989).

### v2.30.38 (2026-07-27): TITLE_STATE â€” the launch-splash false "New Game" closed statically

**User request** (same morning as v2.30.37): fix the boot-time bug where
"New Game" is announced during the company-logo splash, before the title
menu exists â€” and then the real menu appears silently (same cursor
value, change-check). Documented since v2.0 as a KNOWN LIMITATION with
the claim "there is no in-process signal that distinguishes splash from
title screen." That claim is now DISPROVED â€” one static session, no
live scans, no play-test rounds spent.

**Hunt** (3 scripts, ~20 min): ff7_title_phase_static.py swept every
executable byte for references to TITLE_CURSOR 0xDD6F24 â€” only THREE,
all reads, all in 0x721xxx-0x722xxx (title module): two draw sites
(cursor Y = base + cursorÃ—stride, hi/lo-res) and the OK-confirm switch
(case 0 = New Game, case 1 = Continue â†’ builds the Continue grid widget
0xDD6D98 with the shop-mapped ctor 0x6F4D30). The reveal:
`push 0xDD6F20; call 0x6F4DB2` â€” **TITLE_CURSOR is the +4 ROW field of
a cursor widget at 0xDD6F20** (why no writer instruction exists).
âš  trap logged for posterity: a raw-byte E8 caller scan "found" call
sites at 0x713703/0x71375D that were actually E8 bytes INSIDE
`cmp [0xDD17E8],â€¦` operands â€” raw E8 scans need disasm confirmation
(ff7_title_callers_disasm.py replaced it with a proper sweep).

**The state machine** (title_callers_disasm + title_state_writers logs):
per-frame main 0x722393 â€” first tick per session (guard [0xDD76F8]==0)
resets **[0xDD74E0]=0** and runs init 0x720E64 (widget ctor, music,
saves-exist probe â†’ 0xDD76FC); draw 0x7212FB then fades in
(0x722BB0(-0xF) per frame) until **[0xDD74E0]=1 = menu interactive**;
a confirmed choice writes 2 (fade out), then -1 (exit) â€” and teardown
clears the 0xDD76F8 guard, so EVERY entry (boot, post-game-over,
quit-to-title) re-cycles 0â†’1. -1 stays stale through gameplay, so a
==1 gate cannot false-fire outside the title. Subscreens (menu vs
Continue grid) switch on [0xDD7704] 0..7 under a constant ==1.

**Shipped**: TITLE_STATE/TITLE_STATE_INTERACTIVE in ff7_addresses.h
(full state machine documented); TitleCursorThread announces only at
TITLE_STATE==1 â€” kills the splash announce AND lands the first
announce exactly when the menu fades in, now prefixed "Title screen."
on every fresh session (generalizing v2.30.37's game-over-only
prefix); "TITLE state=%d" transition logging (the disasm semantics'
live verification rides the next launch's log for free);
GameOverWatchThread's prompt detection upgraded from the once-observed
MENU_OPEN==1 proxy to (MENU_OPEN==1 || TITLE_STATE==1), with the latch
clear requiring the title to have LEFT state 1 â€” closes v2.30.37's
open questions (2) and (3) statically (same byte at the post-game-over
prompt: proven, same module; MENU_OPEN-vs-input ambiguity: moot).

**VERIFY next launch** (log): "TITLE state=" shows 0â†’1 at menu-appear
(no announce before 1); "Title screen. New Game" spoken AT the menu,
nothing during logos; Up/Down announces unchanged; after game over the
prompt still announces (now via TITLE_STATE). If state=1 appears
during the logos, the disasm read of the fade path is wrong â€” capture
the log and re-derive.

Deployed both installs, hash-verified (A6E96D2C7033B770).

### v2.30.39 (2026-07-27): config file restructured â€” settings list + glossary, DLL creates the default

**User request**: rearrange ffvii_accessibility.cfg so all configurable
items sit at the top one after another, with descriptions and examples
in a glossary below â€” easier for users to find the knobs â€” and make
this the default the mod produces going forward.

**Restructure**: the canonical AccessibilityMod/ffvii_accessibility.cfg
now opens with the 17 bare `key = value` lines (header comment points
to the glossary), followed by a per-setting glossary preserving all the
existing documentation. Every glossary line is `#`-commented â€” load-
bearing, not cosmetic: the parser is last-one-wins, so an uncommented
`key = value` example in the glossary would silently override the
user's setting at the top. Wall-bump glossary gained the v2.30.22
"<Name> is in the way" behavior; speak_menus's coverage list updated
to the 2026 menu family (Item/Materia/Equip/Status/Order/Limit/Save/
shops).

**DLL now creates the default** (it previously never wrote a config â€”
missing file just meant silent compiled defaults): Config::Load() on a
missing cfg writes the canonical file next to the DLL, then runs on
the compiled defaults (identical by construction). Single source of
truth enforced at BUILD time: CMake embeds the repo cfg into
default_config.h as a byte array (file(READ HEX) + configure_file;
CMAKE_CONFIGURE_DEPENDS re-generates on cfg edits) â€” no second copy of
the text to drift (the stale-comment lesson applied to config). Byte
array, not a string literal, because the cfg is 16,514 bytes and MSVC
caps a single string literal at ~16K (C2026) â€” the file is ALREADY
over that line. Write is best-effort (unwritable folder â†’ silent
defaults, the old behavior) and CRLF-normalized regardless of git's
checkout line endings ('\r' stripped, text-mode write). Embed verified
byte-identical to the canonical file post-build.

**Deploys**: both installs got the new-format cfg with their live
overrides preserved (debug_log=true, speak_enemy_hp_always=true â€” the
two places they differ from defaults; the 2013 install's previously
missing keys now explicit). No addresses involved â€” no Â§4/Â§14 changes.
VERIFY (trivial): rename the cfg away, launch, confirm the mod
recreates it in the new format with default values.

Deployed both installs, hash-verified (770ED59415B1475D).

---

### v2.30.40 (2026-07-27): quit-cursor stale "Yes" at menu open â€” seed-on-reset

**v2.30.38 LAUNCH-LOG CONFIRMED first.** The 12:16 launch (first with
the new build) is the verification the TITLE_STATE disasm was waiting
for: `TITLE state=0` through the whole logo splash (silence â€” the old
false "New Game" gone), `state=1` at 12:16:55.619 with the cursor
announce ("Continue") at that exact poll, `state=2` on the fade-out
into the loaded save. The Continue grid also spoke its slot correctly
(SAVEMENU phase=1 line). One minor absence: no `state=-1` line after
the handoff to the field â€” either the module writes it before the
150ms poll saw 2â†’-1 in sequence or logging stopped mattering once out
of title context; the announce gate (==1) is unaffected. [TITLE]
closed.

**The same log caught a new bug**: at the first main-menu open after
loading the save (12:17:02), `QUIT cursor=0 (Yes)` fired at the same
instant as `MENU cursor=0 (Item)` â€” the quit thread spoke a stale
"Yes" (immediately cut by "Item", both interrupt=true, so audibly a
blip â€” but the same class as the pre-v2.30.37 game-over-prompt stale
"Yes", now proven to fire on ORDINARY menu opens too).

**Root cause**: QUIT_CURSOR is stale between quit dialogs, and every
stand-down/close path re-arms `last_quit_cursor = 0xFF` ("nothing
announced"). The first poll of a fresh menu open then sees stale-byte
!= 0xFF, and if the stale value is <= 1 it speaks it as if the player
had moved the quit cursor. Any menu open following a session where the
byte settled on 0 or 1 reproduces it.

**Fix (the v2.30.13 baseline-suppression pattern)**: first valid read
after a reset seeds silently (logged with a `seeded` suffix); the two
sentinel states keep the REAL dialog-open announce alive â€” 0xFF =
"just reset, seed next valid read", 0xFE = "byte was out-of-range
while watched; a garbageâ†’valid transition is the quit dialog writing
its initial cursor and speaks" (that transition was the old
else-branch's announce path, preserved by construction). Yesâ†”No moves
inside a live dialog are validâ†’valid changes and speak exactly as
before. The `ORDER focus=0 (was 255)` line in the same log was
checked and is log-only (speaks only on focus 1/2 with a non-0xFF
baseline) â€” benign.

No addresses involved â€” no Â§4/Â§14 changes. VERIFY (passive): menu
opens speak only the row; log shows `QUIT cursor=N (...) seeded`
instead of a bare announce at open; a real Quit dialog still speaks
Yes/No on navigation.

Deployed both installs, hash-verified (64BF90FD00FDFF17).

---

### v2.30.41 (2026-07-31): waveOut tone player â€” Beep() silent on tester's VM

**The report**: a remote tester (running the Echo-S voice mod via 7th
Heaven) heard NO wall tones and NO interaction tones. Their FFNx.log
identified the machine: Windows 11 ARM Insider VM on Apple Silicon,
VMware virtual audio/GPU.

**The diagnosis came entirely from their existing logs** â€” no new build
needed: the `WALL body:` lines ('Shinra guard'/'Biggs'/'Jessie'/'Wedge',
a dozen-plus across the session) print INSIDE the block that has just
called `Beep()` (proxy.cpp WallBumpThread), and `MSG wait tone` lines
fired too â€” so every tone code path was executing and calling Beep();
the tester simply never heard it. The two audio paths they COULD hear
(Tolkâ†’NVDA speech, DirectSound/FFNx game audio incl. footsteps) are
exactly the two paths the mod's tones didn't use. kernel32 Beep()'s
legacy system-beep route returns success with no audible output in many
VMs/remote sessions and when the Volume Mixer's "System Sounds" slider
is muted. 7th Heaven / footstep sounds: red herrings (game-side audio
cannot intercept a kernel32 call in our DLL).

**Fix â€” new tones.cpp/h module**: all 7 tone call sites (wall thud 220,
prox chirp 1175, wander cue 880, dialog wait/choice 1568 Hz) now go
through `Tones::Play(freq, ms)` â€” a synthesized 16-bit mono 44.1 kHz
sine played via winmm waveOut on WAVE_MAPPER, i.e. the same default-
endpoint route as the audio the tester demonstrably hears. Design:
BLOCKING like Beep() (drop-in: the 300ms wall repeat gate and the
choice tone's Sleep(60) double-beep gap keep their timing by
construction); per-call waveOutOpen so a mid-session default-device
switch is followed (Beep parity); 5ms fade in/out inside the duration
(kills Beep's edge click); winmm resolved from System32 by ABSOLUTE
PATH, never linked (self-proxy safety â€” the winmm_proxy.cpp technique);
winmm pinned for process lifetime (tone threads join with 500ms
timeouts at shutdown â€” FreeLibrary could unmap under a live
waveOutWrite); every failure path falls back to Beep() with a
once-per-session log line, so no system behaves worse than before.

**New config setting `tone_volume` (0-100, default 60)**: master
loudness for ALL tones (0 = master mute; per-tone bools unchanged) â€”
amplitude = full-scaleÂ·(v/100)Â² (perceptually even steps; 60 â‰ˆ -9 dB
â‰ˆ Beep's perceived level). Beep() had no volume control at all. Added
to the canonical cfg in BOTH places (list + commented glossary, per the
v2.30.39 rule) + strtol parse with garbage-keeps-default and clamping.
Behavior shift native users may notice: tones now live in the game's
audio session (game slider in Volume Mixer), not "System Sounds".

**Diagnostics**: `Tones::Init()` (after Log::Init, before any tone
thread) logs `Tone player: waveOut ready (system winmm).` or the
fallback line â€” every future "no tones" report now states its playback
path up front. Runtime waveOut failures log ONCE per session.

No addresses involved â€” no Â§4/Â§14 changes. VERIFY (tester): send the
new build; tones should be audible in the VM; their log should show
the `waveOut ready` line. VERIFY (local, passive): tones sound the
same (slightly cleaner edges), follow the game's mixer slider, and
`tone_volume = 30` in the cfg audibly quiets them.

Deployed both installs, hash-verified (CA96B2A4658FBD66).

---

### v2.30.42 (2026-07-31): F8 in-game audio-only accessibility menu

**User request**: change every mod setting from inside the game â€” spoken,
no graphics, changes live immediately, saved immediately, no restarts.

**F8 verified free before claiming it**: accessiblity_keys.txt already
designates "F8: Open mod menu." (parity, not invention); the engine's
ff7input.cfg contains no DIK_F8 (0x42) byte; FFNx's only hotkey is
devtools on F12 (0x7B, read from the live FFNx.toml); game keyboard
defaults are numpad-centric.

**Why the in-menu keys are J/L/K/I, not arrows**: a version.dll proxy
cannot eat keys â€” the game keeps receiving everything while the menu is
open. Arrows would walk the character while browsing. J/L/K/I carry no
game function (pathfinder-proven since v2.14), and the verbs map 1:1
onto the established scheme (J/L cycle, Shift+J/L modify, K announce,
I describe â€” same I as the shop/config description key). One modal at a
time: FieldNavThread and the three I-key description handlers stand
down on SettingsMenu::IsOpen() (edge state still tracked so close can't
manufacture stale edges); the gamepad stick is suppressed the same way.
The ONE context where the menu stands down is the naming screen
(GAME_MODE 6 â€” J/L/K are letters there and would type into the name):
F8 refuses with speech, and the menu auto-closes if naming appears.

**New module settings_menu.cpp/h**: table-driven (18 entries: cfg key,
spoken name, kind bool/volume/dirstyle, member pointer, one-line I-key
description). 40ms poll, focus-gated, Ctrl chords ignored (reserved by
the parity file). Selection persists across open/close within a session
(toggle-test-toggle-back loops). Open speaks the full key help every
time + current setting QUEUED (interrupt=false â€” two interrupt=true
utterances back-to-back would cut the help off; caught in review before
deploy). tone_volume changes play an 880 Hz demo at the new loudness.

**Live apply**: audited every consumer â€” all read Config::Get().<field>
at point of use, so changes are live within one poll by construction.
ONE exception found: debug_log (file handle opened once at startup) â†’
new Log::SetEnabled(bool): first enable this session truncates like
Init(true), re-enable appends (an off/on toggle must not wipe the very
capture the user is making), disable closes flushed.

**Live save**: new Config::SaveSetting(key, value) â€” line-based in-place
rewrite of the cfg; replaces the first ACTIVE assignment line (comments
can't match â€” the glossary stays inert per the v2.30.39 rule); appends
at end (last-one-wins) if no active line exists; recreates the canonical
default first if the cfg was deleted mid-session. Save failure (read-only
dir) is spoken: "change lasts until the game closes." Config::GetMutable()
breaks the old settings-are-immutable contract DELIBERATELY, with a
single-writer rule (menu thread only) â€” all fields are â‰¤4-byte aligned,
so concurrent readers see old-or-new, never torn, on x86.

**Offline dry-run before deploy** (the SaveSetting harness compiled
against the REAL config.cpp, run on a copy of the canonical cfg):
4 targeted lines replaced in place, unknown key appended under its
comment, all 378 other lines byte-identical (glossary untouched),
values reload correctly, and the speak_battle write did NOT touch
speak_battle_menu (the prefix hazard is what the '=' check after the
key match is for).

No addresses involved â€” no Â§4/Â§14 changes (GAME_MODE/NAME_ENTRY
constants already existed). VERIFY (play): F8 opens/closes with speech
everywhere but naming; J/L wrap through 18 settings; Shift+L on Tone
volume steps +10 with a demo tone; wall tone toggle takes effect at the
next wall; pathfinder ignores J/L while the menu is open and works
again after close; cfg file shows the new values immediately (check
while the game still runs); debug_log toggled off then on mid-session
appends rather than truncating; F8 on the naming screen refuses with
speech.

Deployed both installs, hash-verified (B5365D596CD2E58F).

---

### v2.30.43 (2026-07-31): kernel2 scanner crash â€” SEH guard + fruitless backoff

**The report**: tester crashed at the Guard Scorpion fight. FFNx.log:
access violation 0xC0000005 at 0x6D7EACE2, ~13s after
`[BATTLE] Scene# 324` began, stack frames all in VERSION.dll (base
0x6D7C0000).

**âš  ENVIRONMENT CORRECTION (2026-07-31, user)**: this crash happened on
NATIVE Windows â€” i5-10300H, GTX 1650, Win11 Home, 8GB (1.87GB free),
FFNx 1.24.3.0 stable â€” NOT the Apple-silicon VM from the silent-tones
report (that log had FFNx 1.24.3.172 and a different username; possibly
a different tester entirely). The original write-up assumed the same
machine and blamed "VM memory pressure + Echo-S streaming churn" as
aggravators; both claims were unverified carry-over. The correct
reading is STRONGER, not weaker: the TOCTOU race lands under ordinary
boss-load heap churn on stock hardware â€” no exotic conditions needed â€”
which the fix (SEH guard) covers regardless. LESSON: never assume two
reports share an environment; read each FFNx.log's PC SPECS header
(CPU/GPU/OS/RAM), FFNx version line, and the SymInit UserName before
reasoning about causes. The wrong assumption did not change the fix
here, but it skewed the "why now" narrative and could have misdirected
a diagnosis where environment mattered.

**Symbolication method (NEW CAPABILITY)**: added `/MAP` to the link
(permanent). Relinked DLL verified byte-identical to the shipped
release binary except 2 timestamp bytes â‡’ the map is authoritative for
the tester's crash addresses. (FFNx's module 'size' is SizeOfImage â€”
507904 vs 466944 file size confused this briefly.) RVA floors:
0x6A89 = BattleMenuThread (thread entry), 0x16D93 = ScanKernel2Sections
(FindSectionBase inlined), 0x2ACE2 = static-CRT region (the
memchr/memcmp of the sweep). âš  map "Publics" exclude static functions â€”
floor-symbol attribution near statics needs a sanity check against the
call chain.

**Root cause**: TOCTOU in ScanKernel2Sections â€” VirtualQuery snapshots
a region, then FindSectionBase sweeps the WHOLE region with
memchr/memcmp for milliseconds while the game's threads allocate/free
freely. Region freed/decommitted mid-sweep â‡’ AV. Boss-fight start =
peak churn from battle-asset loading alone (native stock hardware â€”
see the environment correction above; no VM or voice-mod conditions
required). Every prior battle ran
the same dice roll and won; scene 324 lost. Aggravator discovered
while fixing: the MENU-thread call sites retry every 3 SECONDS (not
60s) while their sections are missing â€” on retranslated installs where
signatures never match, that was a full address-space sweep every 3s
forever, precisely on the modded installs with the most churn.

**Fix**: (1) FindSectionBaseSafe â€” noinline SEH wrapper (__try/__except
filtering ACCESS_VIOLATION only; separate function per C2712), AV â‡’
skip region, InterlockedIncrement counter, next retry rescans; nothing
permanently lost. (2) Fruitless-scan backoff INSIDE the scanner: no new
section this pass â‡’ next non-urgent scan waits 30sÂ·2^(streak-1) capped
10 min; ANY progress resets. Healthy installs never engage it (first
scan succeeds, triggers go quiet). (3) `urgent=true` from the two
BATTLE call sites â€” the COMMAND section is a transient battle
allocation re-found every battle; battle scans bypass backoff armed by
field-menu retries (their own 60s local limits still apply). Scan log
line now appends `avs=N streak=N`.

âš  CLASS LESSON: IsReadableSpan-then-read is a race everywhere, but the
window is microseconds for small spans â€” the scanner was the outlier
(megabytes, milliseconds). Any future whole-region sweep of live heap
must go through an SEH guard, not more VirtualQuery checks.

No addresses involved â€” no Â§4/Â§14 changes. VERIFY (tester): replay the
scorpion fight on v2.30.43 â€” no crash; log's scan line may show avs>0
(the guard working). VERIFY (local): battles still speak
command/magic/item names (urgent path unharmed); scan log shows
streak=0 on our installs.

Deployed both installs, hash-verified (90C6445101587967).

---

### v2.30.44 (2026-07-31): debug_log defaults ON â€” test-mod period

**User decision**: the mod is a TEST MOD until further notice; debug
logging defaults on so every tester report arrives with its evidence
(the v2.30.41 silent-tones and v2.30.43 scorpion-crash diagnoses both
hinged entirely on session logs â€” and the crash session had NO
accessibility log because the tester's default was off).

Changed: config.h compiled default (`debug_log = true`), canonical cfg
list line + glossary (explains the test period, points at the F8 menu
toggle for opting out), log.h header comment. The CMake embed keeps the
DLL-created default cfg in sync automatically. âš  REVERT CHECKLIST when
the test phase ends (one commit): config.h default, cfg list line, cfg
glossary text, log.h comment â€” grep "test period" in AccessibilityMod/.

Log overhead is modest (line-buffered, flushed per line, overwritten
each session) and users can opt out live via the F8 menu (Debug log â†’
off, saved persistently).

No addresses; no Â§4/Â§14 changes. Deployed both installs, hash-verified
(8BF3475B76BD60EC).

---

### v2.30.45 (2026-07-31): three tester reports â€” system messages, taken items, wall switches

**Report 1 â€” speak_dialog=false silenced item pick-ups.** The voice-mod
config again (the v2.30.36 lesson's config). Voice mods voice CHARACTER
dialog, never system notices, so the speaker-vs-speakerless distinction
is what the player wants â€” implemented as
hooks.cpp LooksLikeCharacterSpeech(): (a) party-name token 0xEA-0xF2 in
the first 24 raw bytes; (b) Echo-S literal style `Name "â€¦"` â€” early
quote after a name-like run AND the last page ENDS with a quote (what
separates it from 'Received "Potion"!', which ends '!'); (c) vanilla
literal style â€” first decoded LINE a bare name-like word with more
lines following. All-miss = system message = speaks in EVERY config.
Error direction deliberate: uncertain â†’ system (re-speaking one voiced
line is mild; silencing a pick-up is the reported bug). âš  pages are now
decoded UNGATED for classification â€” the v2.30.17 pages-remaining
re-arm branch needed a dialog_speaks gate or muted speaker dialogs
would never re-arm re-talk detection (caught in-edit; the pre-change
code relied on the cache being EMPTY in the muted config).

**Report 2 â€” collected items stayed listed.** Offline game-wide script
walk (NEW ff7_prop_interact_catalog.py: 702 fields, 5454 model
entities, 0 walk errors) proved the hide mechanism: pickup talk scripts
(nmkin_3 potion 'po0', nmkin_5 materia 'mtr') are LOOT+VISI. Handler
disasm (NEW ff7_visi_handler_disasm.py) pinned the byte: **VISI (0xA4)
writes its operand to field_event_data +0x62**; CHAR-bind disasm (NEW
ff7_char_handler_disasm.py) proved bound models START at 1 (store at
0x6143D2) â€” ==0 is a safe "script hid it" test. Items pass + prox
chirp now skip vis==0 items/devices (AFTER label assignment â€” ordinals
stay reserved, the v2.18.2 identity rule); People deliberately NOT
filtered yet (scenes hide/show people constantly â€” needs play evidence
first; NAV debug line now logs vis= for exactly that). Bonus statics:
FIELD_CURRENT_ENTITY 0xCC0964, FIELD_SCRIPT_PC_ARRAY 0xCC0CF8 (Â§4+Â§14).

**Report 3 â€” wall switches missing from the pathfinder.** Two-part
truth: (a) the reactor elevator button ('evb', nmkin_1 ent 12 â€” NEW
ff7_reactor_button_probe.py) is a LINE entity, ALREADY listed under
Triggers but as cryptic "evb, scene" (its action lives in a move slot,
so the line catalog files it SCENE) â€” fixed by name translation
('evb' â†’ "elevator button"); reclassifying SCENE-vs-device lines
automatically was rejected â€” cutscene triggers also reach MES, no
honest offline discriminator found. (b) switch/lever MODELS were
MC_SCENERY-filtered â€” the v2.30.36 deferred whitelist, now delivered:
ff7_prop_catalog.h (1341 talk-scripted model entities, generated) +
MC_PROP class: scenery whose (field, entity) is cataloged resurrects
as a Trigger-category "â€¦, device" entry; prox chirp covers it for free
(class-agnostic talk-radius loop). One classifier stays in one place:
the catalog only ever RESURRECTS scenery, never reclassifies.

VERIFY (play): with speak_dialog=false â€” pick-ups speak, story speech
doesn't, log shows "[SYSTEM, dialog off]" / "speaker dialog" tags;
grab the reactor potion â€” it vanishes from Items (no chirp on the
spot); nmkin fields list door devices ("nmkdrâ€¦, device") and the
elevator button speaks "elevator button, scene"; People lists
unchanged (vis= column in the log for the follow-up).

Deployed both installs, hash-verified (7C1EA3C0BB40F163).

---

### v2.30.46 (2026-08-01): the elevator switch â€” story hotspots (curated)

**Report + screenshots**: after Jessie's "Push that button over there!"
(elevtr1), nothing at the panel spot is listed in any pathfinder
category; players are confused at this exact story beat.

**Trace (all offline + the user's own live log)**: the 09:44 session
log shows the field change into elevtr1 (121) right before the prompt;
the runtime line array holds ONLY the 'jump' exit line, and the only
models are Cloud, Barret (parked, vis=0) and Jessie. Yet OK at the
panel produced "Switch On.". Script trace
(ff7_elevtr1_switch_trace.py + the parameterized reactor probe):
elevtr1 text[46] = 'Switch On.'; BOTH MES ops for it live in
**Jessie's entity (av_j)** â€” one in her talk-slot region, one in slot
3 (the animation + window + MES sequence). There is NO switch object:
no line, no prop model, no 'key' opcode anywhere in the field. The
"button" is Jessie's script reacting to the player; the panel spot
just sits inside her talk radius (she stands at (-96,72), talk 80).
Her init also VISI-hides her under a story condition â€” more +0x62
ecology. Side finding: 'ele' entity = scriptless shell; the earlier
'evb' line in nmkin_1 is the OUTSIDE call button (separate thing,
already listed since v2.30.45).

**Why no automatic fix exists**: every browsable source (line array,
models, prop catalog) is genuinely empty here â€” the interaction is
indistinguishable from ordinary NPC dialog at the engine level. Any
automatic "hotspot detector" would be guessing.

**Fix â€” curated story hotspots** (same never-guess rule as the
v2.30.18 scenery list: entries only from played evidence): a small
hand table {field, x, y, z, name} emitted under Triggers, point-located
like exits/lines. First entry: elevtr1 (121) "elevator switch, press
OK" at (-140, 40, 5) â€” between the panel wall and Jessie, inside her
talk radius, so walking there + OK runs her switch script. Listed
whenever the field is visited (story-gating would need the story var â€”
exactly the guessing the list refuses).

VERIFY (play): in the elevator, Triggers lists "elevator switch,
press OK"; directions route to the panel; OK there speaks "Switch
On."; the 'jump' door line still lists with its exit suffix.

No addresses â€” trace only. Deployed both installs, hash-verified
(6B77068526AE09D0).

---

### v2.30.47 (2026-08-01): 7th Heaven spell names â€” retranslation-tolerant signatures

**Report**: under 7th Heaven the battle magic list speaks only "row N",
never spell names. The user's own 10:34 log (2013 install, Echo-S via
7H) shows the mechanism precisely: `BMENU list ... => row 1` fallbacks,
and the in-battle urgent kernel2 scans resolving EVERY section EXCEPT
magic and command (`magic=00000000 command=00000000`, all nine others
found). The magic signature is the literal vanilla head "Cure|Cure2|" â€”
7H text mods use modern tier names (Cure/Cura/Curaga), so entry 1's
bytes differ while Potion/Buster Sword/MP Plus sections still match.
(Same log also live-confirmed v2.30.42's F8 menu writing
speak_dialog=false and v2.30.45's speaker classification running.)

**Ground truth before coding** (ff7_kernel2_sig_ranges.py over vanilla
kernel2.bin): magic name section = 256 entries (first_off 0x200) and
bare "Cure|" self-validates at exactly ONE place in the whole file;
command table = 24 entries (first_off 0x30). Bonus finding: in the
kernel2 FILE "Attack|Magic|" does NOT self-validate (F9-compressed
file text â€” the v2.30.28 expanded-at-runtime lesson from the other
direction); only the runtime copy matches it.

**Fix â€” signature ladders with structural bands**: FindSectionBase
gains an optional first_off acceptance band (defaults keep all callers
identical); magic/command scans try the vanilla two-entry head first,
then fall back to the single-entry head ("Cure|" banded 0x1F0-0x210,
"Attack|" banded 0x28-0x40) â€” entry COUNT is fixed by the kernel
format, so the band blocks a stray matching word in other text (the
measured file has 5 bare "Attack|" hits; only shape-checking survives).
The matched signature is REMEMBERED (g_k2_magic_sig/g_k2_command_sig)
so ValidatedSection's per-read stale check tests the same bytes that
found the section; scan log line now appends msig=/csig=. If a text
mod renames even entry 0, the log self-diagnoses (section 0 + primary
sig shown) and a new rung is one line.

VERIFY (play, 7H install): battle magic list speaks spell names as
shown on screen (Cura etc. if retranslated); scan log shows magic
nonzero with msig='Cure|'; command names likewise; vanilla installs
unchanged (primary sigs still match first).

Deployed both installs, hash-verified (45921165B2AD5AD9).

---

### v2.30.48 (2026-08-01): MAGIC MENU connected â€” one static session, the six-menu recipe

**User report**: spells "not showing up" in the out-of-battle spell
list â€” the screen was the last un-narrated main-menu sub except PHS
(known gap since v2.30.35); silence read as an empty list.

**Static session** (ff7_magic_menu_static.py â€” the shop/limit recipe):
magic sub = menu_subs_call_table[2] = 0x710DFA (rowâ†’index pattern,
third fixed point). Key derivations, all from the annotated disasm:
- **The menu's spell list IS battle's**: the sub computes
  [0xDD17E8]Â·0x440 + 0xDBA5A0, and 0xDBA5A0 == BATTLE_CHAR_BLOCK +
  BCHAR_OFF_MAGIC_LIST exactly ([ptr]+offset == static proof pattern
  again) â‡’ 0xDD17E8 = the menu's PARTY SLOT, entries = the v2.36
  battle layout verbatim (stride 8, u8 id @+0, 0xFF empty). Also
  re-confirms stride 8 â€” the stale "6-byte" comment on
  BCHAR_OFF_MAGIC_LIST corrected this commit.
- **Standard widget at 0xDD1708**: the sub's index math reads +0 col /
  +4 row / +0x14 scroll (exactly the 0x6F4D30 ctor offsets);
  index = col + (row+scroll)Â·3 â€” a 3-column grid.
- **The grayed "battle only" state is a STATIC EXE TABLE**: the draw
  loop maps u8[0x714440 + id] (ids â‰¤0x33) through jump table 0x714430 â€”
  cases 0/1/2 draw color 7 (white), case 3 and ids >0x33 draw color 0
  (gray). Disk bytes: white = ids {0,1,2,7,8,0x33} only. The mod reads
  the SAME table live (in-process .text, no ASLR) â‡’ spoken state
  mirrors the drawn gray by construction â€” no spell-list semantics
  were guessed.
- 0x921100 = pane (0 list / 1 target), 0xDD16D4 = pane-1 cursor row
  (drawn at Â·0x78) â€” the two LEAST-PROVEN pieces, flagged verify-live.

**Shipped MagicMenuThread** (LimitMenuThread clone): gate = dispatch
index 2 + the standard stand-downs; entry "Magic. <char>"; per-cell
speech = kernel2 magic name (through the v2.30.47 retranslation-
tolerant signature â€” the 7H report that exposed this screen gets
correct names too) + ", battle only" per the exe table; "Empty" cells;
slot-change re-announce; pane-1 "Use on whom?" + target names.

RESIDUALS (TODO [MAGICMENU]): I-key descriptions (needs a kernel2
magic-desc signature), MP cost, Summon/Enemy-Skill top-bar tabs
(unmapped â€” the list widget tracked is the MAGIC tab's), pane-1
semantics verify. Menu family now: everything except PHS.

VERIFY (play): open Magic â€” "Magic. Cloud" + first spell; arrows speak
names matching the screen incl. grayed ones as "battle only"; empty
cells say "Empty"; on 7H, names match the retranslation. Log lines
"MAGICM ...".

Deployed both installs, hash-verified (37ADB82E73E2904B).

---

### v2.30.49 (2026-08-01): Defend/Change spoken â€” pseudo-commands are widget STATES

**User question**: "should there be a Defend option?" â€” Defend exists
in vanilla FF7 but is HIDDEN: Right on the Attack cell swaps its label
to Defend, Left shows Change (row swap). The v2.9 research knew the
pseudo-command ids (0x12 Change / 0x13 Defend, never stored in the
command table) but not where they lived â€” so the mod, which speaks
from the table, stayed silent and Defend was undiscoverable by ear.

**Disasm (ff7_defend_toggle_static.py, fn table 0x91E6B8)**: the
command-state handler fn[1] = 0x6D91FA tests LEFT (0x8000) / RIGHT
(0x2000) at the grid's EDGE COLUMN and jumps straight to dedicated
widget states: **state 2 = Change, state 3 = Defend** â€”
issued_command_id (0xDC3C70) pre-loaded with 0x12/0x13 at
0x6D937C/0x6D9429, BATTLE_MENU_STATE (0x91EF9C) written directly, menu
busy flag set. (Input masks match the tutorial VM's key table â€”
LEFT 0x8000 / RIGHT 0x2000 â€” a nice cross-proof.) So the pseudo-
commands were never a label swap at all: they are two one-entry
widgets, fn[2] 0x6D9DBE / fn[3] 0x6D9ED7.

**Fix**: BattleMenuThread already tracks state transitions â€” states
2/3 now speak the game's own labels ("Change"/"Defend") on the entry
edge (speak_battle_menu-gated); Cancel back to state 1 re-announces
the command via the existing last_cmd_key reset, so the round trip is
voiced. Both states joined in_turn_session so the whose-turn announce
doesn't re-arm mid-Defend. Users can now: Attack â†’ Right â†’ hear
"Defend" â†’ OK.

VERIFY (play): on Attack press Right â†’ "Defend"; Left at the left
edge â†’ "Change"; Cancel â†’ command re-speaks; OK on Defend â†’ turn
proceeds (action side already worked). BMENU state log lines show
1â†’3/1â†’2.

Deployed both installs, hash-verified (8DC272CE6FEE4AC7).

---

### v2.30.50 (2026-08-01): equip menu play-correction â€” 0xDCA4A4 was the CHARACTER, not the category

**Play report**: Barret's equip screen announced "Bronze Bangle" at
entry, then every cursor move was silent. The log made it exact: entry
1 (Cloud) logged cat=0, entry 2 (Barret) logged cat=1, and the "cat"
byte never changed while the pane flag moved freely.

**Root cause â€” v2.30.34 misidentification**: TWO 0..2-wrapping cursors
coexist on the equip screen, and the July static session grabbed the
wrong one. Re-reading the very Â±1-wrap disasm that "settled" 0xDCA4A4
as the category cursor (0x707079/0x7070C0): after each step it reads
**SAVEMAP_PARTY_IDS[0xDCA4A4]** and RE-STEPS on 0xFF â€” an empty-party-
slot skip loop. That is a PARTY-MEMBER cycler (the L1/R1 character
flip; the 0x707105 key path copies it into CHARSEL_CHOSEN). With a
full 3-member party, both cursors wrap 0..2 â€” indistinguishable by
value range; the skip loop was the overlooked discriminator. The
"cat=slot" coincidence even made entries LOOK right (Cloud=0=Weapon,
Barret=1=Armor â€” hence "Bronze Bangle": Barret's ARMOR row was never
on screen; his SLOT is 1).

**The real category row = 0xDCA5C4** (ff7_eqcat_writers.py +
re-reading the July log): the OK handler (key 0x20 test at 0x707175)
passes IT to the candidate-list builder (0x707187 â†’ 0x7083ED), and
every bounds check in the sub compares it against 2. Second latent bug
fixed in the same pass: gear names resolved via CHARSEL_CHOSEN, which
only updates on specific key paths â€” after an L1/R1 flip the rows
would have described the PRE-FLIP character. The thread (and
EquipCategoryLine/record resolution) now key entirely off
EQMENU_PARTY_SLOT (0xDCA4A4's true identity), which also makes L1/R1
character flips announce.

âš  LESSON (the v2.30.12 principle, static edition): a Â±1-wrap disasm
proves "a cursor", not WHICH cursor â€” when a screen has multiple
same-range widgets, the discriminator is what the value INDEXES
(party-ids skip loop) or what consumes it at commit (the OK path's
argument), not the wrap shape.

VERIFY (play): Barret equip: entry speaks "Equip. Barret" +
"Weapon: Gatling Gun" (whatever row the screen actually remembers);
up/down speaks the three rows with gear names; OK into a list tracks
candidates; L1/R1 speaks the next character and re-reads rows for THAT
character; equipping re-announces the new gear.

Deployed both installs, hash-verified (A781162AF70DEEA3).

---

### v2.30.51 (2026-08-01): character-flip announces cut off â€” the interrupt-chain class

**Report** (minutes after v2.30.50): L1/R1 on the equip screen spoke
only the gear row, not the character name. The name WAS spoken â€”
interrupt=true â€” and the row re-announce triggered by the same flip
landed in the same poll, ALSO interrupt=true, cutting the name after a
syllable. The identical bug was caught in review on the F8 menu's open
sequence (v2.30.42) â€” and the same pattern existed unnoticed in FOUR
menu threads' character-flip branches: equip (reported), limit (grid
+ bar), magic (selection), materia (cursor line).

**Fix**: every flip branch now marks the poll as an announce sequence
(the same fresh/announce_context flag each thread's ENTRY path already
uses) so the follow-up re-announce queues (interrupt=false) behind the
name. Limit's grid line switched from hard interrupt=true to !fresh to
participate.

âš  CLASS RULE, now three sightings (F8 open, magic-menu open guard,
this): whenever ONE user action produces TWO utterances in the same
poll (context + detail), the SECOND must queue. Any new "announce A
then B" sequence should default to interrupt-then-queue, and reviews
of new menu threads should grep the flip/entry branches for
back-to-back interrupt=true.

VERIFY: L1/R1 in equip/materia/limit/magic speaks "<Name>" THEN the
row/selection line in full, both audible; normal cursor moves still
interrupt crisply.

Deployed both installs, hash-verified (4896259E5B95895D).

---

### v2.30.52 (2026-08-01): magic menu modes were INVERTED â€” diagnostic-led correction

**Report**: the magic list speaks the selected spell on entry, then
arrows say nothing (left/right do nothing at all).

**Method note â€” the diagnostic paid for itself.** Static reasoning had
two live-plausible causes (stale cursor addresses vs. a gate bailing
out), so instead of guessing, a debug-only probe logged the gate inputs
plus the cursor trio on every change. One 20-second session settled it:
`screen=2` held for the whole 9 seconds (so the thread was NOT bailing
â€” my leading theory was wrong) and the cursor trio never moved through
eight presses. Cost: one build + one short test; the alternative was
another wrong-guess release.

**Root cause**: the v2.30.48 mode semantics were INVERTED. The screen
dispatches input through a jump table at 0x7144CC:
**case 0 (0x7135F8) = CHARACTER-SELECT pane** (its up/down cycles the
party slot with the SAVEMAP_PARTY_IDS 0xFF skip â€” the third sighting of
that cycler shape, after equip v2.30.34/.50), **case 1 (0x71377F) = THE
SPELL GRID** (it computes the spell index from the cursor trio and runs
the OK press with the MP check: cost = list entry byte +1, current MP =
[slotÂ·0x440 + 0xDBA4AC]). The mod had 0 = list and treated 1 as a
"target pane" it SKIPPED â€” so it announced a spell the instant the
screen opened (while the player was still choosing a character) and
then went permanently silent once the grid actually had focus. The
player's arrows were moving the character pane, which the mod wasn't
watching at all.

**Fix**: modes corrected (0/-1 = character select, 1 = grid, 2/3 =
confirm sub-modes written as mode+2 at 0x713638/0x713693). The
character pane now announces, and â€” Limit-menu style â€” watches BOTH
candidate cursors (MAGICMENU_PARTY_SLOT and CHARSEL_CURSOR),
announcing whichever the game moves, so a wrong guess about which one
this pane uses cannot silence it again. Grid entry re-announces the
selection. MAGICMENU_TARGET_ROW renamed MAGICMENU_TARGET_SLOT (the OK
path indexes SAVEMAP_PARTY_IDS with it at 0x7137F8).

âš  THIRD SIGHTING of the party-cycler-vs-cursor confusion (equip twice,
magic once): when a menu variable wraps 0..2, check for the
party-ids-skip loop BEFORE calling it a row cursor.

The diagnostic stays in this build (now logging charsel too) until the
retest confirms; it is debug_log-gated and one line per change.

VERIFY: open Magic â€” hear the character pane (names as you move), pick
a character, then arrows speak spell names with "battle only" where the
screen greys them; log shows `MAGICM mode 0 -> 1` at the transition.

Deployed both installs, hash-verified (AB959BC597EA5026).

---

### v2.30.53 (2026-08-01): magic grid is mode 2 â€” measured, not inferred

**Report on v2.30.52**: "it speaks Cloud as if he is a spell â€” still
stuck on character select."

**The second diag session is the whole answer** (and this time the
numbers are LIVE, not derived): screen 2 held throughout;
mmode âˆ’1 â†’ 0 (character pane, slot moved 0â†’1â†’0 as the player browsed
characters) â†’ **2 on OK, and in mode 2 the cursor trio MOVED with the
player's presses (row 0â†’1â†’0)** â†’ back to 0 on cancel. So the grid is
**mode 2**, the trio is confirmed as its cursor, and v2.30.52's
`MODE_LIST = 1` sent every grid poll into the character branch â€” hence
character names spoken where spells belong.

**Why the static read said 1**: the jump-table case index is NOT the
stored value. The OK paths write `mode = [0xDD169C] + 2`
(0x713638/0x713693), so the value parked in 0x921100 is offset from
the case number the dispatcher uses. Reading the table told me the
SHAPE of the state machine correctly (a character pane and a grid
pane, and which handler owns the spell index) but not the ENCODING â€”
that only the live values could give.

âš  LESSON: a jump-table decode yields case indices; if the variable is
written with an offset (mode+2 here), those indices are NOT the values
to compare against. Measure the variable, or derive the offset, before
hard-coding state constants.

**Shipped**: MODE constants now live-measured (âˆ’1 entering, 0 char
select, 2 grid, â‰¥3 confirm/target); grid branch keyed on 2; a target
branch added for â‰¥3 that speaks "Use on whom?" plus the party member
under MAGICMENU_TARGET_SLOT. Diagnostic kept one more round.

VERIFY: Magic â†’ character names while choosing â†’ OK â†’ spell names
with "battle only" as the screen greys them â†’ arrows track â†’ cancel
returns to character names. Log: `MAGICM mode 0 -> 2` then MAGICM
spell lines.

Deployed both installs, hash-verified (CAA7D3A1AB45D9CD).

---

### v2.30.54 (2026-08-01): the magic screen is a THREE-TAB screen â€” delta scan ends the guessing

**Three failed versions in a row** (.48 wrong cursor semantics, .52
inverted modes, .53 wrong encoding) all shared one root cause: I kept
INFERRING which variable the player's presses move. v2.30.54 measured
it. A debug-only DELTA SCANNER (in the mod: snapshot 0xDD1600-0xDD18FF
+ 0x921000-0x9211FF every poll while the screen is open, log every
dword that changes with its address) plus a scripted user test â€”
"open Magic, wait 2s, press Down exactly three times slowly" â€” gave
the answer in ONE session:

    MAGICM scan 0x00DD169C: 0 -> 1
    MAGICM scan 0x00DD169C: 1 -> 2
    MAGICM scan 0x00DD169C: 2 -> 0

ONE address moved, wrapping at THREE. Not a spell cursor, not a
character cursor: **the Magic / Summon / Enemy Skill TAB SELECTOR**.
Everything else fell out immediately:
- mode = TAB + 2 (the 0x713638/0x713693 writes) â‡’ mode 2 = Magic list,
  3 = Summon, 4 = Enemy Skill; mode 0 = the selector; -1 = entering.
  (That is also why .53's "grid = mode 2" worked in one session and
  looked wrong in the next â€” the player was on the SELECTOR both times.)
- Each tab owns a canonical widget and a per-character list base (draw
  0x710F94/0x71186E/0x711EB8, OK 0x7137A9/0x712C46/0x713284):
  Magic 0xDD1708 / +0x108 / 3 columns; Summon 0xDD1740 / +0x2C8 /
  2 columns; **Enemy Skill 0xDD1778 / +0x348 / 2 columns** â€” a
  previously unknown third per-character list.

**Shipped**: tab-aware MagicMenuThread â€” the selector speaks
"Magic"/"Summon"/"Enemy Skill", each list browses with its OWN widget,
base and column count, names via the v2.30.47 kernel2 signature, and
the ", battle only" suffix from the exe's own grey table. The scanner
is removed; the one-line state diagnostic stays until play-confirmed.

âš  THE LESSON, stated plainly: static analysis gives structure, never
live semantics. When a screen's behavior doesn't match the model,
MEASURE THE MEMORY (a scoped delta scan costs one build and one 30s
session) instead of re-reading the disassembly for a better story.
Three shipped-broken versions is what the alternative cost.

VERIFY: Magic â†’ hear "Magic"/"Summon"/"Enemy Skill" as you move the
tabs â†’ OK â†’ spell names with "battle only" where greyed â†’ arrows
track â†’ cancel back to tab names; Summon/E.Skill tabs list their own
entries.

Deployed both installs, hash-verified (68BC1A7646402DEA).

**PLAY-CONFIRMED 2026-08-01** ("I think we got it that time"). The
magic screen is done: tab selector spoken, all three lists browse
correctly. v2.30.55 strips the investigation diagnostic (delta scanner
already removed in .54; the state line now too) â€” the release build
carries no probe code.

---

### v2.30.56 (2026-08-01): timer on a mid-countdown save load â€” WSPCL arming + honest T

**Report**: a tester loaded a save made with the timer "disabled"; the
countdown silently resumed, and T answered "timer disabled" while it
was visibly counting down. Their log is unambiguous:
`TIMER ticking value 288 suppressed (no STTIM this runâ€¦)` then T
presses at val 284 â†’ 281 â†’ 277 â†’ 269 â†’ 241, all `running=0 live=0`.
(288s â‰ˆ the 5-minute reactor timer the 7H/Echo-S mod substitutes for
vanilla's 10 â€” that is why testers meet this case: a shortened escape
makes saving mid-countdown far likelier, not because 7H changes the
mechanism.)

**Engine truth, established this session**
(ff7_timer_window_static.py): the countdown decrement at **0x40AC3C**
is inside the global tick (0x40AB81) and is gated ONLY by two pause
bytes (savemap +0x1134/+0x1138) and a count-up flag bit
(0xDC093B & 2 â†’ the 0x40AC56 increment branch). **There is no
"timer active" flag anywhere** â€” which is precisely why a finished
escape's leftover value keeps ticking invisibly (the v2.30.8 report)
and why "it is ticking" can never, by itself, prove a live timer.
Bonus map: 0xDC08C0/0xDC08C4 are two Ã—0x444 accumulators (play-time
and countdown), 0xDC08B8 the play-time seconds.

**The honest discriminator is the DISPLAY**: vanilla shows the clock
only while a countdown really runs. WSPCL (0x36) creates that window â€”
handler 0x61FD5C writes its type arg to byte [0xCFF5D3 + win*0x30] and
the position to +0xE0/+0xE2. So v2.30.56 hooks WSPCL as a SECOND
arming signal (types 1/2 = clock family; every call logs id+type, so a
field using a different type is self-diagnosing). A save loaded
mid-escape arms as soon as the script re-creates its clock.

**And the T key no longer lies**: a sane, nonzero, actively-decreasing
value that the arming gate has suppressed now reads as "Clock counting
down. N minutesâ€¦" instead of "No active timer", and Shift+T may freeze
it (a pure savemap write â€” harmless even if the value is a stale
leftover). Automatic announcements stay gated, so a stale ticker still
cannot start narrating on its own.

âš  OPEN (needs the tester): whether the clock window is actually
re-created on a mid-countdown load. If WSPCL does not fire there, the
log will show the ticking-value line with no WSPCL line, and the next
step is reading the window-state table directly (the type byte above +
the per-window state array) rather than an opcode hook.

VERIFY: load a save made during the reactor escape â€” the log should
show `WSPCL special window: id=â€¦ type=â€¦ -- countdown clock armed` and
normal countdown announcements; T should report the time either way,
never "no active timer" while it ticks.

Deployed both installs, hash-verified (E0B2D04573B2B3E0).

---

### v2.30.57 (2026-08-01): magic menu completed â€” MP costs, affordability, descriptions

Closes the v2.30.54 residuals: everything a sighted player reads on the
spell screen is now spoken.

**MP cost + affordability come from the game's OWN check.** The OK
handler (0x7137C4..0x7137E5) reads cost = list entry byte **+1** and
current MP = u16 at [slotÂ·0x440 + 0xDBA4AC] (= char block +0x14, the
BCHAR_OFF_MP pair) and refuses the cast when MP < cost â€” precisely when
the screen dims the spell. The mod now speaks "<name>, N MP", appends
", not enough MP" on that same comparison, and keeps ", battle only"
from the exe's grey table. Entry announce gained the character's
"C of M MP" (on screen the whole time).

**SPELL DESCRIPTIONS â€” new kernel2 section.** Found by enumerating
every self-validating section in the decompressed kernel2
(ff7_kernel2_section_enum.py): base +0x315, **256 entries,
index-aligned with the magic NAME section** (Cure â†’ "Restores HP",
Regen â†’ "Gradually restores HP", Esuna â†’ "Cures unusual status",
Life â†’ "Restores life"). Head signature "Restores HP|Restores HP|"
(entries 0-2 are all Cure-family) matches twice in the file, so the
v2.30.47 entry-count band (first_off 0x200) is what pins it. Exposed
on the **I key**, matching the FF4-scheme parity line and the
shop/materia/equip readers' focus/edge/F8-standdown discipline;
answered on any poll, not just when the cursor moves.

All three tabs share the section (summons and enemy skills live in the
same magic id space), so descriptions work across Magic/Summon/Enemy
Skill for free.

VERIFY: Magic â†’ entry says "Magic. Cloud. 46 of 46 MP"; each spell
reads "Cure, 5 MP" (+ "battle only" / "not enough MP" where the screen
greys); I speaks the description; scan log shows mg_desc= nonzero.

Deployed both installs, hash-verified (E08298AF836D0BCB â€” the cfg
glossary edit re-ran the CMake embed, so the shipped DLL is the
post-embed rebuild).

---

### v2.30.58 (2026-08-01): magic TARGET pane ("use Cure on whom?") spoken

**Report**: picking a field-usable spell opens a character picker that
was silent.

**Deliberately MODE-AGNOSTIC.** I have no live capture of this pane's
mode value, and guessing state numbers on this screen has already cost
three broken versions (.48/.52/.53). So instead of asserting a number:
the pane is recognised as "a mode that is neither the tab selector nor
one of the three list modes", AND the announce is driven by
MAGICMENU_TARGET_SLOT (0xDD16D4) actually CHANGING â€” the slot the
game's own OK path feeds to SAVEMAP_PARTY_IDS at 0x7137F8, i.e. the
picker's cursor. Either signal alone is enough for the player to hear
the character; last_tslot resets on every mode change so the pane's
initial write cannot speak before the player moves.

Speaks the target's name plus **HP** ("Barret, 314 of 442 HP") â€” the
picker shows each character's HP/MP, and HP is what decides a heal.
(The caster's MP is already on the entry announce, v2.30.57.)

A debug line records the pane's REAL mode value the first time a
target is announced, so one play session upgrades this from
mode-agnostic to documented â€” the same measure-then-document discipline
the delta scan established.

VERIFY: Magic â†’ Cure â†’ the picker speaks a character (with HP) and
tracks up/down; cancel returns to the spell list; log shows
`MAGICM target mode=N slot=â€¦` (report N so the constant can be named).

Deployed both installs, hash-verified (62910DC38C370FA5).

---

### v2.30.59 (2026-08-01): target pane reached at last â€” a control-flow bug the COMPILER found

**Report on .58**: the picker still said nothing. The log gave the
missing constant though: `MAGICM mode 2 -> 1` on selecting Cure and
`1 -> 2` on cancel â‡’ **the target pane is mode 1**
(MAGICMENU_MODE_TARGET; note 1 was also v2.30.52's WRONG guess for the
spell list â€” right number, different pane).

**But the silence had a second cause, and the toolchain diagnosed it.**
The v2.30.54 TAB-SELECTOR guard catches every mode outside 2..4 â€”
including mode 1 â€” and `continue`s, so the .58 target branch (and the
delta scanner added to debug it, which is why THAT produced no output
either) sat downstream of an unconditional continue. MSVC proved the
block unreachable and eliminated it: the giveaway was that the
branch's log string was **absent from the shipped DLL even after a
forced clean rebuild** of proxy.cpp. Verifying a binary by grepping it
for the strings the new code should contain is now a standing check â€”
"the literal isn't in the DLL" means dead code, not a stale build.

Fix: the tab guard excludes the target mode, the target branch keys on
MAGICMENU_MODE_TARGET explicitly, and 0xDD16D4 is confirmed as the
picker's cursor by play ("spoke characters cleanly"). Scanner removed;
the one-line MAGICM target log stays, matching the other menu threads.

âš  LESSON: when a new branch never fires, check its ORDER against the
existing early-`continue` guards before doubting its addresses â€” this
screen's data was right and its control flow was wrong.

Deployed both installs, hash-verified (663C47D00AD6CD0E).

---

### v2.30.60 (2026-08-02): ladders â€” "On ladder, push up" / "Off ladder"

**Report**: testers can't tell when they are on or off a ladder, or
which way to push.

**Both halves came out of the LADER handler** (opcode 0xC2 = 0x615EC6,
ff7_ladder_static.py â€” the v2.17 session had noted this handler in
passing; this one read it properly):

- **ON/OFF is unambiguous.** The handler's four script cases (jump
  table 0x6163D0) write movement type **4** (cases 0/1) or **5**
  (cases 2/3) to field_event_data **+0x63**, and its own re-entry test
  is `>= 4 && <= 5` = "this model is already climbing" (0x615F33); on
  arrival it writes 0 back (0x615F9E). A .text sweep found only two
  other writers of that byte (0x60C321 / 0x60D494) and **both write
  0** â€” so 4/5 is a positive, exclusive "on a ladder" signal needing no
  heuristic. (This is the class of evidence the timer work lacked: for
  ladders the engine really does have a state flag.)
- **WHICH WAY is the climb target.** +0x7C/+0x80/+0x84 hold the target
  x/y/z, script args shifted <<12 (0x616168/0x61619A) â€” the same
  fixed-point scale as model_pos, so target>>12 subtracts directly from
  the player's position. The bearing is rotated by control_direction
  and quantised by the SAME DpadSectorIndex/kDpadSectors the pathfinder
  uses, so "up and left" means exactly what it means in a route.

Bonus: +0x6E (0/1 per case) is the orientation variant â€” this finally
explains the "rc6E â‰¡ 0" reading from the v2.30.24 radius hunt: that
byte is only written during a climb. +0x70 is the movement phase
(0 armed / 1 moving / 2 arrived).

**Shipped** in FieldNavThread's continuous section: mount edge speaks
"On ladder, push <direction>", a target flip re-announces (top-of-
ladder turnarounds), dismount speaks "Off ladder". Gated by
pathfinder_keys with the rest of this thread's field narration; one
debug line per transition.

VERIFY (reactor ladders): mounting speaks "On ladder, push up" with a
direction matching what actually climbs; stepping off speaks "Off
ladder"; no announcements while walking normally; the direction stays
correct after a screen change (control_direction rebases it).

Deployed both installs, hash-verified (7F4ABF0CBA439A66).

---

### v2.30.61 (2026-08-02): level-ups announced — the watcher freed from the results window

**Request**: announce when a character levels up on the victory screens.

**It was already written (v2.35) and structurally unable to fire
reliably.** The watcher lived INSIDE the detected results window, so it
inherited two gates that can each miss:
1. `MENU_OPEN != 1` → `continue`, above the watcher, and
2. the window itself is recognised by a 4-second battle-recency
   heuristic (`g_last_battle_tick`, stamped only while GAME_MODE==2 by
   BattleActionThread) — if that stamp is stale when the results
   MENU_OPEN rises, `in_results` never becomes true and the level watch
   never runs at all.
No log in hand showed a victory window, so rather than tune a
heuristic I removed the dependency: **a level-up is worth announcing
whenever it happens**, and the savemap level byte is authoritative
without any results-screen context.

**Now**: the watch runs every poll (150ms), before both gates.
False-positive guards, since a level byte changes for non-level-up
reasons too:
- keyed by CHARACTER ID per party slot — a PHS/story swap puts a
  different person in the slot, which re-baselines instead of
  announcing;
- the first observation after start (or after speak_battle is
  re-enabled) baselines SILENTLY;
- a jump of more than 3 levels reads as a save load or a scripted join
  (Cait Sith arrives around level 20) → silent re-baseline, logged when
  debug_log is on. Real level-ups step one at a time through a 150ms
  poll even on a huge EXP haul.
Speech stays interrupt=false so it queues behind the victory line
(v2.30.51 rule).

Because it no longer depends on the results window, level-ups from
story events or item use announce too — strictly more than asked, and
the guards keep it from narrating save loads.

VERIFY: win a battle that levels someone → "Cloud grew to level 8!"
after the victory line; load a save with different levels → silence
(log shows "re-baselined, not announced"); PHS swaps → silence.

Deployed both installs, hash-verified (4CC6B6C320A9DF6D).

---

### v2.30.62 (2026-08-02): proximity ANNOUNCE — say what you reached

**Request**: announce what the player has come within interaction range
of (a ladder, a jump, a person with dialog), on its own config toggle,
default on.

**No new detection was needed** — the v2.27 proximity chirp already
solves the hard half (interaction range = max(talk radius, body
contact + a step), once-per-approach arming, z-gate for other layers,
talk-disabled and VISI-hidden skipped, silence during cutscenes and
dialog). This adds the NAME on the same arming edge, so the two are
exactly in step: one chirp, then one name.

**Names come from the browser's own machinery**, deliberately: models
through FieldModelLabel → ClassifyModelLabel → TranslateDevLabel (plus
the v2.30.45 prop catalog, so a cataloged scenery model announces as
"…, device"), and lines through the entity-name table →
TranslateEntityName → the offline behaviour catalog's suffix. A thing
is therefore called the SAME whether the player walked into it or
cycled to it with J/L ("ladder up, climb", "pinball, exit to Seventh
Heaven", "Biggs", "Chest", "Save point") — one vocabulary, not two.
Scenery stays unspoken exactly as the browser filters it; the v2.17
entity/slot cross-check still degrades an unmatched line to
"Trigger N" instead of a plausible wrong name.

Speech is QUEUED (interrupt=false): walking past three things reads as
a list rather than each clipping the last, and it cannot clip dialog
that starts in the same instant.

**New setting `proximity_announce`** (default true) — cfg list +
glossary + the F8 menu ("Say what you reached"). Kept separate from
proximity_tone because they suit different moments: the chirp is quick
and unobtrusive once a room is known; the name answers "what did I
just walk up to?" on a first visit. Either may be used alone; the
range/arming logic now runs if EITHER is enabled.

VERIFY: walk to a reactor ladder → chirp + "ladder up, climb"; to
Biggs → "Biggs"; to a chest → "Chest"; walk away and back → it speaks
again; standing still stays quiet; turning the setting off in the F8
menu leaves the chirp working alone.

Deployed both installs, hash-verified (DBBE6868F0B7AC35).

---

### v2.30.63 (2026-08-02): save slots read "empty" on the 2013 release — wrong FOLDER, right format

**Report**: on 2013 + 7th Heaven the save menu reports every slot empty.

**Cause: one hard-coded save location.** The v2.29 reader looked only in
`<dll dir>\save\` — correct for the 1998 release and for 2026
(`ff7/workingdir/save/`), but the **2013 Steam release keeps saves in
the user's Documents**:
`…\Square Enix\FINAL FANTASY VII Steam\user_<steamid>\saveNN.ff7`.
Reproduced locally: the 2013 install's game-dir `save\` folder EXISTS
but is empty (so it isn't even a missing-folder error — it silently
shadowed the real location), while the Documents copy holds the real
file.

**The format was never the problem.** Parsing that very file with the
§5 preview layout gives "Cloud, level 7, Mako Reactor 1, 376 gil,
25 minutes" — so no re-derivation was needed, and 7th Heaven turns out
not to redirect saves at all (a checked assumption: the report named
7H, but the 2013-vs-2026 split is the real variable).

**Fix — ResolveSaveDir()**: try `save\` beside the DLL, then
`Documents\Square Enix\FINAL FANTASY VII Steam\user_*\`, choosing the
most recently written profile when several Steam accounts exist. A
directory only qualifies if it CONTAINS a `saveNN.ff7`, which is
exactly what lets the empty 2013 folder fall through instead of
shadowing. Result cached; re-resolves if the cached folder loses its
files. One log line names the chosen directory.

⚠ **Documents must come from the shell.** This machine has OneDrive
folder redirection — `%USERPROFILE%\Documents` does not exist, the real
path is `…\OneDrive\Documents`. SHGetFolderPath (CSIDL_PERSONAL) returns
the redirected location; shell32 added to the link line for it.

**Offline dry-run before deploy** (the same resolver compiled
standalone, run against BOTH real installs): 2013 → falls through the
empty folder to the OneDrive profile, finds save00.ff7 (65,109 bytes);
2026 → unchanged, uses the game folder. Absent files still read as
empty slots, which is what the sighted menu shows.

VERIFY (2013 + 7H): the save/continue menu speaks the real slot data
("Cloud, level 7, Mako Reactor 1…"); 2026 unaffected; log line names
the resolved directory.

Deployed both installs, hash-verified (636AB4A95FBCCBB2).

### v2.30.64 (2026-08-02): TRANSITION TRACKING - arrival facing + jump-mailbox watcher

**Origin**: the screen-construction investigation (same day - see the §4
FIELD_JUMP_INTERFACE / model-FACING rows and §14 code landmarks for the
full static derivations). User picked transition tracking as the first
build on those findings; the journey graph waits until this is
play-confirmed.

**What ships**:
1. **Arrival facing in the screen announce**: "Screen: Sector 1 Station,
   facing up." The facing byte is field_event_data +0x38 (proven three
   ways: DIR writes it, GETDIR reads it, the arrival routine copies the
   jump mailbox's direction into it at 0x63C094). Read from the byte
   itself, not the mailbox, so a scripted entry that turns the player
   still announces the truth. Same d-pad vocabulary as routes/ladders.
   Rides the existing announce_map_change setting - NO new cfg key, no
   embed regeneration.
2. **Jump-mailbox watcher** (log-only this version): placed BEFORE the
   FieldNavThread field gates (a pending jump holds GAME_MODE=1, which
   the gates discard - the v2.30.59 gate-ORDER lesson applied
   preemptively). One "[FF7Access] JUMP armed dest= x= y= tri= dir=
   phase= mpjpo= from=" line per armed jump - covers gateway walks,
   MAPJUMPs, save loads, and world-map exits, per the static proof that
   all entry paths share the mailbox.
3. **ARRIVE live-confirm line** (debug, independent of the announce
   setting): "[FF7Access] ARRIVE field= via=jump|direct facing38=
   destdir= match= ctrl= sector= destfld= mpjpo=". match=1 = the +0x38
   static proof confirmed live; the raw byte + spoken sector pair is the
   v2.14 calibration playbook applied to facing (the wheel-to-screen
   composition `screen = world + control - 180` is PROVISIONAL for
   facing until one log agrees).
4. **MPJPO folded in** (ff7_mpjpo_static.py): opcode 0xD2 handler
   0x61A4D4 writes its byte arg to [modules]+0x36 = **0xCC0DBE
   FIELD_MAPJUMP_DISABLED** - the PSX "map jump disabled" label
   CONFIRMED. Read into both debug lines; no spoken behavior yet (value
   convention 1=disabled awaits one log sighting during a scene).

**Address block added** (ff7_addresses.h): FIELD_JUMP_DEST_FIELD/X/Y/TRI/
DIR 0xCC0D8A/8C/8E/AA/AC, FIELD_JUMP_PHASE 0xCC0DAE (READY=2),
GAME_MODE_FIELD_JUMP=1, FIELD_MAPJUMP_DISABLED 0xCC0DBE,
FIELD_EVENT_FACING +0x38. ⚠ Mailbox bytes are STALE after arrival -
consumers must pair them with an edge/latch (the countdown-timer lesson,
v2.30.8, same class).

**Build checks**: all three new literals grep'd in the built DLL (JUMP/
ARRIVE narrow, ", facing " wide - the v2.30.59 dead-code check; note
wide literals need a UTF-16 search).

VERIFY (play-test): (a) every screen change speaks ", facing X" and X
matches the room (if consistently opposite/rotated, the facing wheel
needs an offset - the ARRIVE line has the raw byte to derive it from);
(b) JUMP armed lines appear for walk-across exits AND for a save load;
(c) ARRIVE match=1 on ordinary gateway walks; (d) an MPJPO sighting:
mpjpo nonzero during some scripted scene. Full checklist TODO [TRANSIT].

Deployed both installs, hash-verified (A53BE6061DAA2192).

**PLAY-TEST CONFIRMED same day (2013 + 7th Heaven, reactor run new game
-> save before the boss; log 13:18-13:33 + the user's auto screen
captures at ~0.55s intervals)**:
- 7 JUMP armed lines, mailbox contents byte-identical to the offline
  gateway dump where comparable (116->117 = md1stin gw0 exactly:
  x=1049 y=400 tri=90 dir=58) - the interface is LIVE-CONFIRMED.
- ARRIVE match=1 on 5/7 jump arrivals -> **facing +0x38 = mailbox
  direction CONFIRMED LIVE**. The two match=0 are the predicted
  scripted-entry class (117 = opening train cutscene, 120 = nmkin_1
  entry scene) - and the announce stayed honest (reads the byte).
- **Facing wheel calibration CONFIRMED by screenshots**: nrthmk bridge
  arrival spoke "left" and the capture shows the party crossing the
  bridge leftward (decisive); elevtr1 "right" and nmkin pipe-room
  "up and left" consistent. No offset needed - `screen = world +
  control - 180` holds for facing.
- RESIDUAL 1: the arm edge is BEST-EFFORT - 117->118 arrived
  via=direct (fast load, GAME_MODE==1 window < one 50ms poll).
  Arrival is authoritative, as designed. RESIDUAL 2: that same
  transition's mailbox dir was 128, but md1_1's gateway record says
  132 -> the story-gated door used a scripted MAPJUMP, not the
  gateway - the journey graph must prefer the line catalog for
  script-gated doors. RESIDUAL 3: mpjpo=0 the whole run - the
  1=disabled convention still awaits a scene sighting.
- Same log also CONFIRMED: v2.30.63 save dir (2013+7H resolved the
  OneDrive Documents profile, slot read "Cloud, level 7, Mako
  Reactor 1...", save written), v2.30.60 ladders (on/off + push
  directions through nmkin climbs), v2.30.61 level-up (Cloud 6->7
  announced from an ordinary battle), journey planner (3-component
  ladder route to the save point). NEW ISSUE from the same scan line:
  **mg_desc=00000000 under this 7H profile** while spell-name sigs
  matched vanilla - the magic-DESCRIPTION section signature fails
  (text mod rewords descriptions?); Magic I-key descriptions silent
  on 7H until a sig ladder like v2.30.47's (TODO [K2DESC]).

### v2.30.65 (2026-08-02): CROSS-FIELD JOURNEY GRAPH - the "Places" category

**The GPS feature the construction investigation was for**: pick a place
you have visited, get guided there screen by screen.

**Interaction (key parity - ZERO new bindings)**: a 7th browser category
"Places" (Shift+J/L). J/L cycles VISITED places (the v2.25 caption
cache = parity with a sighted player's memory), nearest-first as
"Sector 1 Station, 3 screens"; several fields sharing one caption list
only the nearest. K announces. **\ or P starts the journey**: speaks
"Journey to X, N screens. First, To <next screen>: <turn-by-turn>" -
the first leg is fed through the UNCHANGED directions tail, so
turn-by-turn, within-field journeys, and body cautions all apply.
On every arrival (the v2.30.64 transition tracking edge) the journey
recomputes FROM THE ACTUAL FIELD and queues "X: N screens left. Next,
To Y, up and left, 4 seconds" behind the screen announce - wrong turns
and detours self-heal because the next leg is always the shortest path
from wherever the player really is. Arrival at the target: "Arrived: X.
Journey complete." Shift+K cancels ("Journey ended.").

**Graph** (nodes = maplist field ids, directed edges = ways out):
- NEW generated header ff7_field_graph.h (ff7_field_graph_catalog.py):
  1036 gateway edges {src, dst, slot} game-wide - only identity stored,
  geometry re-read LIVE from the trigger header at guidance time (the
  Exits category's own source, so guidance can never disagree with the
  engine).
- Script exits from ff7_line_trigger_catalog.h (EXIT/EXIT_OK rows with
  real dests), same live-lookup-by-entity as the Triggers category.
- ⚠ DRY-RUN FINDING (offline BFS over the shipped headers, before
  deploy): the reactor's halves were DISCONNECTED at elevtr1 - the
  lift is a conditional multi-destination exit, which the v2.30.23
  catalog honestly records as dest=-1. Elevators are exactly the
  connectors journeys need ⇒ the line-catalog generator now ALSO emits
  **kCondExits** (158 edges): one edge per CANDIDATE destination of
  each multi-dest exit, with the engine's MAPJUMP 0x313->0x159 remap
  applied. Wrong-floor outcomes self-heal via the arrival recompute.
  Post-fix dry run: md1stin->nmkin_4 = 8 hops matching the play-test's
  ARRIVE sequence field-for-field, both directions; md1stin->mds7
  correctly NO PATH (train story transition, not walkable).
- World-map nodes excluded (journeys are field-only; future campaign).
- BFS is full-graph per query (788 nodes / 1521 edges - microseconds),
  hop counts spoken as "screens" (the player-meaningful unit).

**Honesty limits (documented, accepted v1)**: story locks are invisible
to the graph - a locked door routes normally and the leg keeps naming
that exit ("the next exit is not available here yet" when nothing
resolves live); conditional exits may deliver the player to the other
candidate (self-heals); places list only offers reachable-right-now
targets.

**Build checks**: journey literals verified in the DLL (narrow + wide);
deployed both installs hash D1D22E0F5639F726.

VERIFY (play-test checklist TODO [JOURNEY]): start a journey from the
reactor save room back to the station; wrong-turn self-heal; Shift+K
cancel; elevator leg wording; "not available yet" on a story door;
Places counts sane; no chatter regression on ordinary transitions.

### v2.30.66 (2026-08-02): journey play-fixes - elevator actuators, save-point places, ladder up/down

**Two same-day journey runs** (2013+7H; run 1 = pre-boss save back to
Sector 1, run 2 = new game toward the boss) proved v2.30.65 works
end-to-end - legs spoke at every arrival, wrong-turn recompute fired,
match=1 on all tracked jumps - and surfaced four fixes:

1. **Elevator stall (run 1's big finding)**: ARRIVE at elevtr1 then a
   2m40s gap - the journey pointed at the lift's exit LINE, but the
   line only fires after the SWITCH runs. Fix: conditional-exit edges
   (kCondExits) now carry kinds 3/4, and when such a leg lands on a
   field with a curated story hotspot, the leg targets the ACTUATOR:
   "elevator switch, press OK, toward Mako Reactor 1". kStoryHotspots
   hoisted to file scope for it (still played-evidence-only; one entry).
2. **Save room untargetable (run 2)**: fields 119-124 ALL carry caption
   "Mako Reactor 1" - dedupe collapsed the whole reactor to its nearest
   screen. Fix: NEW kSavePointFields in ff7_field_graph.h (60 ids,
   offline model-loader walk for the game-wide-unique 'saveicn' label;
   124 = the pre-boss save room confirmed in-table); save fields list
   as their own Places entries ("Mako Reactor 1, save point, 7
   screens") with the spoken base as the dedupe identity. Boss rooms
   stay unlistable (no engine signal) - the pre-boss save IS the
   destination that matters.
3. **Ladder pushes (user report)**: 8-sector wording spoke impossible
   directions on diagonal ladders (run-1 log: dir=6 "left", dir=3
   "down and right" - a ladder has exactly TWO control paths). Fix:
   collapse to the screen bearing's VERTICAL component (cos > 0 = push
   up, else down; near-horizontal falls back to climb-target height,
   sign proven by the nmkin_2 ladder pair's z values).
4. **NavDest name 64->96**: journey-wrapped leg names truncated LIVE in
   both logs ("Journey to Sector 1,Statio"). Dependent buffers widened.

**Story-direction groundwork (user request)**: ARRIVE lines now log
**ppv=** (STORY_PROGRESS 0xDC08DC - first consumer of that address).
A spoken "this way continues the story" Places marker needs a curated
PPV -> next-objective table; every played session now contributes the
mapping (PPV value at every screen change), so the table grows from
real play under the played-evidence rule (TODO [STORYNAV]). "Where
they've already been" needs no marker: Places is DEFINED as visited
places - said in the ReadMe wording instead.

Deployed both installs, hash-verified (F25491E59C85EEA2). VERIFY:
TODO [JOURNEY2].

### v2.30.67 (2026-08-02): ladders named "ladder 1/2/3" (user request)

"ladder up"/"ladder down" as NAMES collided with the push-direction
wording - "take ladder up, down 3 seconds" reads as two conflicting
instructions. All ladder dev-name stems (ladd/ladu/lad/ldu/ldd) now
translate to plain **"ladder"**; the Triggers category's existing
duplicate-ordinal rule numbers them ("ladder 1", "ladder 2") and
TriggerLineSpokenName (the journeys + proximity naming path) gained the
SAME ordinal computation over the live line array - one vocabulary, all
voices agree on which rung is which. Journey wording becomes "First
take ladder 1, down 3 seconds" + on mount "push up". DLL literal check:
"ladder up" ABSENT (wide scan). Deployed both installs
(EAE560BAF15CC595). VERIFY with [JOURNEY2]'s ladder item.

### Release v2.30.68 published 2026-08-02 (test build)

User decision: "ship something to the testers, fix things later."
Rolls up v2.30.60-.68 (ladders, level-ups, proximity announce, 2013
save-dir fix, transition tracking + arrival facing, JOURNEYS/Places,
and all three same-day play-fix rounds). Release id 363892810, tag
v2.30.68, zip digest sha256 e9ebbab030aea368139bc7d9663954824e45c5c2
fc44a806a46b4648c90cbaa3 = local hash (426,781 bytes),
/releases/latest confirms public. ReadMe per the template rule: TEST
BUILD notice leads "New in this version"; Known Issues gained the two
journey honesty limits (story locks invisible, no world map); Keys
gained the Places/journey usage lines and Shift+K's journey-cancel
role. Point testers at v2.30.68.

### v2.30.68 (2026-08-02): six third-run fixes

Third journey run (new game -> reactor, log 15:47-16:08) reported six
issues; all fixed, each from log evidence:

1. **"Facing down" after the train cutscene**: the arrival announce
   fires while the entry script still holds the UC lock and turns the
   player. Facing clause now DEFERRED under UC lock: spoken as a fresh
   "Facing X." (byte read at that instant) the moment the lock
   releases; new "FACING deferred release" log line.
2. **\ after a screen change routed to the wrong thing**: field change
   resets category/selection (v2.14), so mid-journey \ pointed at
   "All" slot 0. An ACTIVE journey now owns the directions key: \ in
   any non-Places category speaks the current leg ("Journey to X, N
   screens. Next, ..."); a Places selection retargets; Shift+K remains
   the way off.
3. **Elevator point wrong**: log showed the leg at (-140,40) speaking
   "up/left" while the player reports the button on the FAR RIGHT wall
   ("right 1 second" works). Hotspot play-corrected to (60,0) - curated
   evidence, not derivation.
4. **Second ladder said push up, correct was down**: nmkin_3's
   near-flat pipe ladder (z 864->849) descends toward +Y = screen-UP,
   so the v2.30.66 screen-vertical rule inverted. HEIGHT now decides
   (climb target lower = push down; |dz|<3 falls back to bearing) -
   the game's own semantic (its ladder tutorial says "move Up or
   Down"). LADDER log line carries dz.
5. **Save pad said "climb"**: field 124's save line classifies CLIMB in
   the catalog (its script chain reaches a LADER - pads on pipe
   platforms). Climb suffix suppressed when the name contains "save"
   (both suffix sites: browser + proximity).
6. **Wrong menu selections after a victory screen**: log 16:08:36
   "cursor=0 (Item)" then "cursor=10 (Quit)" 0.8s apart on ONE open -
   the menu module writes row 0 during init before restoring the
   remembered row. Open announce now waits for the byte to hold still
   2 consecutive polls (~100ms settle gate); navigation announces
   unchanged.

Deployed both installs (B46D107D07108C35). VERIFY: TODO [JOURNEY3].

---

## 9. Menu and Config TTS (v2.0â€“v2.3, 2026-07-01â€“02)

### Overview

Menu TTS does not use opcode hooks. The field script VM is frozen while any overlay is open, so
there are no MESSAGE or ASK opcodes to intercept. Instead, we use background polling threads that
read BSS addresses every 150ms and speak on changes. All threads share a manual-reset stop event
(`g_cursor_stop_event`) so a single `SetEvent()` in `Shutdown()` wakes them all cleanly.

### Address discovery methodology

For each menu feature, we wrote a Python investigation script using `ctypes.ReadProcessMemory` over
the full 0x00400000â€“0x00DE0000 BSS range:

- **Isolate scan** (title cursor, menu cursor, config row, config values): take two snapshot passes
  with the game in different states, subtract the idle-noise pass from the nav pass. Addresses that
  only changed during active navigation are candidates.
- **Symmetric toggle scan** (MENU_OPEN): three snapshots Aâ†’Bâ†’A (closedâ†’openâ†’closed). Candidates
  are addresses that changed Aâ†’B and reverted Bâ†’C.
- **Delta scan** (Sound sub-menu cursor, SOUND_CURSOR): take a baseline snapshot, guide the user
  through exactly N button presses via a beep countdown, take a second snapshot. Search for
  addresses where `(snap_b - snap_a) == Â±N` (signed byte delta). Designed to filter out the audio
  subsystem noise that contaminates the isolate scan when the Sound sub-menu is open. For the cursor
  (0=Music / 1=FX), N=Â±1 suffices; two full Down+Up rounds Ã— 2 intersected to one confident address.
- **Beep countdown** (timing-critical scans): `winsound.Beep(freq, ms)` is **synchronous** â€” it
  blocks until the tone finishes. This makes pre-snapshot timing deterministic unlike SAPI, which
  fires asynchronously and returns immediately. Pattern: three 800 Hz warning tones (200ms each, 1s
  period) then one 1400 Hz press tone (400ms); user presses ON the high beep; script waits SETTLE_S
  (1.5s) after the high beep before snapshotting. An `input()` prompt + 3s pre-countdown delay lets
  the user switch focus to FF7 before beeps start.

All scripts tee stdout to a timestamped log file automatically (Tee class wrapping sys.stdout).
All instructions are spoken aloud via a fire-and-forget PowerShell SAPI subprocess so the terminal
can stay in the background while FF7 is in focus.

### Confirmed addresses (2026-07-01â€“03)

| Address | Symbol | Discovery script |
|---------|--------|-----------------|
| `0x00DD6F24` | TITLE_CURSOR | ff7_title_poll.py + ff7_title_verify.py |
| `0x00DC1154` | MENU_CURSOR | ff7_menu_cursor_isolate.py + ff7_menu_cursor_verify.py |
| `0x00DC12DC` | MENU_OPEN | ff7_menu_open_scan.py |
| `0x00DC10F0` | CONFIG_ROW | ff7_config_menu_scan.py + ff7_config_menu_verify.py |
| `0x00DC0E10` | CONFIG_SPEED_BATTLE | ff7_config_values_scan.py + ff7_config_values_verify.py |
| `0x00DC0E11` | CONFIG_SPEED_MSG | same |
| `0x00DC0E12` | CONFIG_PACKED_CURSOR_ATB | same |
| `0x00DC0E13` | CONFIG_PACKED_CAMERA_MAGIC | same |
| `0x00DC0E24` | CONFIG_SPEED_FIELD_MSG | same |
| `0x00DC108C` | SOUND_CURSOR | ff7_sound_cursor_scan.py |
| `0x00DC0FA0` | QUIT_CURSOR | ff7_quit_dialog_scan.py |
| `0x00DD4538` | NAME_ENTRY_COL | ff7_name_entry_scan.py + ff7_name_entry_verify.py (2026-07-12) |
| `0x00DD453C` | NAME_ENTRY_ROW | same |
| `0x00DD45F0` | NAME_ENTRY_BUFFER | same (scan reported 0xDD45F5; verify's screen-handoff diff exposed the true base) |
| `0x00DD46F8` | NAME_ENTRY_CHAR_INDEX | same (disproved the Echo mod's "cursor column" label) |
| `0x00DD46FC` | NAME_ENTRY_ACTIVE | same |
| `0x00DD4574` | NAME_ENTRY_PANEL_INDEX | ff7_name_entry_panel_probe.py (buttons labeled by their effect on the name buffer, 2026-07-12) |
| `0x00921ED4` | NAME_ENTRY_PANE_FLAG | ff7_name_entry_pane_flag_scan.py (A/B/A revert) + ff7_name_entry_pane_verify.py (live, 2026-07-12) |
| `0x00DD46F0` | NAME_ENTRY_CARET | ff7_name_entry_panel_probe.py (tracked 5â†’8 during appends) |

### Packed byte encodings

**DC0E12** encodes two config rows in one byte:

| Bits | Field | Values |
|------|-------|--------|
| 7:6 | ATB | 00=Active, 01=Recommended, 10=Wait |
| 4 | Cursor | 0=Initial, 1=Memory |
| 3:0 | Constant 0x5 | (other packed fields, not yet decoded) |

Extraction: `cursor = (val >> 4) & 1`, `atb = (val >> 6) & 3`

**DC0E13** encodes two config rows in one byte:

| Bits | Field | Values |
|------|-------|--------|
| 4:2 | Magic order | 0=No.1, 1=No.2, 2=No.3, 3=No.4, 4=No.5, 5=No.6 |
| 0 | Camera angle | 0=Auto, 1=Fixed |
| 7:5, 3, 1 | Constant 0 | (unused at these rows) |

Extraction: `camera = val & 1`, `magic_order = (val >> 2) & 7`

**Magic order has 6 presets, not 4.** The config screen shows the selected preset's internal
ordering (restore / attack / indirect) rather than a list of presets. Values cycle through
0,4,8,12,16,20 (step=4, stored in bits 4:2) confirming 6 distinct choices (No.1â€“No.6).

### Sound sub-menu investigation (2026-07-03)

**Isolate scan failure**: Opening the Sound sub-menu activates the audio subsystem (FFNx/SoLoud
sample streaming), flooding the BSS region with constantly-changing timer and buffer bytes. The
idle-phase baseline is immediately contaminated, producing ~47 false candidates for Music volume.
Ruled out the isolate scan approach entirely for this sub-menu.

**Volume address scan via FFNx DLL range**: FFNx's `dotemuRegSetValueExA` (not a real Windows
registry call â€” FF7 routes all `RegSetValueExA` calls through this FFNx function) stores
`external_music_volume` and `external_sfx_volume` as global `long` variables deep in AF3DN.P's
address space (~27MB into the DLL). To find them, `ff7_sound_submenu_scan.py` was extended with
`CreateToolhelp32Snapshot`/`MODULEENTRY32` to enumerate AF3DN.P's actual load range and scan it
alongside BSS. Found one Music candidate at +0x1DA2A68 from AF3DN.P base (Before=0, After=236).

**Audio ring buffer false positive** (`ff7_sound_verify.py`): A live monitor polling Â±32 bytes
around the scan candidate at 200ms intervals revealed that the entire region is SoLoud's audio
engine streaming ring buffer. Every byte churns with random values every 200ms regardless of any
user input. The Before=0/After=236 result was a coincidence â€” the byte happened to be 0 at
snapshot-A time and 236 at snapshot-B time while the ring buffer was operating. Confirmed false
positive; the delta scan cannot find volume addresses because the audio engine fully saturates
the surrounding region.

**IAT hook attempt**: FF7 statically links `dotemuRegSetValueExA` from AF3DN.P. If the Import
Address Table (IAT) of `ff7_en.exe` contains this function, patching the IAT entry would redirect
all calls through our handler without touching AF3DN.P. `SetupSoundIATHook()` was implemented:
it walks `ff7_en.exe`'s `IMAGE_IMPORT_DESCRIPTOR` table, finds the AF3DN.P section, walks
`OriginalFirstThunk`/`FirstThunk` pairs matching `dotemuRegSetValueExA` by name, and patches
`FirstThunk` with `VirtualProtect`. The hook installed without error ("patched" logged), but
Left/Right presses produced no TTS. Most likely cause: FF7 calls `GetProcAddress` at runtime
for this import rather than using the static IAT entry, so our patch is bypassed. TODO for v2.5.

**Sound sub-menu cursor** (`ff7_sound_cursor_scan.py`): Delta scan for the cursor position byte
(0=Music highlighted / 1=FX highlighted). Two full Down+Up rounds (4 total transitions): sole
confident candidate = `0x00DC108C`, 0x5C bytes before `CONFIG_ROW` (0x00DC10F0) in the same
DC10xx structure. First attempt with SAPI countdown failed â€” "press now" finished too late for
the post-press settle window to capture valid data (Up-pass found zero results both rounds). Fixed
by replacing SAPI with `winsound.Beep()` (synchronous), adding `input()` prompt + 3s delay.

### False candidates and rejected approaches

**QUIT_OPEN (0x00DC0FB1)**: Confirmed 0â†’1 when the Quit dialog opens, but does NOT return to 0
when dismissed with No. Gating MenuCursorThread's quit-dialog handler on this flag caused it to
loop in the handler indefinitely, silencing the main menu. Not used; QUIT_CURSOR is polled without
a gate instead.

**0x009A8729**: Top candidate for Battle message speed in the isolate scan (count=highest, last=0).
Identified as a button-transient address â€” changes when any directional button is held, regardless
of which row is active. The real address (DC0E11, rank 5 in the scan) was confirmed by the verify
script showing DC0E11 changing exclusively during row 6.

**0x6B852A68 (+0x1DA2A68 in AF3DN.P)**: Top candidate from the FFNx-range delta scan for Music
volume. Appeared to change from 0 to 236 during the scan window. Confirmed false positive by
`ff7_sound_verify.py`: the entire Â±32-byte region is SoLoud's audio engine streaming ring buffer;
all bytes churn with random values every 200ms independent of any Music slider input.

### Bug: stale MENU_OPEN at game start (v2.2 fix)

The title screen uses the same overlay flag (MENU_OPEN=1) as the main menu. On the first field
load after the title screen, that stale MENU_OPEN=1 persisted for exactly one poll cycle before
clearing. This caused MenuCursorThread to fire its "re-announce on menu open" path, speaking "Item"
(the BSS default of MENU_CURSOR=0) before the player had opened any menu.

Fix: require `menu_open_streak >= 2` (two consecutive polls of MENU_OPEN=1) before trusting it.
The stale title-screen value clears after one poll and never reaches streak=2.

### Bug: false config row announce during main-menu navigation (v2.2 fix)

Initializing `last_row = 0xFF` in ConfigMenuThread caused a false announce when the player scrolled
quickly through the main menu and MENU_CURSOR briefly passed through 7 (the Config row). The
MENU_CURSOR==7 gate fired, but CONFIG_ROW still held its retained value from the last config session
(e.g., 0=Window color). Since `last_row` was 0xFF and CONFIG_ROW was 0, `curr != last_row` was
true, and "Window color" was announced.

Fix: initialize `last_row = 0` (matching the BSS default of CONFIG_ROW). Because `last_row` is
never reset to 0xFF, it stays in sync with the retained CONFIG_ROW value throughout main-menu
navigation. False announces are impossible.

### Threading model

Three persistent polling threads after v2.4:

| Thread | Polls | Period | Stop signal |
|--------|-------|--------|------------|
| TitleCursorThread | TITLE_CURSOR | 150ms | g_cursor_stop_event |
| MenuCursorThread | MENU_CURSOR, QUIT_CURSOR | 150ms | g_cursor_stop_event |
| ConfigMenuThread | CONFIG_ROW + 5 value addrs + SOUND_CURSOR | 150ms | g_cursor_stop_event |

ConfigMenuThread handles SOUND_CURSOR as a separate polling block inside the same loop: when
CONFIG_ROW==1 (Sound sub-menu open), it checks SOUND_CURSOR every iteration. The
`last_sound_cursor` sentinel (initialized to 0xFF) suppresses the first-observation announce
so re-entering the Sound row does not repeat the last slider name. Resets to 0xFF whenever
CONFIG_ROW != 1.

---

## 10. Current Status

### Working (as of v2.4)

- All field story dialog (MESSAGE opcode 0x40) spoken via NVDA on dialog start and page advance
- All field choice menus (ASK opcode 0x48) spoken with "Choose: " prefix
- Speaker identification (Cloud, Barret, Tifa, etc.) from token at dialog position 0
- Win=0 and win=1: state machine primary path (earlier, cleaner detection)
- Win=2 and win=3: DLGID fallback path (two-frame delay, reliable in practice)
- Voice acting (FFNx) and TTS coexist â€” hook chain passes through both
- Config file: `speak_dialog`, `speak_choices`, `interrupt`, `speak_menus` toggles
- No duplicate speaks; no garbage TTS blocks
- ASCII filter: printable ASCII only; word boundaries preserved
- Title screen cursor TTS: "New Game" / "Continue" on each Up/Down press
- Main menu cursor TTS: option name (Item/Magic/Equip/â€¦/Quit) on each Up/Down press
- Quit confirmation cursor TTS: "Yes" / "No"
- Config sub-menu row TTS: row name on Up/Down + current value on row entry and Left/Right changes
  - Toggle rows (Cursor, ATB, Camera, Magic order): option name spoken
  - Slider rows (Battle speed, Battle message, Field message): numeric value spoken
  - Rows 0/1/2 (Window color, Sound, Controller): row name only (value addresses not yet found)
- Sound sub-menu cursor TTS: "Music volume" or "FX volume" on Up/Down within the Sound sub-menu
  (Config row 1 â†’ Confirm). Announces slider name on each cursor change; if the cached volume is
  known it is appended (e.g., "Music volume, 100"). Numeric value from Left/Right not yet functional.
- Battle action TTS with exact names (v2.7): "Cloud, Ice" / "Cloud, Potion" / "enemy, Machine Gun" â€”
  the flash-message text â€” for Magic/Summon/Item/E.Skill/Limit/enemy attacks; generic labels
  ("Attack", "Steal") for commands with no flash text, and as fallback on any resolution failure.
  Wall-bump navigation tone (v2.6) on dead-stop wall contact during field play.

### Known Issues / Limitations

| Issue | Severity | Fix |
|-------|----------|-----|
| Apostrophe â†’ space ("I'm" â†’ "I m") | Moderate | Needs proper byteâ†’char lookup table |
| Other extended chars garbled (curly quotes, em-dash, etc.) | Moderate | Same lookup table |
| Speaker detection broken when 3-byte window header precedes speaker token | Minor | Detect/skip 0xD0â€“0xDF at position 0 |
| Dynamic token placeholders spoken literally ("[item name]") | Minor | Resolve tokens from script banks |
| "X <" artifact occasionally in ASK output | Minor | ASK formatting codes not yet filtered |
| Sound sub-menu volume value (Left/Right) not announced | Moderate | IAT hook on dotemuRegSetValueExA not functional â€” likely GetProcAddress at runtime; TODO v2.5 |
| Config menu entry does not re-announce row if last session ended on row 0 | Minor | Need CONFIG_OPEN flag or entry detection |

### Not Yet Implemented

| Feature | Hook Point / Approach |
|---------|----------------------|
| Sound sub-menu volume value TTS (Left/Right) | IAT hook on `dotemuRegSetValueExA` implemented but non-functional (v2.4). Alt: hook `GetProcAddress` call for this fn, or find `external_music_volume`/`external_sfx_volume` in a stable AF3DN.P data section |
| ASK per-option TTS as cursor moves | `opcode_ask + 0x8E` â†’ inner loop; needs FF7 original opcode_ask address |
| Item/Magic/Equip/Status/Order/Limit sub-menu cursors | Isolate scan within each sub-menu |
| ~~Main menu unlockable slots 6 and 8~~ | **RESOLVED v2.31.1 (2026-07-18, player row-by-row report)**: the 2026-07-01 label table had omitted Materia (index 2), shifting Equip..Limit one row early; slot 6 = Limit, slot 8 = PHS. Full order: Item, Magic, Materia, Equip, Status, Order, Limit, Config, PHS, Save, Quit |
| Battle turn announcement | `battle_set_do_render_menu_call` â€” but BATTLE_MENU_STATE 0â†’1 transition + ACTIVE_SLOT (2026-07-12) is likely the cleaner poll-based signal |
| ~~Battle menu cursor TTS~~ | **DONE v2.9 (2026-07-12)** â€” BattleMenuThread; see Â§8 v2.9 entry. Remaining battle-menu polish: ~~real enemy names in target announcements~~ (DONE v2.10), ~~Sense HP readout during targeting~~ (DONE v2.11), ~~enemy defeat announcements~~ (DONE v2.12, 2026-07-13), ~~same-tick action-announce clobber~~ (DONE v2.13, chained announces), limit/E.Skill/W-command list widgets (states 0x14/0x18/0x1A/0x1B, 26/27), list-entry disabled-flag announce (u8[entry+4] bits), party-KO announcements (in TODO.txt with implementation notes â€” awaiting a fuller party to test) |
| World map dialog | `world_opcode_message_sub_75EE86`, `world_opcode_ask_sub_75EEBB` |
| Name entry screen cursor | Isolate scan while moving grid cursor |
| Field navigation spatial audio | Entity position list + audio panning |

---

## 11. Remaining RE Work

| Symbol | Needed For | How to Find |
|--------|-----------|------------|
| FF7 original `opcode_ask` address | ASK per-option cursor hook at +0x8E | Disassembly; scan for CALL 0x6310A1 within known function range |
| Per-menu cursor index offsets | Main menu, item, magic, equip, status, PHS, shop | Cheat Engine scan within `menu_objects` (0xDC0FC0) region |
| Name entry grid cursor X/Y | Name entry screen | Cheat Engine: value changes as keyboard grid cursor moves |
| ATB gauge offset in `battle_context` | "Whose turn" announcement timing | Within `battle_context->actor_vars`; ~2 bytes per actor |
| `battle_set_do_render_menu_call` address | Battle menu entry hook | Relative call chain from battle init |
| `update_display_text_queue` / `add_text_to_display_queue` addresses | Battle MESSAGE text TTS ("Cloud gained a level", enemy dialogue) â€” distinct from the v2.7 action-name flash | FFNx chains: `add_text_to_display_queue = get_relative_call(battle_sub_42CBF9, 0x1C7)`; queue array = `get_absolute_value(add_text, 0x25)`, 64Ã—6-byte entries {s16 buffer_idx, s16, u8 wait, u8 frames}; text = kernel2 battle-text section entry buffer_idx (accessors 0x419442 / 0x41D2E5 for idxâ‰¥256) |
| FF7 byte 0x5Fâ€“0xDF â†’ correct Unicode | Extended character lookup table | FF7 font texture / Makou Reactor character table |

---

## 12. FF7 Text Encoding â€” Byte Lookup Table (Partial)

Confirmed mappings based on in-game observation:

| Byte | FF7 Renders | Current Output (byte+0x20) | Correct Unicode |
|------|------------|---------------------------|-----------------|
| 0x00 | (space)    | U+0020 space âœ“            | U+0020          |
| 0x21 | A          | U+0041 A âœ“                | U+0041          |
| 0x27 | G          | U+0047 G âœ“                | U+0047          |
| 0x3F | ?          | U+005F _ (wrong: prints as space in ASCII filter) | U+003F ? |
| 0x80 | Ã  / special| U+00A0 nbsp (stripped)    | TBD             |
| 0x82 | - (hyphen) | U+00A2 Â¢ (stripped)       | U+002D          |
| 0xB2 | " (left)   | U+00D2 Ã’ (stripped)       | U+201C          |
| 0xB3 | " (right)  | U+00D3 Ã“ (stripped)       | U+201D          |
| 0xB5 | ' (apos)   | U+00D5 Ã• (stripped)       | U+0027          |
| 0xB4 | ' (left)   | U+00D4 Ã” (stripped)       | U+2018          |

The full table (0x5Fâ€“0xDF) needs to be derived from the FF7 PC US font texture or sourced from
Makou Reactor's character encoding documentation.

---

## 13. Source Reference

- **`FFNx/src/voice.cpp`** â€” complete dialog + battle hook template; our hooks are a TTS-only subset
- **`FFNx/src/externals_102_us.h`** â€” all hardcoded absolute addresses for 2013 Steam exe
- **`FFNx/src/ff7_data.h`** â€” dynamic address discovery chains (authoritative reference)
- **`FFNx/src/ff7.h`** â€” game data structure declarations with commented addresses
- **`FFNx/src/field/opcode.h`** â€” full FieldOpcode enum (246 opcodes)
- **`FFNx/src/field.h`** â€” `get_field_parameter` implementation (opcode parameter reading)
- [Makou Reactor](https://github.com/myst6re/makoureactor) â€” field editor; source reference for field file format
- [FF7 Field Script Opcodes](https://wiki.ffrtt.ru/index.php/FF7/Field/Script/Opcodes) â€” opcode reference
- [FF7 Savemap](https://wiki.ffrtt.ru/index.php/FF7/Savemap) â€” save file layout (live addresses derived from base 0xDBFD38)
- [Tolk](https://github.com/ndarilek/tolk) â€” screen reader abstraction library

---

## 14. Memory Region Map â€” Running Analysis

Every address this project has confirmed, organized spatially instead of by feature.
The clustering is itself a discovery tool: FF7 statically allocates each engine
module's globals in a contiguous block, so **a new unknown for module X is almost
certainly within a few KB of module X's known addresses** â€” start every new scan
there before falling back to full-memory delta scans. This section should be
extended every time a new address is confirmed.

Proven payoffs of cluster reasoning so far:
- `FIELD_PLAYER_MODEL_ID` (0xCC162C) landed 0x5C bytes after `FIELD_ID` (0xCC15D0).
- `SOUND_CURSOR`, `CONFIG_ROW`, `MENU_CURSOR` were all found within 0xD0 bytes of
  each other after the first menu address anchored the region.
- The `modules_global_object` struct at 0xCC0D88 matches the PSX decomp's struct
  field-for-field (+0x28..+0x3B verified), so PSX decomp comments name PC bytes
  that FFNx leaves as `field_XX` â€” this is how the UC control lock was found
  without any scanning.

### Code (.text): 0x401000 â€“ 0x9FFFFF

| Address | Symbol | Notes |
|---------|--------|-------|
| `0x40B27B` | sub_40B27B | anchor for movie-playing word (+0x25) |
| `0x41963C` | sub_41963C = **get_kernel_text** (FFNx external, confirmed via kernel2_get_text call at +0xF7) | `(section, idx, 8)`; result â†’ 0xDC208C; reads menu scratch 0x9A13C8 â€” EMPTY in battle |
| `0x419457` | kernel2_get_text | `base = 0x9A13C8 + u16[0x9A7FC8 + file*2]; text = base + u16[base+idx*2]` |
| `0x6D1CC0` | flash-name dispatcher | branch tables 0x6D7080 (jump) / 0x6D70A8 (byte, per cmd 0x00â€“0x20); per-branch sections in Â§4 |
| `0x6D70F1` | enemy-attack name copier | branch 4 (cmd 0x07) â†’ buffer 0xDC3640 |
| `0x7B7488/8A/98` | item-namespace remap tables | idx<128â†’items, <256â†’weapons(âˆ’128), <288â†’armor, <384â†’accessory |
| `0x7B74A0` / `0x7B74A8` | section bias / sectionâ†’file tables | biases {0,56,72,128} map sections 0â€“3 into ONE magic-names file: 0â€“55 spells, 56â€“71 summons, 72â€“95 E.Skills, 128+ limits |
| `0x42782A` | display_battle_action_text | FFNx trampolines this â€” do not hook |
| `0x60BACF` | field_init_event | PRIMARY ANCHOR: +0x80â†’execute_opcode, +0x20â†’modules_global_object, +0x1Câ†’field_global_object_ptr |
| `0x60C683` | execute_opcode | +0x10D â†’ opcode table |
| `0x614E3E` | opcode_canm1_canm2 (table[0xB1]) | +0xC1 â†’ field_event_data_ptr |
| `0x630D50` | opcode MESSAGE update loop | +0x12 â†’ dialog state array |
| `0x6310A1` | opcode ASK update loop | v2 hook target |
| `0x6342C6` | field_update_models_positions | +0x45Dâ†’player_model_id, +0x25â†’n_models |
| `0x63C17F` | field_loop | +0x5DD â†’ field_update_models_positions |
| `0x6D71FA` | kernel2 request writer | stores section/idx to 0xDC38E8; returns void; FFNx-trampolined |
| `0x6CE8B3` | battle_menu_update (FFNx name) | per-frame battle menu tick; +0xD9 CALL â†’ 0x6DB0EE (FFNx trampolines THIS call site â€” hook wary) |
| `0x6DB0EE` | battle menu state dispatcher | +0x1B4 â†’ fn table 0x91E6B8; +0x276 â†’ battle_actor_data 0xDC38E0; +0x1F9 CALL â†’ 0x6E6291; +0x50E CALL â†’ dispatch_chosen_battle_action 0x6D86D2 |
| `0x6D8C75` / `0x6D91FA` | state 0 (actor ready) / state 1 (command menu) handlers | state 1 is where the command cursor logic lives; Confirm jump table at 0x6D97F7 |
| `0x6D98E3` / `0x6D9B98` / `0x6DA072` | state 5/6/7 list handlers | magic-shaped/per-actor lists; widget ptr = 0xDC20D8/0xDC2110/0xDC2148 + slotÂ·0x700 |
| `0x6F4DB2` | shared widget navigation helper | takes widget ptr arg; ALL cursor inc/dec/wrap/scroll logic â€” cursor ops are [reg+disp], invisible to absolute-operand scans |
| `0x6E5C52` | set_battle_targeting_data (FFNx) | +0x14E/+0x164 â†’ target type/index globals |
| `0x6E6291` | battle_update_targeting_info (FFNx) | +0x684 â†’ targeting_actor_id 0xDC3C98 |
| `0x6D72E9` / `0x6D1CC0` | kernel2 request consumer / dispatcher | real CALL to 0x41963C at 0x6D72C6 |
| `0x6E97E0` | build_dialog_window | |
| `0x6111D8` / `0x6115AD` / `0x6114D0` | opcode LINE / LINON / SLINE handlers (table[0xD0]/[0xD1]/[0xD3]) | all three write FIELD_LINE_ARRAY 0xCC1F70 â€” the triple agreement that validated the v2.17 line-array layout; LINE also writes the entityâ†’slot map 0xCBF600 and count 0xCC088C (ff7_line_triggers_static.py, 2026-07-14) |
| `0x618E33` | opcode MPNAM handler (table[0x43]) | reads the 1-byte text id from the script, calls the storage callee (ff7_mpnam_static.py, 2026-07-16) |
| `0x633691` | MPNAM storage callee | decodes field text entry (via FIELD_TEXT_BLOCK_PTR 0xCC08E8) into LOCATION_NAME_BUFFER 0xDC0C44, â‰¤0x17 bytes; token jump table 0x6338CF handles 0xE2-family expansions; char-name tokens (0xEA+) resolved via CALL 0x6CB9B8 |
| `0x6CB9B8` | character-name-for-token resolver | returns a pointer to the FF7-encoded live name for dialog char tokens; shared by the MPNAM path (2026-07-16) â€” candidate anchor if a token ever needs resolving outside dialogs |
| `0x618A80` | opcode TLKON handler (table[0x7E]) | resolves the executing entity's model via the entityâ†’model map 0xCBFB70 (0xFF = no model) and writes its 1-byte arg raw to field_event_data +0x61 â€” the talk-disabled byte (scratch disasm + live confirm 2026-07-16, v2.26) |
| `0x618253` / `0x6182DF` | opcode talkR (0xC5) / tlkR2 (0xD6) handlers | both scale their radius arg by the field scale word ([0xCBF9D8]+0x10): value = arg Ã— scale >> 9, written to field_event_data +0x74 (talk radius). Found by the v2.30.26 talk-range hunt (ff7_talk_range_static.py) |
| `0x60C3A8`-region | field model init | sets the scale-based DEFAULTS: +0x72 collision = 30Â·scale>>9, +0x74 talk = 80Â·scale>>9 (e.g. scale 448 â†’ col 26, talk 70 â€” why most talk radii read 70). Same v2.30.26 hunt. âš  the talk-check READER of +0x74 was NOT found in three scan passes (word loads game-wide, +0x61 consumers) â€” the chirp/reach formula is behaviorally derived instead (see Â§8 v2.30.26) |
| `0x61E29F` | opcode IDLCK handler (table[0x6D]) | args u16 triangle_id + u8 flag; sets/clears bit (tri&7) of byte [0xCBF9D8]+0xB2+(tri>>3) â€” the triangle-lock bitfield (= static 0xCC0E3A). ff7_idlck_static.py 2026-07-23, v2.30.21 |
| `0x6369E8` / `0x636AAF` / `0x636B76` | movement edge-crossing lock tests | one branch per triangle edge: neighbor id from the parsed access pool [0xCFF748] (stride 3Ã—u16), then the >>3/&7 bit test against 0xCC0E3A â€” crossing REFUSED when set. Also writes u16 0xCC1630 (new current triangle?, unconfirmed) (ff7_idlck_bitmath.py 2026-07-23) |
| `0x615EC6` | opcode LADER handler (table[0xC2]) | disasm bonus (v2.17 log): confirms field_event_data +0x63 movement_type, +0x7C/80/84 target pos <<12, and reads anim-data ptr 0xCFF738 with stride 0x190. **Fully read v2.30.60** (ff7_ladder_static.py): script byte arg selects 4 cases via jump table 0x6163D0 → writes movement type **4** (0x61603E/0x616085) or **5** (0x6160CC/0x616110) with orientation +0x6E 0/1; re-entry test `>=4 && <=5` at 0x615F33 = "already climbing"; arrival clears +0x63 (0x615F9E) and +0x70; targets stored at 0x616187/0x6161B7 from args via 0x60FD6C, shifted <<12. This is the mod's on/off-ladder signal and push-direction source |
| `0x618A01` | opcode VISI handler (table[0xA4]) | entity from 0xCC0964 â†’ model via 0xCBFB70 (0xFF-guarded) â†’ imul 0x88 â†’ base [0xCC0B60] â†’ **writes operand to +0x62 (0x618A54) = the model VISIBILITY byte**; PC advance +2 via 0xCC0CF8 (ff7_visi_handler_disasm.py 2026-07-31, v2.30.45 â€” the picked-up-items-stay-listed hunt) |
| `0x6143A5`-region | CHAR (0xA1) bind path | same addressing chain; **stores 1 to +0x62 at 0x6143D2** (bound models start VISIBLE â€” what makes ==0 a safe hidden test), entity id to +0x5D at 0x6143F9 (independent re-proof of FIELD_EVENT_ENTITY_ID), opcode operand word to +0x6C (ff7_char_handler_disasm.py 2026-07-31) |
| `0x6388EE` | field_sub_6388EE | v2.14 chain anchor (FFNx name embeds address); grc(+0x11) â†’ field_draw_everything 0x63A60B |
| `0x63A60B` / `0x640F22` / `0x640F95` | field_draw_everything / field_pick_tiles_make_vertices / field_layer3_pick_tiles | v2.14 chain to FIELD_TRIGGERS_HEADER_PTR (gav(0x640F95, 0x134) = 0xCFF454); 3 name-embedded cross-checks passed |
| `0x6CDA83` | menu-TYPE dispatcher | switch on GAME_MODE byte 0xCC0D89 â€” jump table decoded offline (index bytes 0x6CDBE4, targets 0x6CDBC4): 6=name entry, 7=PHS, 8=SHOP, 9=main menu, 14/18/19=further screens; both live-confirmed values (6, 9) match the decode (ff7_shop_static.py, v2.30.28) |
| `0x71AAA3` | shop loop (FFNx menu_shop_loop) | switch on SHOP_STATE 0x92565C via jump table 0x71E193; shop init 0x719D7A fills SHOP_ID/NAME_IDX/TEXT_IDX from the catalog; generic list-widget ctor 0x6F4D30 (+0 col/+4 row/+0x14 scroll) builds every shop cursor; get_materia_gil 0x71FCF9 = the sell-price function (mastered â†’ baseÂ·70) (v2.30.28) |
| `0x6CB620` | menu start_tutorial | sets TUTORIAL_RUNNING 0xDBFD30; tutorial VM opcode jump table 0x7185C7 (0x02-0x0D = key INJECTION); menu input refresh 0x7186C8 â†’ 0x71826E overwrites the pressed/held digests 0x9A85E0/0x9A85D4 with VM output while a tutorial runs â€” real input never reaches menu nav (ff7_tutorial_static.py, v2.30.29) |
| `0x70CF0B` | materia menu sub (menu_subs_call_table[3]) | mode jump table 0x70E246 (12 cases on MATMENU_MODE 0x920FA0); equip-list commit 0x70DC80..0x70DD0C = the materia[200] index formula row+scroll (v2.30.33) |
| `0x705D16` | equip menu sub (table[4] = FFNx menu_sub_705D16; table[15] dupes it) | category Â±1-wrap at 0x707079/0x7070C0 (what settled 0xDCA4A4 as a cursor); candidate-list builder 0x708640; OK-commit reads u8[0xDCA6A8][row+scroll] at 0x707350..0x70735E (v2.30.34) |
| `0x70212A` | limit menu sub (table[7]) | draw switch 0x70313A on LIMITMENU_MODE 0x9204D8; resolves char via SAVEMAP_PARTY_IDS + the idâ†’record table 0x919928 (0x70216A..0x702186); learned-mask bit test (imul 3/shl) at 0x702190 (v2.30.35) |
| `0x710DFA` | MAGIC menu sub (table[2]) | slotÂ·0x440+0xDBA5A0 spell-list resolve at 0x710F89 (= BATTLE_CHAR_BLOCK+0x108 â€” battle's list, stride 8 re-confirmed); 3-col index math + draw loop 0x711726..0x7117FB; usable classifier = u8[0x714440]â†’jump 0x714430 (color 7 white / 0 gray); kernel text via the 0x41963C getter; widget 0xDD1708, window struct 0xDD1690; pane cmp sites 0x710E0E/0x710FBA on 0x921100 (ff7_magic_menu_static.py, v2.30.48) |
| `0x75EE86` / `0x75EEBB` | world MESSAGE / ASK | world module is adjacent code (0x75xxxx) |
| `0x6131C4` | opcode MAPJUMP handler (table[0x60]) | two-phase: first entry arms FIELD_JUMP_INTERFACE (Â§4) + GAME_MODE=1, later entries wait for phase 0xCC0DAE==2 then advance the script PC by 10. Field id 0x313 remapped to 0x159 in-handler (ff7_screen_construction_static.py 2026-08-02) |
| `0x618062` | opcode DIR handler (table[0xB3]) | writes facing +0x38 / step-idx +0x3A / steps-type +0x3B via the standard entity->model chain; GETDIR reads +0x38 at 0x6184F1; arg fetch = bank helper 0x60F750 (2026-08-02) |
| `0x636233` | ArmGatewayJump(record*) | the gateway-crossing HIT path: GAME_MODE=1 then record +0x12/+0x0C/+0x0E/+0x10/+0x14 -> DEST field/X/Y/triangle/DIRECTION. Caller = crossing test in the movement module (0x636284.. reads player pos >>12) (ff7_gateway_hit_disasm.py 2026-08-02) |
| `0x63BF60`..`0x63C17E` | field ARRIVAL/init routine (ends right before field_loop 0x63C17F) | copies modules+0x2A -> PLAYER_MODEL_ID (0x63C073), applies DEST_DIRECTION -> player event_data +0x38 (0x63C094), reads hdr control fields, inits walkmesh ptrs 0xCFF434/0xCFF744/0xCFF748 (0x63C116..42), hands hdr+0x158 (door triggers[12]) to 0x638420 (0x63C0EC), clears FIELD_LINE_ARRAY via 0x637E88 (0x63C156), then **phase 0xCC0DAE=2** (0x63C148) = construction complete (2026-08-02) |
| `0x63CCBA` | save-load field entry | rep-movsd 0x43D dwords staging->savemap 0xDBFD38, then savemap continue block 0xDC08CE..DA -> FIELD_JUMP_INTERFACE (same arrival path as MAPJUMP) (2026-08-02) |
| `0x6211DA` / `0x6307E5` | the SINGLE writers of FIELD_TRIGGERS_HEADER_PTR / FIELD_FILE_BUFFER | one construction path each - the static proof that exactly ONE field is in memory at a time; parse helper writing gateway records (stride 0x18) at 0x623487.. (2026-08-02) |
| `0x64DAC8`.. | gateway ARROW renderer | reads show_arrow_flag hdr+0x218 and arrows[12] hdr+0x224/+0x228/+0x22C/+0x230 (x/y/z/type) - confirms the FFNx header-tail layout (2026-08-02) |
| `0x76713B` | world-map -> field exit | writes DEST field/triangle/direction (0x76713B/0x767163/0x767172) - the world module uses the same FIELD_JUMP_INTERFACE (2026-08-02) |
| `0x61A4D4` | opcode MPJPO handler (table[0xD2]) | one-arg store to [MODULES_PTR]+0x36 (0x61A4F7) = static 0xCC0DBE MAPJUMP_DISABLED, PC += 2 - the gateway on/off switch scripts flip during scenes (ff7_mpjpo_static.py 2026-08-02, v2.30.64) |

Pattern: field module code sits in 0x60xxxxâ€“0x6Exxxx, world map in
0x74xxxxâ€“0x76xxxx (world_loop 0x74BE49, world_update_player 0x74EA48,
MESSAGE/ASK 0x75EExx, field-exit writer 0x76713B, battle toggle
0x767674), battle UI text in 0x42xxxx, shared low-level services in
0x40â€“0x41xxxx.

### World-map statics cluster: 0xE0xxxx â€“ 0xE3xxxx (FFNx-sourced leads)

Recorded 2026-08-02 for the future world-nav campaign â€” addresses from
FFNx's name-embedded externals + resolution chains (ff7_data.h), NOT
our own derivation; verify live before consuming:

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xE045E8` | world_map_type | int (FFNx world_map_type_E045E8) |
| `0xE04918` | world_player_pos | vector4<int> (FFNx world_player_pos_E04918; via gav(world_sub_75042B, 0xE)) |
| `0xE39AD8` | world_event_current_entity_ptr | -> world_event_data (ff7.h:2333: position vec4, facing s16, walkmap_type u16 under entity, direction s16, model_id u8, script position) |
| â€” | walkmap type/region getters | grc(world_update_player 0x74EA48, 0x7DF) / grc(world_sub_767641, 0x2B) â€” terrain type under the player (the world-map walkability signal) |

Our one confirmed world find (static disasm 2026-08-02): the world
module's field-exit path writes the SAME FIELD_JUMP_INTERFACE the field
module uses (0x76713B/163/172 -> DEST field/triangle/direction).

### Static data (.data): 0x900000 â€“ 0x9Fxxxx

| Address | Symbol | Notes |
|---------|--------|-------|
| `0x9055A0` | execute_opcode_table | uint32[256] |
| `0x91E6B8` | BATTLE_MENU_FN_TABLE | uint32[64] battle menu state handlers (2026-07-12) |
| `0x91EF98` / `0x91EF9C` | BATTLE_MENU_PREV_STATE / BATTLE_MENU_STATE | u16 pair â€” the battle "current widget" selector; same .data neighborhood as NAME_ENTRY_PANE_FLAG 0x921ED4 (menu-module state cluster) |
| `0x9AC354` | BATTLE_ITEM_LIST_TABLE | global 6-byte entries for the state-5 (magic-shaped) battle list |
| `0x921ED4` | NAME_ENTRY_PANE_FLAG | 0=grid, 1=side panel on the naming screen (v2.8.2). Sole clean candidate of a full-static A/B/A revert scan; live-verified across 6 crossings. Far from the DD name-entry block â€” menu-module .data |
| `0x9A8729`, `0x9A872A`, `0x9ADE30`, `0x9ADE34` | input-event/SFX pulse flags | pulse-and-reset on any d-pad press; REJECTED as cursor candidates |
| `0x9A8731` | grid/panel covariant | 44 on grid, 49 on panel, reverted (pane-flag scan 2026-07-12); secondary candidate, likely cursor-SFX/sprite id â€” unused, PANE_FLAG is cleaner |
| `0x9A13C8` / `0x9A7FC8` | kernel2 text scratch + u16 offset table | menu-module staging; **ALL ZERO during battle** (probed live 2026-07-11) â€” battle code never populates it |
| `0x9A9484` | ENEMY_ATTACK_NAME_TABLE | CONFIRMED (was "section-8 table?"): current formation's attack names from scene.bin, stride 0x20; = get_kernel_text section 9 (`ret 0x9A9484 + idx*0x20`) |
| `0x9A80F0` | target-name scratch buffer | get_kernel_text section 7 composes "name + dup letter (+ status/Sense text)" here on render; write-on-render only, do NOT poll (2026-07-13) |
| `0x9A8794` | BATTLE_FORMATION_SLOTS | stride 0x10 Ã— 6 enemy slots (ends 0x9A87F4); u16[+0] = loaded-record index, movsx (âˆ’1 = empty). Note 0x9A8729/2A pulse flags above sit INSIDE the region just before it â€” this 0x9A87xx area is the battle formation block (2026-07-13, v2.10) |
| `0x9A8B1F` | BATTLE_DUP_LETTER_TABLE | per-actor-slot DISPLAY struct array, stride 0x44 (letter byte at 0x9A8B1F + slotÂ·0x44); u8[0x9A8B39+slotÂ·0x44] bit 0x40 = **SENSED flag** (v2.11 gates the HP readout on it), u16[0x9A8B4C+slotÂ·0x44] = display-cached CURRENT HP the game formats as "cur/max" (2026-07-13) |
| `0x9A8E9C` | BATTLE_ENEMY_RECORDS | 3 Ã— 0xB8 scene.bin enemy records (ends 0x9A90C4); name = bytes 0â€“0x1F, possibly unterminated. Sits between the formation/per-actor block and ENEMY_ATTACK_NAME_TABLE 0x9A9484 â€” one contiguous loaded-scene cluster 0x9A87xxâ€“0x9A98xx (2026-07-13, v2.10) |
| `0x9AB070` | encoded-'A' base for dup letters | dword; game emits FF7-char(value + letter idx) for "MP A"/"MP B" suffixes (2026-07-13). Region 0x9AAD70â€“0x9AB070 (0x300 bytes) is cleared as one block by the battle-init memset |
| `0x9AB0A0` | battle_ai_context (FFNx battle_context) | = u32 operand at 0x41CCB2+0x5F (FFNx's own chain; sub_41CCB2 = battle-init memset, clears 0x253 dwords from here). Header 0x3C bytes (10 flag bytes + 23 u16 masks + u32 partyGil), then **actor_vars[10] at 0x9AB0DC = BATTLE_ACTOR_VARS**, stride 0x68: +0x04 stateFlags (the 0x9AB0E0 read from the v2.10 disasm), +0x24 formationID, +0x28/+0x2A cur/max MP u16, +0x2C/+0x30 cur/max HP i32 (+0x30 low word = the 0x9AB10C read). Array ends 0x9AB4EC (v2.11, 2026-07-13) |
| `0x919928` | char-id â†’ savemap-record map | static u32 table the game itself uses to map character IDs to record indices (Young Cloud 9â†’6, Sephiroth 10â†’7); read by the row-toggle code (v2.32) and the limit menu's char resolution 0x70216A (v2.30.35) |
| `0x91AB98` | menu_subs_call_table | uint32[16] sub-screen handlers the main-menu dispatcher calls by MENU_DISPATCH_INDEX 0xDC12EC: [1]=item (live), [3]=materia 0x70CF0B, [4]=equip 0x705D16 ([15] dupes it), [7]=limit 0x70212A, [8]=config, [10]=save/load (v2.31; identities settled v2.30.33-.35) |
| `0x9204D8` | LIMITMENU_MODE | u32 limit-menu state 0..4 (draw switch 0x70313A; 0=Set/Check bar, 1-4=grid/confirm â€” per-value map rides the debug log; v2.30.35). Same 0x92 state band |
| `0x920FA0` | MATMENU_MODE | u32 materia-menu state machine, 12 cases (jump table 0x70E246; full map in Â§4; v2.30.33). Fourth confirmation of the 0x91Eâ€“0x925 per-screen state-machine cluster |
| `0x92565C` | SHOP_STATE | u32 shop screen state 0..6 â€” the shop loop's own switch variable (v2.30.28 static; full state map in Â§4). Menu-module .data, same neighborhood as BATTLE_MENU_STATE/NAME_ENTRY_PANE_FLAG â€” third confirmation that per-screen menu state machines live in this 0x91Eâ€“0x925 band |
| `0x9A85D4` / `0x9A85E0` | menu held / pressed input digests | the menu module's own digested-input words; OVERWRITTEN with VM output by the tutorial input refresh (0x7186C8â†’0x71826E) while a tutorial runs â€” the reason real presses never reach menu nav during demos (v2.30.29) |
| `0x922D00â€“0x923416` | shop caption strings | FF7-encoded exe statics: "Buy"/"Sell"/"Exit"/"Owned"/"Equipped"/"Gil remaining"/"Price through AP"/"Price for Master" captions (0x922Dxx), shop TITLES at 0x922FC8 + idxÂ·0x14, shopkeeper GREETING/PROMPT sets at 0x923080 + setÂ·0x1CC (v2.30.28) |
| `0x923418` | SHOP_CATALOG | shop records, stride 0x54 (name idx, greeting-set idx, ware count, ware[10]{type,id}) â€” the complete what-every-shop-sells table, indexable offline (v2.30.28) |
| `0x9AD1E0` / `0x9AD9E0` | SCENE_MSG_BASE / SCENE_MSG_OFFSETS | current formation's scene.bin messages: text(idx) = 0x9AD1E0 + u16[0x9AD9E0+(idxâˆ’0x100)Â·2], FF7-decoded. Replicates GET_KERNEL_TEXT section 8 (handler 0x4199AD â†’ 0x41D2E5). v2.36 scene-message reader |
| `0x9AE12C` | BATTLE_DROPS_COUNT | u32 count for the drops array 0x99E2F0 (battle results, v2.35). Sits just past the actor_vars block |
| `0x9ADF0C` | kernel2 data pointer candidate | REJECTED â€” reads 0 at runtime (2026-07-11) |
| *(heap, varies)* | decompressed kernel2 text block | magic/item/weapon name sections observed stable for a whole session; each section = u16 offset table + 0xFF-terminated strings, `u16[base]` = offset of entry 0. Located at runtime by English signature scan ('Cure\|Cure2', 'Potion\|Hi-Potion', 'Buster Sword', 'Attack\|Magic') + walk-back rule `u16[base]==distance` (v2.7). No stable static anchor exists â€” the only exe-static pointers into the block are font tables (0xCFF3F8 cluster). âš  **"resident for process lifetime" was DISPROVED for the COMMAND-name section 2026-07-16** (v2.22.1): it lives in a TRANSIENT battle allocation, freed/reused between battles â€” a cached pointer decoded reused binary as speech. ALL section pointers are now head-signature revalidated on every use (ValidatedSection, proxy.cpp); treat any kernel2 pointer as potentially stale |

### Battle module block: 0xBE1170 â€“ 0xBFxxxx

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xBE1170` | G_ACTIVE_ACTOR_ID | u8; never resets between battles |
| `0xBE1178` | G_BATTLE_MODEL_STATE | stride 0x1AEC Ã— 10 slots â‰ˆ ends 0xBF1EF0 |
| `0xBF23B8` | G_SMALL_BATTLE_MODEL_STATE | stride 0x74; starts right after the large array |
| `0xBF1EB8` | BATTLE_TEXT_QUEUE | battle text display queue, battle_text_data[64] stride 6 (s16 buffer_idx@+0, -1=empty, â‰¥0x100=scene AI dialogue). FFNx-anchored (add_text_to_display_queue+0x25). v2.36's scene-message channel (scorpion tail warning etc.) |
| `0xBFC3E0â€“0xBFC5E0` | SFX/audio playback buffer | random churn; noise source in scans |

The battle command-menu CURSOR is confirmed NOT in either known per-actor array
(3 investigation sessions). RESOLVED STATICALLY 2026-07-12: the PSX "menu-widget
struct selected by a current-widget global" architecture DID carry over â€” the
widget global is `BATTLE_MENU_STATE` 0x91EF9C (menu-module .data, like the
name-entry PANE_FLAG at 0x921ED4), and the widget structs live in the menu
module block at 0xDC20A0+slotÂ·0x700 (see Â§4 BATTLE_WIDGET_BASE). The three
live-scan sessions failed because the cursor is two u32 components inside a
0x38-byte struct at an address 0x1000+ bytes from any then-known anchor, in a
region that also hosts constantly-churning scroll/animation fields (+0x24/+0x30
change during list scrolling â€” classic delta-scan poison).
**LIVE-CONFIRMED 2026-07-12** by `ff7_battle_menu_cursor_live_verify.py`
(two battles: command names, magic-list rows incl. Ice by name, target cursor,
and the Limit-replaces-Attack row-0 swap all spoken correctly in real time).

### Battle results block: 0x99E2C0 â€“ â‰ˆ0x99E340

| Address | Symbol | Notes |
|---------|--------|-------|
| `0x99E2C0/C4/C8` | BATTLE_GAINED_EXP/AP/GIL | u32 pools the battle module (0x431541) accumulates per enemy from actor_vars; âš  consumed on apply (gil zeroed entering mode 3) â€” capture at results entry (v2.35) |
| `0x99E2F0` | BATTLE_DROPS_ARRAY | stride-6 entries, u16 item id at +0 (0-319 namespace); +4 = compaction-copied word (qty/taken â€” unconfirmed). Count u32 at `0x9AE12C` (v2.35) |

### Field module block: 0xCBF578 â€“ 0xCC2270

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xCBF578` | DIALOG_TEXT_PTRS[8] | authoritative dialog text pointers |
| `0xCBF5E8` | field_script_ptr | section 0 pointer |
| `0xCBF600` | FIELD_ENTITY_LINE_SLOT | u8 per entity â†’ line index (v2.17); sits right after the script pointer |
| `0xCBFB70` | FIELD_ENTITY_MODEL_MAP | u8 per entity â†’ model slot (0xFF = no model); read by the TLKON handler (2026-07-16). Unused by the mod so far â€” the natural anchor whenever an entity-keyed fact needs its model |
| `0xCBF9D8` | field_global_object_ptr | â†’ modules_global_object |
| `0xCC0418` | current_dialog_message_speed | from ff7.h comment (unused by us so far) |
| `0xCC088C` | FIELD_LINE_COUNT | u16, LINE zones on this field (v2.17) |
| `0xCC08E8` | FIELD_TEXT_BLOCK_PTR | â†’ field dialog-text block (u16 offset table at +2); the MPNAM callee's text source (2026-07-16). 0x5C past FIELD_LINE_COUNT â€” the cluster rule again |
| `0xCC0960` | field_entity_id_list | |
| `0xCC0964` | current_entity_id | |
| `0xCC0B60` | field_event_data_ptr | â†’ 0xCC1670 (observed) |
| `0xCC0CF8` | field_curr_script_position | WORD per entity |
| `0xCC0D88` | **modules_global_object struct** | spans â‰ˆ0x138 bytes â†’ 0xCC0EC0 (PSX-decomp estimate; see sub-map below). âš  note on the +0xB2 lock bitfield: is_triangle_locked()'s FWMESH_MAX_TRIS=4096 guard would in theory allow reads to +0x2B1, past this span â€” but the guard is unreachable in practice: callers pass tri < the field's ntris, and the game-wide max is 496 triangles (bitfield ends +0xF0; ff7_walkmesh_max_tris.py 2026-07-23), so real reads always stay inside the struct |
| `0xCC14D1` | ASKMENU_OPTION | âš  demoted v2.30.12: the ASK opcode's per-DIALOG script output variable, NOT a cursor global â€” frozen for any dialog whose bank/address params name a different variable (soldier fight-or-flee, log 2026-07-22). Cursor now read from 0xCFF5DE (below). Kept as provenance only |
| `0xCC15D0` | FIELD_ID | does NOT zero in battle |
| `0xCC162C` | FIELD_PLAYER_MODEL_ID | |
| `0xCC1638` | FIELD_MOVIE_PLAYING word | |
| `0xCC165C` / `0xCC1660` | (unnamed save-load pair) | save-load field entry 0x63CCBA copies savemap 0xDC08D9/0xDC08DA here alongside the FIELD_JUMP_INTERFACE fill; identities unknown (audit 2026-08-02 - recorded so the cluster stays complete) |
| `0xCC1670` | field_event_data array (static) | stride 0x88 per model; player facing applied at array+0x38 per slot (absolute 0xCC16A8 for slot 0) by the arrival routine 0x63C094 (2026-08-02) |
| `0xCC1B42` | field-script variable | FALSE cursor candidate (freezes when menu opens) |
| `0xCC1F70` | FIELD_LINE_ARRAY | 32 Ã— 0x18 LINE trigger zones (v2.17); starts 0x80 past the event-data array's 16-model end (0xCC1EF0) â€” same allocation neighborhood, as the cluster rule predicts |

Sub-map of `modules_global_object` (0xCC0D88 + offset; PSX decomp names in quotes):

| Offset | Address | Field | Confirmed? |
|--------|---------|-------|------------|
| +0x01 | `0xCC0D89` | game_mode: 0=field, **1=field jump pending (2026-08-02)**, 2=battle, 6=name entry, 9=menu, 15..24=field_loop menu-sub dispatch (static), 26=game-over handoff (transient ~60ms; reel+post-GO title read 0 with stale FIELD_ID â€” v2.30.37) | âœ“ live |
| +0x02 | `0xCC0D8A` | next-module parameter: DEST FIELD ID on a field jump (MAPJUMP 0x613220, gateway-hit 0x636244, world exit 0x76713B all store it; field_loop dispatch 0x63C1DF pushes it into menu-module calls); FFNx's "battle_id" label = the same slot carrying the formation id when the next module is battle | âœ“ static disasm 2026-08-02 (Â§4 FIELD_JUMP_INTERFACE) |
| +0x04/06 | `0xCC0D8C/8E` | DEST X/Y for the pending field jump (arrival placement consumes) | âœ“ static disasm 2026-08-02 |
| +0x22 | `0xCC0DAA` | DEST walkmesh TRIANGLE id (gateway record +0x10 / MAPJUMP arg / savemap 0xDC08D6) | âœ“ static disasm 2026-08-02 |
| +0x24 | `0xCC0DAC` | **DEST arrival DIRECTION** (byte 0-255) - applied to player field_event_data +0x38 at 0x63C094 on arrival | âœ“ static + LIVE (ARRIVE match=1, three runs 2026-08-02) |
| +0x26 | `0xCC0DAE` | jump/module-switch PHASE: **2 = new field constructed** (written 0x63C148/0x63C232; MAPJUMP's second entry waits for ==2 then advances the script PC) - supersedes the old "previous_game_mode/movieState" label guesses | âœ“ static disasm 2026-08-02 |
| +0x28 | `0xCC0DB0` | num_models | PSX+FFNx agree |
| +0x2A | `0xCC0DB2` | field_model_id ("pc model id") - the INCOMING field's player model slot; arrival init copies it to PLAYER_MODEL_ID 0xCC162C at 0x63C073 | PSX+FFNx agree + âœ“ disasm 2026-08-02 |
| +0x2C/2E/30 | `0xCC0DB4â€¦` | PSX: idle/walk/run animation ids | PSX only |
| +0x32 | `0xCC0DBA` | UC player-control lock | âœ“ live (v2.6 gate works) |
| +0x33 | `0xCC0DBB` | PSX: "suspend walk animation" | PSX only |
| +0x34 | `0xCC0DBC` | PSX: "menus disabled" (MENU opcode?) | PSX only â€” candidate for menu-availability TTS |
| +0x36 | `0xCC0DBE` | **MAPJUMP_DISABLED** - the MPJPO opcode (0xD2, handler 0x61A4D4) writes its 1-byte script arg here raw; nonzero = gateway crossings dead (scenes). PSX "map jump disabled" label CONFIRMED (ff7_mpjpo_static.py 2026-08-02); value convention (1=disabled) awaits one live sighting - rides the v2.30.64 debug lines | âœ“ static disasm 2026-08-02 |
| +0x37â€“0x3B | `0xCC0DBFâ€“C3` | SCRLO / MPDSP / MVCAM / BGMOVIE / BTLON flags | PSX+FFNx agree |
| +0x3C | `0xCC0DC4` | PSX: "encounter table id" | PSX only |
| +0x44 | `0xCC0DCC` | midi_id | FFNx label only |
| +0x4Câ€“0x62 | `0xCC0DD4â€¦` | fade type/adjustment/speed/rgb | FFNx labels |
| +0x64 | `0xCC0DEC` | field_id (module copy â€” distinct from 0xCC15D0) | FFNx label only |
| +0x68 | `0xCC0DF0` | current_key_input_status (u32) | âœ“ live |
| +0x6C | `0xCC0DF4` | previous_key_input_status | FFNx label only |
| +0xB2 | `0xCC0E3A` | **TRIANGLE_LOCK_BITS** â€” IDLCK per-triangle lock bitfield (bit tri&7 of byte tri>>3, SET = impassable). Writer: IDLCK handler 0x61E29F via [0xCBF9D8]+0xB2; reader: movement edge-crossing 0x6369E8/0x636AAF/0x636B76 against this static address â€” the address equality is what PROVED field_global_object_ptr (0xCBF9D8) â†’ this struct. v2.30.21 A* overlay. CAPACITY verified game-wide (ff7_walkmesh_max_tris.py 2026-07-23): max field = 496 triangles (bugin1c) â†’ bitfield tops out at +0xF0, inside the struct span | âœ“ static disasm Ã—2 + capacity catalog |

### Field statics cluster: 0xCFF3D8 â€“ 0xCFF73E

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xCFF3D8` | field_camera_rotation_matrix | FFNx name embeds the address; used as a chain cross-check in v2.14. The rotation matrix itself is NOT yet used by the mod (control_direction supersedes it for input-relative directions) |
| `0xCFF3F8` | font tables cluster | the only exe-static pointers into the kernel2 heap text block (v2.7 finding) |
| `0xCFF434` | WALKMESH_PTR | engine's parsed walkmesh: [ptr] = u16 nTriangles, +4 = triangle pool (arrival-init disasm 0x63C116, 2026-08-02; Â§4 row) |
| `0xCFF454` | FIELD_TRIGGERS_HEADER_PTR | â†’ field_trigger_header (field name, control_direction, gateways[12]) â€” the v2.14 pathfinder source; see Â§4. control_direction = world bearing of screen-DOWN (live-calibrated 2026-07-13); screen angle = world + ctrl âˆ’ 180 |
| `0xCFF5D2â€“0xCFF74F` | ASK per-window struct array | 8 windows Ã— stride 0x30 (v2.30.12 disasm consolidation): byte 0xCFF5D2+nÂ·0x30 input-armed flag, u16 0xCFF5DC+nÂ·0x30 = 5 while choosing, **u16 0xCFF5DE+nÂ·0x30 = ASK_CURSOR_PIXEL_Y (highlight pixel Y = lineÂ·16+6 â€” the mod's cursor source)**, u16 0xCFF5E4+nÂ·0x30 = 7 on confirm, u16 0xCFF5E6+nÂ·0x30 state-flag word (bit 0 gates input). Sits between the triggers-header ptr 0xCFF454 and the field model globals 0xCFF73x â€” same field-module BSS cluster |
| `0xCFF594` | FIELD_FILE_BUFFER | pointer to raw field file â€” dialog text (Â§5), model labels (v2.16), and since v2.22 the WALKMESH (section index 4: triangles + adjacency, the turn-by-turn/journey data source; Â§4 *(walkmesh section)* row) |
| `0xCFF738` | FIELD_ANIM_DATA_PTR | â†’ field_animation_data array, stride 0x190 per model (kawai_opcode u8 at +0x21). Doubly confirmed 2026-07-14: FFNx ff7.h names it with the address in a comment AND our LADER-handler disasm reads it with the same stride (v2.18.1 chest-state work) |
| `0xCFF73E` | FIELD_N_MODELS | u16 model count |
| `0xCFF744` | TRIANGLE_POOL_PTR | u32 -> walkmesh triangle pool (= [0xCFF434]+4), set by the arrival init at 0x63C12C (2026-08-02) |
| `0xCFF748` | game's parsed ACCESS-pool ptr | u32 â†’ the engine's own parsed walkmesh adjacency (3Ã—u16 neighbor ids per triangle), read by the movement edge-crossing code (0x6369E8â€¦) alongside TRIANGLE_LOCK_BITS. Same data the mod re-parses from the raw section; recorded 2026-07-23 (IDLCK investigation bonus). Derivation seen 2026-08-02: = walkmesh base + 4 + nTri*0x18 (0x63C142) |

### Shared char-data block: 0xDBA498 â€“ â‰ˆ0xDBB158 (3 Ã— 0x440)

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xDBA498` | BATTLE_CHAR_BLOCK | Per-party-slot char data, stride 0x440 â€” battle command/magic/summon tables (v2.9) AND, v2.33, the menu's computed EFFECTIVE stats: +0x02..+0x07 u8 stats, +0x08..+0x0E u16 Attack/Defense/Magic atk/Magic def, +0x10..+0x16 HP/MP pairs. See the Â§4 row for the full field map. Sits BELOW the savemap â€” the two must not be conflated |

### Kernel gear-data arrays: 0xDBCAEE â€“ â‰ˆ0xDBEB00 (loaded from kernel.bin)

Static BSS destinations of the kernel.bin DATA sections (not the text
sections â€” those are heap + signature-scanned). Mapped v2.30.28 from the
gear-record helper 0x6C50DD, which the shop's sell handler calls for the
restriction word (bit 0 = cannot sell):

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xDBCAEE` | accessory records | stride 0x10, ids 0x120+ (restriction word at +0) |
| `0xDBCD00` | armor records | stride 0x24, ids 0x100â€“0x11F |
| `0xDBD16A` | item records (word field) | stride 0x1C, ids 0x00â€“0x7F |
| `0xDBE75A` | weapon records (word field) | stride 0x2C, ids 0x80â€“0xFF |

(The addresses are the RESTRICTION-WORD field the helper returns, not the
record bases â€” subtract the field offset if the full records are ever
needed; the helper's own math is the documented ground truth.)

### Savemap: 0xDBFD38 â€“ â‰ˆ0xDC0E2C (0x10F4 bytes)

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xDBFD30` | TUTORIAL_RUNNING | u32 sitting 8 bytes BEFORE the savemap: 1 while the menu tutorial VM runs (v2.30.29). Menu-module global, NOT saved state â€” listed here for address-ordering only |
| `0xDBFD38` | savemap base | live game state, persisted on save |
| `0xDBFD8Câ€“0xDC022F` | SAVEMAP_CHAR_RECORDS | 9 character records Ã— 0x84 (savemap+0x54..+0x4F7); live name at record+0x10, equipment at +0x1C (= the 7thHeaven "+0x70 blocks") (v2.19); battle-row byte at **+0x20** (0xFF front/0xFE back â€” LIVE-toggled + disasm XOR 1, v2.32; community's +0x1F is one byte off); HP/MP words +0x2C/+0x38/+0x30/+0x3A (v2.31) |
| `0xDC0230` | SAVEMAP_PARTY_IDS | u8[3] party-member character IDs (savemap+0x4F8); slot 0 mirrors PARTY_LEADER â€” used as the v2.19 runtime layout guard |
| `0xDC0234â€“0xDC04B3` | SAVEMAP_ITEMS | items[320] u16 (savemap+0x4FC, pinned by party_members[3]+pad in FFNx's savemap struct): id = bits 0-8, qty = bits 9-15, EMPTY = 0xFFFF (FFNx menu.cpp's own reimplementation). Screen row order = array order. Read by v2.31's item-menu speaker |
| `0xDC04B4â€“0xDC07D3` | SAVEMAP_MATERIA | materia[200] u32 (savemap+0x77C, FFNx savemap struct): id = low byte (0xFF/whole-word -1 = empty), AP = bits 8-31 (0xFFFFFF = mastered). The shop's sell-materia code indexes exactly here (0x71DD16) â€” v2.30.28's sell-list reader |
| `0xDC0894â€“0xDC08B3` | SAVEMAP_KEYITEM_BITS | 32-byte key-item bitmask (savemap+0xB5C, FFNx field_B5C). Recorded for the Key Items pane follow-up; not yet consumed |
| `0xDC08B4` | SAVEMAP_GIL | u32 party gil (savemap+0xB7C). Triple-confirmed: v2.35 victory total, the shop's buy/sell writes (0x71DBBF/0x71DD2E), and FFNx's achievement reads. Spoken by the G key + shop screens (v2.30.28) |
| `0xDC08BC` | COUNTDOWN_TIMER_SECONDS | u32 seconds, timed-escape clock (savemap+0xB84, STTIM-written; v2.34 announcer + Shift+T freeze). +0x4 = ms accumulator 0xDC08C0 |
| `0xDC08CE` | SAVEMAP_CONTINUE_FIELD | u16 saved field id (savemap+0xB96) - the save-load field entry 0x63CCBA copies it to the module field-id 0xCC0DEC (audit 2026-08-02; static disasm same day) |
| `0xDC08D2â€“0xDC08DA` | SAVEMAP_CONTINUE_POS | saved re-entry position (savemap+0xB9A..): u16 X 0xDC08D2, Y 0xDC08D4, walkmesh triangle 0xDC08D6, u8 arrival DIRECTION 0xDC08D8, u8 pair 0xDC08D9/DA -> module 0xCC165C/0xCC1660 (unnamed). Loading a save feeds these into FIELD_JUMP_INTERFACE - the same arrival path as MAPJUMP/gateways (2026-08-02) |
| `0xDC08DC` | STORY_PROGRESS (PPV) | s16 story counter (7thHeaven.var); logged as ppv= per arrival since v2.30.66 ([STORYNAV] pipeline) |
| `0xDC09E5` | PARTY_LEADER | u8 leader character ID (7thHeaven.var; live-proven by battle labels since v2.7) |
| `0xDC0C44` | LOCATION_NAME_BUFFER | savemap+0xF0C: the friendly menu caption ("Sector 1 Station"), FF7-encoded, â‰¤0x17 bytes, 0xFF-terminated, written by MPNAM's callee 0x633691 â€” live-confirmed 2026-07-16, spoken by v2.24. Persisting in the savemap is WHY save files remember the caption |
| `0xDC0E10â€“0xDC0E24` | CONFIG_* value bytes | **these sit INSIDE the savemap range** â€” FF7 persists config in the save header region, which is why the sliders live here and not with the menu cursors |

### Menu module block: 0xDC0FA0 â€“ 0xDCA810

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xDC0FA0` | QUIT_CURSOR | |
| `0xDC0FB1` | QUIT_OPEN | unreliable (never re-zeroes) â€” do not gate on it |
| `0xDC0FC0` | menu_objects | FFNx externals |
| `0xDC108C` | SOUND_CURSOR | |
| `0xDC10F0` | CONFIG_ROW | |
| `0xDC110C` | ORDERMENU_FIRST_SLOT | s8 slot latched at the Order pane's first confirm (v2.32 disasm) |
| `0xDC1130` | MENU_DISABLED_ROWS | u16 bitmask, bit N = main-menu row N grayed (v2.32 â€” the Materia/PHS gray) |
| `0xDC1154` | MENU_CURSOR | frozen at 9 (Save row) for the whole save-menu session â€” v2.29's save-mode gate (the Config frozen-row signature again) |
| `0xDC118C` | CHARSEL_CURSOR | u32 character-select pane cursor (mode-1 rows: Magic/Equip/Status; v2.32 speaks it) |
| `0xDC11C4` | ORDERMENU_CURSOR | u8 Order-pane party cursor, scan speak-back verified (v2.32) |
| `0xDC1259` | (unresolved) | read 9 in the Order pane, 10 with a member selected (scan latch pass); maybe a widget/cursor count â€” not consumed |
| `0xDC1288` | CHARSEL_CHOSEN | u32 slot committed by the mode-1 pane (v2.32 disasm; not yet consumed) |
| `0xDC1300` | BATTLE_END_MODE | u16 victory-screen phase, advancing on the player's OK PRESSES not screen appearances (v2.35.2 play-corrected): 0=EXP/AP screen showing, 1=roll-up running (chirps/levels apply), 2=gil/items screen showing, 3=after its OK (gil applied). FFNx menu_battle_end_mode |
| `0xDC1320` | ORDERMENU_LATCH | u32 1 = first member selected (v2.32, scan + disasm) |
| `0xDC1310` / `0xDC1214` / `0xDC1318` / `0xDC1314` | TUTWIN_STATE / TEXT_PTR / MODE / TIMER | the menu message/tutorial window renderer's state block (0x6C49FD; = FFNx menu_tutorial_window_state/_text_ptr). Full semantics in Â§4 (v2.30.29). Shared by tutorial slides AND save-screen info popups |
| `0xDC1324` | MENU_FOCUS_MODE | u8 0=menu bar / 1=char-select pane (chimed) / 2=Order pane (silent â€” the player-noticed missing chime); v2.32's Order gate |
| `0xDC1210` | (frame parity) | âš  DISPROVED as a pane flag (v2.29.2): oscillates in real use â€” passed the A/B/A scan by coincidence. CAUSE FOUND (v2.31 dispatcher disasm): the sub-screen dispatcher XOR-toggles it every menu tick. Never read |
| `0xDC12DC` | MENU_OPEN | also 1 on post-battle results screen AND the naming screen (v2.8.3) |
| `0xDC12E8` | MENU_DISPATCH_TRANS | u32 sub-screen index used by the dispatcher during fade-transition frames (menu_sub_6CB56A disasm, v2.31) |
| `0xDC12EC` | MENU_DISPATCH_INDEX | u32 steady-state sub-screen index into menu_subs_call_table[16] @0x91AB98 â€” ITEM screen = 1 (LIVE: constant 1 through the whole item-menu scan session; overrides the static caption guess of 3). Known table ids: [8]=config, [10]=save/load (FFNx). v2.31's which-screen gate. âš  value on the PLAIN main menu not yet observed |
| `0xDC1138` | (menu frame counter) | u32, +1 every dispatcher tick (same disasm); not consumed |
| `0xDC6AE0` | SAVEMENU_GRID_CURSOR | u8 0..4 file-grid COLUMN (not 0..9 â€” v2.29.3); holds selected file while slot list open (v2.29) |
| `0xDC6AE4` | SAVEMENU_GRID_ROW | u8 grid row (0=top/1=bottom); LIVE-CONFIRMED by the field probe (v2.29.4) |
| `0xDC6B1C` | SAVEMENU_SLOT_CURSOR | u8 0..2 visible ROW of the 3-row slot window (NOT absolute slot â€” v2.29.2), grid+0x3C â€” same DC6Axx save-menu struct. Holds still while the confirm dialog is up |
| `0xDC6C6C` | SAVEMENU_CONFIRM_CURSOR | Yes/No cursor of the save-confirm dialog: 0=Yes 1=No, resets to Yes on open; single candidate + speak-back verified (v2.29.5) |
| `0xDC6B2C` | SAVEMENU_SLOT_SCROLL | u8 0..12 scroll offset, LIVE-CONFIRMED (field probe 20260717_200802); absolute slot = row + scroll. Neighbors: 0xDC6B34 = slot count (15), 0xDC6B24 = visible rows (3), 0xDC6B3C tween + 0xDC6B48 direction flag = scroll-animation noise |
| `0xDC208C` | kernel2 lookup result ptr | written after every consumer CALL to 0x41963C â€” but consumer is FFNx-replaced, so **never written in practice**; observed 0 always (2026-07-11) |
| `0xDC20A0` | BATTLE_WIDGET_BASE | per-slot (+slotÂ·0x700) battle menu widget structs â€” command cursor at +0/+4; see Â§4 (2026-07-12) |
| `0xDC35AC` | BATTLE_MENU_BUSY | u32 transition flag; `0xDC35A8` = command-menu-opened SFX-played byte |
| `0xDC3C54â€“0xDC3C98` | issued-action staging block | 0xDC3C70 cmd id, 0xDC3C78 action id, 0xDC3C7C ACTIVE SLOT, 0xDC3C84 action idx, 0xDC3C90/94 target type/idx, 0xDC3C98 targeting actor (all = FFNx externals; static 2026-07-12) |
| `0xDC3640` | flash-name compose buffer | dispatcher branch 4 (cmd 0x07) output |
| `0xDC38E0` | BATTLE_ACTOR_DATA (FFNx struct) | +0x08 pending pulse, +0x0C command_index, +0x10 action_index â€” the v2.7 flash-message source |
| `0xDCA028` | SAVEMENU_WIDGET_STATE | save-menu widget state machine: 0=file grid, 1=slot list, 7=save-confirm dialog (v2.29.5; only 7 acted on) |
| `0xDCA198/9C` + `0xDCA208/0C` | LIMITMENU Set/Check grid col/row | two instances of the 2Ã—2 LEVEL grid widget (Ã—0x124/Ã—0x89 px draw); limit level = rowÂ·2+col (v2.30.35) |
| `0xDCA1D0` | LIMITMENU bar cursor | 0=Set 1=Check (Ã—0x50 px highlight) (v2.30.35) |
| `0xDCA3C8` | LIMITMENU party slot | 0..2; char resolved via SAVEMAP_PARTY_IDS + idâ†’record table 0x919928 (v2.30.35) |
| `0xDCA4A4` | EQMENU_PARTY_SLOT | u32 equip-screen character cycler 0..2 (âš  play-corrected v2.30.50 â€” was shipped as the category row; the wrap code's party-ids skip loop is the tell) |
| `0xDCA5C4` | EQMENU_CATEGORY | u32 category row 0=Wpn 1=Arm 2=Acc (OK handler passes it to the candidate builder; cmp 2 bounds throughout) (v2.30.50) |
| `0xDCA5F8` (+4/+0x14) | equip candidate-list widget | EQMENU_LIST_ROW 0xDCA5FC + SCROLL 0xDCA60C (v2.30.34) |
| `0xDCA6A0` | EQMENU_LIST_OPEN | pane flag: 0=category rows, 1=candidate list (set 0x7071C3, cleared 0x707346/0x707601) (v2.30.34) |
| `0xDCA6A8` | EQMENU candidate bytes | u8[] category-relative kernel gear indices, 0xFF terminator; candidate = [row+scroll] (the OK-commit's own read) (v2.30.34) |
| `0xDCA7EC` | EQMENU_LIST_COUNT | candidate count from the list builder 0x708640 (v2.30.34) |
| `0xDCA810` | MATMENU_CHARREC_PTR | u32 â†’ viewed character's savemap record (init 0xDBFD8C=Cloud); slot contents = rec+0x40 weapon / +0x60 armor u32[8] materia words. The v2.31 "0xDCA7F8 exclusive block" was the materia screen's state all along (v2.30.33) |

### Materia menu cursor block: 0xDD12BC â€“ 0xDD1638 (v2.30.33, all static)

Same menu-module BSS band as the item menu block just past it â€” the cluster
rule again. All from one annotated-disasm session (mode jump table 0x70E246).

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xDD12BC` | MATMENU bar cursor | 0=Check 1=Arrange |
| `0xDD12F0/F4` | MATMENU slot idx/row | row 0=weapon 1=armor; OK on a slot â†’ equip list |
| `0xDD1364/74` | MATMENU equip-list row/scroll | **materia[200] index = row+scroll** (commit math 0x70DC80) |
| `0xDD1398/9C` | MATMENU Check-mode widget col/row | mode 4 |
| `0xDD147C` | MATMENU popup row | Arrange popup 0..3 (Arrange/Exchange/Remove all/Trash) |
| `0xDD14B4/C4` | MATMENU arrange-list row/scroll | modes 9/10 |
| `0xDD1638` | MATMENU party slot | 0..2, Ã—0x440 = shared char-data index (weapon slot count byte at chardata+0x21) |

### Item menu block: 0xDD19C8 â€“ 0xDD1A8C

All four = the SINGLE intersected candidates of the guided scan
item_menu_scan_20260718_114427 (list cursor speak-back verified live).

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xDD19C8` | ITEMMENU_MODE | the item menu's own state machine: 0=top bar, 1=item list (ENTRY state â€” the menu opens in the list, Cancel goes UP; player-corrected flow), 2=use-on-whom target pane. Both A/B/A toggles landed on this one address. Other values (Arrange popup? Key Items pane?) unmapped â€” v2.31 debug-logs them |
| `0xDD1A18` | ITEMMENU_TOPBAR_CURSOR | u8 0=Use 1=Arrange 2=Key Items |
| `0xDD1A54` | ITEMMENU_LIST_CURSOR | u8 item-list row; tracked 0..4 over a 3-item inventory in speak-back (cursor DOES ride empty rows â†’ "Empty"). âš  window-vs-absolute UNRESOLVED (3 items can't scroll â€” the v2.29.2 lesson); re-verify once inventory > visible rows |
| `0xDD1A8C` | ITEMMENU_TARGET_CURSOR | u8 party slot 0..2, top-to-bottom |

### Shop block: 0xDD4700 â€“ 0xDD4740 + widgets 0xDD6B48 â€“ 0xDD6C98 (v2.30.28, all static)

Every row from one annotated-disasm session (ff7_shop_static.py, log
shop_static_20260726_101315). âš  This block INTERLEAVES with the title /
name-entry block below â€” the menu module reuses this DD44xxâ€“DD6xxx BSS
across its screens (name entry, shop, title Continue all place state
here), which is why gating on the right GAME_MODE matters before trusting
any of these bytes.

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xDD4700â€“0xDD470C` | shop scrollbar param block | 7 u16s rewritten per state (x, y, scroll, w, h, â€¦) â€” draw plumbing, never read for state |
| `0xDD4710` | shop layout-struct ptr | â†’ 0x925660 (0x9256D8 in the 0xDC130C==1 variant); window x/y fields feed every draw call. Hottest read in the loop (R=976 in the mining pass) |
| `0xDD4714` | shop widget-struct ptr | â†’ 0xDD4744 (set every tick at loop entry) |
| `0xDD4718` / `0xDD4738` | frame counter / parity toggle | wrapper 0x71FF95 housekeeping â€” noise |
| `0xDD4720` | SHOP_PRICE_TABLE_PTR | u32 â†’ heap price table (items Â·4, materia +0x600) â€” validate before every read |
| `0xDD4724/28/2C` | SHOP_ID / NAME_IDX / TEXT_IDX | written by init 0x719D7A from the catalog record |
| `0xDD4734` | SHOP_FADE_STATE | 1 fading in / 2 fading out / -1 exiting (â†’ 0xDC12F4 menu-exit) |
| `0xDD473C` | SHOP_QTY | "How many" count, entry value 1 |
| `0xDD4740` | key-repeat delay counter | set 0xA on qty entry, decremented per frame â€” NOT a price (first read suggested otherwise; the decrement loop settled it) |
| `0xDD6B48` | SHOP_BAR_CURSOR | Buy/Sell/Exit widget base (generic list-widget ctor 0x6F4D30: +0 col, +4 row, +0x14 scroll) |
| `0xDD6B80` (+4/+0x14) | buy-list widget | SHOP_BUY_ROW 0xDD6B84 + SHOP_BUY_SCROLL 0xDD6B94; ware = row+scroll |
| `0xDD6BB8` (+0/+4/+0x14) | sell-item widget | 2-col grid; item index = col + (row+scroll)Â·2 (handler 0x71DC2B verbatim) |
| `0xDD6BF0` (+4/+0x14) | sell-materia widget | SHOP_SELLM_ROW 0xDD6BF4 + SCROLL 0xDD6C04; slot = row+scroll |
| `0xDD6C98` | SHOP_SELLTYPE_CURSOR | Item/Materia bar (state 6) |
| `0xDD6D78` | SHOP_SESSION | 1 while the shop session runs (wrapper-managed) |
| `0xDD1BC8` | TUTORIAL_SCRIPT_PC | tutorial VM position (pointer into the field buffer); `0xDD1BBC` = frame-wait counter, `0xDD1BF4` = window-open hold flag, `0xDD1BF8/FC` = window x/y from opcode 0x12 (v2.30.29 â€” item-menu-block neighborhood, more menu-module BSS interleaving) |

### Title / name-entry block: 0xDD4400 â€“ 0xDD7704

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xDD4400` | (noise) | frame-parity blink byte, toggles 0â†”1 every frame on the naming screen |
| `0xDD4538` | NAME_ENTRY_COL | grid column 0â€“9 (v2.8). 4-byte slot spacing, but READ AS u8 â€” only the low byte is verified (v2.8.1) |
| `0xDD453C` | NAME_ENTRY_ROW | grid row 0â€“6 (v2.8). Read as u8, same reason. Can CHANGE when entering the side panel (1â†’4 observed) |
| `0xDD4574` | NAME_ENTRY_PANEL_INDEX | RESOLVED (v2.8.2): side-panel button index 0=Space 1=Delete 2=Select 3=Default (0/1 proven by buffer effects; 2/3 order ear-confirmed). Wraps 0â†”3. Retains last value after leaving the panel and idles 0 â€” gate on PANE_FLAG (0x921ED4), never alone. The old "3â†’2 alongside a delete" anomaly was a Confirm press ON the panel's Delete button |
| `0xDD45E8` | unknown u32 | small values during editing, 0xFFFFFFFF at times, reset per screen. Unresolved |
| `0xDD45F0` | NAME_ENTRY_BUFFER | FF7-encoded, 0xFF-terminated, â‰¥9 chars (v2.8) |
| `0xDD4630` | (noise) | u16 frame/animation counter, changes every poll on the naming screen |
| `0xDD46F0` | NAME_ENTRY_CARET | RESOLVED (v2.8.2): caret position, clamped 0â€“8. Tracked 5â†’6â†’7â†’8 live as letters were appended to 'Cloud', pinned at 8 when full. Explains the 9-char name cap: at cap, Confirm REPLACES the 9th char instead of appending |
| `0xDD46F8` | NAME_ENTRY_CHAR_INDEX | 0=Cloud, 1=Barret. The Echo mod hext patch called this "cursor column" â€” wrong label, it's the character being named |
| `0xDD46FC` | NAME_ENTRY_ACTIVE | 1 while naming screen open (v2.8 gate, with GAME_MODE==6) |
| `0xDD6D98` | LOADMENU_GRID_CURSOR | Continue menu file grid COLUMN u8 0..4 (v2.29.3); LIVE-VERIFIED speak-back (v2.29.1, 2026-07-17). 0x18C before TITLE_CURSOR â€” the Continue menu lives in the title module |
| `0xDD6D9C` | LOADMENU_GRID_ROW | grid row at +4 (0=top/1=bottom, v2.29.4 play-corrected polarity); LIVE-CONFIRMED by the grid probe (v2.29.3) |
| `0xDD6DD4` | LOADMENU_SLOT_CURSOR | Continue menu slot-list visible ROW 0..2 (3-row window, not absolute); grid+0x3C â€” same struct spacing as the save-menu instance (v2.29.1/2) |
| `0xDD6DE4` | LOADMENU_SLOT_SCROLL | u8 0..12 scroll offset, LIVE-CONFIRMED by the scroll probe; absolute slot = row + scroll. +0x74 = scroll-anim tween (0xFFFFFFxx transients), +0x80 = direction flag â€” noise, never read (v2.29.2) |
| `0xDD6F20` | TITLE_WIDGET | cursor widget (ctor 0x6F4D30, 2 rows Ã— 1 col) built by title init 0x720E64; +0 col / **+4 row = TITLE_CURSOR** / +0x14 scroll (v2.30.38 static disasm â€” settles why TITLE_CURSOR has no direct writer) |
| `0xDD6F24` | TITLE_CURSOR | 0=New Game, 1=Continue; = TITLE_WIDGET+4 (see above); unrelated BSS data outside title screen |
| `0xDD74E0` | TITLE_STATE | dword title lifecycle: 0=fading in/module not run (BSS boot value through logos), **1=menu interactive** (the announce gate, v2.30.38), 2=fading out after choice, -1=exited (stale through gameplay). Reset to 0 by every title entry (init guard 0xDD76F8 cleared at teardown 0x722441) |
| `0xDD76F8` | title init-once guard | 0 = title main 0x722393 runs init on next tick; set 1 after init, cleared at module exit â€” the mechanism that guarantees TITLE_STATE re-cycles 0â†’1 per entry (v2.30.38 disasm) |
| `0xDD76FC` | title saves-exist flag | set at init from file probe 0x720F6E; Continue confirm buzzes (sound 3) when 0, opens the grid when nonzero (v2.30.38 disasm; context only, not consumed by the mod) |
| `0xDD7700` | LOADMENU_LIST_PTR | u32, 0 in file grid / heap ptr to the selected file's loaded data in slot list â€” both menus' phase passes agree; nonzero-check only, never dereference. +0x04 byte flips 0â†’1 with it (runner-up flag) (v2.29.1). v2.30.38 disasm corroborates: written by loader sub 0x720EF0, freed+zeroed by 0x720F2F |
| `0xDD7704` | title subscreen switch | dword 0..7, jump table 0x72231A in draw 0x7212FB; init writes 7; 0 = Continue save-grid subscreen; other values = menu/preview phases (per-value map unharvested â€” context only, v2.30.38 disasm) |

### Discovery techniques ranked by success rate (as of 2026-07-16)

1. **Static chain resolution against the exe on disk** (v2.6; battle menu
   cursor 2026-07-12): replicate FFNx `ff7_data.h` chains on the file image;
   cross-check against `ff7.h` address comments. Zero user effort, immune to
   FFNx trampolines. Best first move. The battle-cursor break came from
   pairing it with **capstone disassembly of the resolved functions**:
   extract every absolute data-region operand per handler, then intersect
   "written by input handlers" with "read by draw code" â€” that intersection
   is tiny and cursor-shaped even when no single +-1 instruction exists
   (the mutation lived in a shared helper behind a struct pointer).
2. **Offline game-data catalog from the install's own archives** (NEW
   2026-07-14, v2.18): parse flevel.lgp (or any LGP) directly â€” LGP TOC +
   LZS decompress + the already-decoded section format â€” and derive facts
   from the COMPLETE dataset instead of play-collected samples. One run
   catalogued every model label in all 720 fields, turned the save-point
   heuristic into a game-wide certainty, and grounded the entire Items
   classification. Zero user effort, zero live process. Use whenever the
   question is "what does the game's DATA say" rather than "where does the
   ENGINE keep it"; validate the parser against one live-dumped reference
   field (md1stin) before trusting it.
   **2a. Offline ALGORITHM replica over the cataloged data** (NEW
   2026-07-16, v2.22/v2.23): before shipping geometry/graph code, replicate
   the exact C++ pipeline in the catalog script and run it against the real
   game data (all 720 walkmeshes; the reactor's real trigger lines lifted
   from the live debug log). One run confirmed the community-spec access
   pool game-wide AND caught an inverted-sign funnel bug that produced
   plausible-sounding zigzag garbage â€” a class of bug play-testing burns
   whole sessions on (a blind tester cannot see that a route is non-taut,
   only that it feels wrong). Any pure function of game data can be
   verified this way before it ever speaks.
3. **Opcode-handler disassembly via the opcode table** (NEW 2026-07-14,
   v2.17): the mod's own Resolve() chain locates execute_opcode_table on
   disk; table[opcode] + capstone gives the handler for ANY field script
   opcode, and cross-agreement between related handlers (LINE/LINON/SLINE
   all writing one array) self-validates the find. Cracked the LINE
   trigger storage in a single pass with no live scanning at all.
4. **PSX decomp struct matching** (v2.6 UC lock): once a PC struct base is known,
   align it with the PSX decomp's version and lift the PSX field comments.
5. **Targeted isolate delta scan** (MENU_CURSOR, CONFIG_ROW, SOUND_CURSOR,
   NAME_ENTRY_ROW/COL/BUFFER): two snapshot phases inside the same frozen
   context, subtract. Succeeded again v2.8 â€” and its validation phase
   correctly EXPOSED a bad external anchor (see item 9).
6. **Live change-monitor with the player narrating** (GAME_MODE values): passive
   500ms change-logger, no staged phases; good for enum-value discovery.
   The v2.18.1 chest-state variant (full-struct diff against a stand-still
   baseline that auto-excludes churning bytes, then a state-matrix check
   across re-entry) found the lid signal in one session â€” but LESSON: a
   state-matrix check is only valid when the precondition is observed in
   the CURRENT game session; the first re-entry run was silently invalidated
   by a game restart between runs (pid changed, "open" reference read
   closed). Guard the precondition in-script before prompting the player.
7. **Full-heap delta scans**: FAILED at scale (battle cursor, ~1.5M bytes of
   background churn per quiet window). Use only inside frozen contexts.
8. **Hardware-breakpoint debugging**: game self-terminates (anti-debug). Never retry.
9. **Third-party mod hext-patch labels**: UNRELIABLE (v2.8). The Echo mod's
   '01 - Disable Name Change.txt' labeled 0xDD46F8 "name-entry cursor column";
   live scanning proved it's the character-being-named index â€” it never changes
   during grid navigation. The ADDRESS a patch touches is a useful region hint
   (it did point at the right DD45xx-DD46xx block), but the LABEL describes what
   the patch author needed to break, not what the byte is. Never use one as a
   validation anchor without live confirmation.
