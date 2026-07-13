# FFVII Blind Accessibility — Technical Research & Implementation Log

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

The background thread slept 200ms and then installed hooks. But FFNx's `voice_init()` — which also patches the opcode table — was running *during* that 200ms window, after our hooks were already installed. FFNx read our hook address from the table and tried to walk *our* machine code looking for a CALL instruction, found our prologue bytes instead, and crashed.

Fix: `Resolve()` checks `execute_opcode_table[0x40]`. If the value is in the original FF7 code range (`0x401000–0x9FFFFF`) and FFNx is loaded (`GetModuleHandleA("AF3DN.P") != nullptr`), FFNx hasn't finished patching yet — return false and retry. Once FFNx's `voice_init()` has run, the entry is FFNx's handler in DLL address space (above `0x9FFFFF`). Only then do we install our hook on top. The background thread polls `Resolve()` every 50ms.

### Hook Chain

```
hook_message (us)  →  FFNx opcode_voice_message  →  FF7 original opcode_message
hook_ask    (us)  →  FFNx opcode_voice_ask       →  FF7 original opcode_ask
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
  +0x80  relative CALL → execute_opcode function address
  +0x10D absolute ref  → execute_opcode_table (uint32_t[256] of opcode handlers)

OPCODE_MSG_UPDATE_LOOP = 0x630D50
  +0x12  absolute ref  → opcode_message_loop_code (uint8_t[], 24-byte stride per window)
```

Additional chains resolved STATICALLY against the exe file on disk for v2.6
(`investigate/ff7_wall_nav_static.py`, 2026-07-09). Static file analysis avoids
FFNx's runtime trampolines entirely — the on-disk bytes are pure Square code and
the binary has no ASLR, so file-derived VAs are runtime VAs. Where FFNx's `ff7.h`
carries an address comment it doubles as a cross-check (all matched exactly):

```
FIELD_INIT_EVENT = 0x60BACF
  +0x20  absolute ref  → modules_global_object            = 0xCC0D88  (ff7.h comment ✓)
  +0x1C  absolute ref  → field_global_object_ptr          = 0xCBF9D8

execute_opcode_table[0xB1]  → opcode_canm1_canm2          = 0x614E3E
  +0xC1  absolute ref  → field_event_data_ptr             = 0xCC0B60  (ff7.h comment ✓)

FIELD_LOOP = 0x63C17F   (FFNx: field_loop_sub_63C17F)
  +0x5DD relative CALL → field_update_models_positions    = 0x6342C6
    +0x45D absolute ref → field_player_model_id           = 0xCC162C
    +0x25  absolute ref → field_n_models                  = 0xCFF73E

SUB_40B27B = 0x40B27B
  +0x25  absolute ref  → word_CC1638 (movie-playing word) = 0xCC1638  (FFNx name ✓)
```

All other symbols are either hardcoded fixed addresses (confirmed from `externals_102_us.h` and `ff7.h`)
or read at runtime from opcode parameters. See §14 for a region-organized map of
every confirmed address — the clustering itself is a discovery tool.

### Confirmed Absolute Addresses (2013 Steam / 1.02 US)

| Symbol | Address | Source |
|--------|---------|--------|
| `current_dialog_string_pointer` (DIALOG_TEXT_PTRS) | `0xCBF578` | `ff7.h` |
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
| `TITLE_CURSOR` | `0x00DD6F24` | 0=New Game, 1=Continue — only valid on title screen; guard with FIELD_ID==0 |
| `NAME_ENTRY_COL` | `0x00DD4538` | u32, grid column 0–9 on the naming screen. Adjacent X/Y pair with ROW below (v2.8, live-confirmed 2026-07-12) |
| `NAME_ENTRY_ROW` | `0x00DD453C` | u32, grid row 0–6 (A–J / K–T / U–Z,.+- / a–j / k–t / u–z:;'" / 0–9) |
| `NAME_ENTRY_BUFFER` | `0x00DD45F0` | Name-in-progress, FF7-encoded, 0xFF-terminated, ≥9 chars capacity. ⚠ the first scan found 0xDD45F5 — that was just the first byte that CHANGED; the "Cloud" prefix masked F0–F4 until the Barret-screen handoff rewrote them |
| `NAME_ENTRY_CHAR_INDEX` | `0x00DD46F8` | Which character is being named: 0=Cloud, 1=Barret (flipped exactly at screen handoff). **This is the address the Echo mod hext patch mislabeled "cursor column"** — it never changes during grid navigation |
| `NAME_ENTRY_ACTIVE` | `0x00DD46FC` | 1 while a naming screen is open, 0 otherwise. Matched all three observed transitions (Cloud close, Barret open, final exit). Gate together with GAME_MODE==6 |
| `NAME_ENTRY_PANE_FLAG` | `0x00921ED4` | 0=cursor in letter grid, 1=cursor on side panel (v2.8.2, live-verified across 6 crossings). Lives in 0x92xxxx .data, NOT the DD block. Entering the panel can change the ROW byte (observed 1→4) — gate grid announcements on this flag |
| `NAME_ENTRY_PANEL_INDEX` | `0x00DD4574` | Side-panel button, valid only while PANE_FLAG==1: 0=Space 1=Delete 2=Select 3=Default (0/1 proven by name-buffer effects). Wraps 0↔3; retains last value after leaving the panel |
| `NAME_ENTRY_CARET` | `0x00DD46F0` | Caret position, clamped 0–8. Name hard cap = 9 chars; at cap Confirm replaces the last char |
| `MENU_CURSOR` | `0x00DC1154` | Main menu row 0–10 (Item…Quit); constant during field play |
| `MENU_OPEN` | `0x00DC12DC` | 1 when main menu, post-battle results, OR the naming screen is active; gate with FIELD_ID!=0 AND GAME_MODE!=6 (naming screen set it with FIELD_ID non-zero → false "Item" announce, fixed v2.8.3) |
| `CONFIG_ROW` | `0x00DC10F0` | Config sub-menu row 0–9 (Window color…Magic order); proxy gate: MENU_CURSOR==7 |
| `CONFIG_SPEED_BATTLE` | `0x00DC0E10` | Row 5 Battle speed — raw byte, 0=Fast → 255=Slow |
| `CONFIG_SPEED_MSG` | `0x00DC0E11` | Row 6 Battle message speed — raw byte, 0=Fast → 255=Slow |
| `CONFIG_PACKED_CURSOR_ATB` | `0x00DC0E12` | Packed byte: bit 4=Cursor (0=Initial/1=Memory); bits 7:6=ATB (0=Active/1=Recommended/2=Wait) |
| `CONFIG_PACKED_CAMERA_MAGIC` | `0x00DC0E13` | Packed byte: bit 0=Camera (0=Auto/1=Fixed); bits 4:2=Magic order index 0–5 (No.1–No.6) |
| `CONFIG_SPEED_FIELD_MSG` | `0x00DC0E24` | Row 7 Field message speed — raw byte, 0=Fast → 255=Slow |
| `SOUND_CURSOR` | `0x00DC108C` | 0=Music slider highlighted, 1=FX slider highlighted; inside Sound sub-menu only |
| `QUIT_CURSOR` | `0x00DC0FA0` | 0=Yes, 1=No inside Quit confirmation dialog |
| `FIELD_ID` | `0x00CC15D0` | s16, non-zero on named field maps, 0 on title/world. **Does NOT zero during battle** (live-corrected 2026-07-09; earlier belief wrong) |
| `G_ACTIVE_ACTOR_ID` | `0x00BE1170` | u8 slot of last-acting battle actor (0–2 party, 4–9 enemy); never resets between battles (v2.5) |
| `G_BATTLE_MODEL_STATE` | `0x00BE1178` | Per-actor battle array, stride 0x1AEC; commandID u8 at +0x23 (v2.5) |
| `G_SMALL_BATTLE_MODEL_STATE` | `0x00BF23B8` | Stride 0x74; its +0x3E "actionIdx" climbs like an animation counter when polled continuously, but AT FLASH TIME it holds the real ability id (FFNx passes it to the flash writer) — only sample it via the flash struct below |
| `BATTLE_ACTOR_DATA` | `0x00DC38E0` | FFNx ff7.h `battle_actor_data`; the old "KERNEL2_REQUEST" reading was its middle: +0x08 formation_entry (pending pulse), **+0x0C command_index (0xDC38EC), +0x10 action_index (0xDC38F0)** — written at FLASH TIME (~1–2s after turn start), not rewritten for repeated identical flashes (v2.7, live-verified 2026-07-11: Ice/Potion/Machine Gun/Tentacle) |
| `BATTLE_DISPATCH_BYTE_TABLE` | `0x006D70A8` | Static .text: byte[table+cmd] = flash-name branch for cmd 0x00–0x20; jump table at 0x6D7080. Branch→source: 0/1=magic names; 2=summon; 3/5=item namespace; 4=buffer 0xDC3640; 6=magic+72 (E.Skill); 7=magic+128 (Limit, 0x7F='????'); 8=enemy attack table; 9=no flash text (v2.7) |
| `ENEMY_ATTACK_NAME_TABLE` | `0x009A9484` | Current formation's enemy attack names from scene.bin, stride 0x20, FF7-encoded (v2.5 candidate → CONFIRMED v2.7; 'Machine Gun'/'Tonfa'/'Bite'/'Tentacle') |
| `GET_KERNEL_TEXT` | `0x0041963C` | The REAL get_kernel_text (= FFNx external; sub_41963C; kernel2_get_text=0x419457 at +0xF7). ⚠ Useless in battle: reads menu-module scratch (0x9A13C8 via u16 table 0x9A7FC8) which is EMPTY during battle. v2.7 reads the heap text sections directly instead |
| `KERNEL2_RESULT_PTR` | `0x00DC208C` | Written with the lookup result after every CALL 0x41963C in the consumer (disasm-confirmed) — but NEVER written under FFNx (consumer path replaced); observed 0 through all battles. Do not use |
| `MODULES_GLOBAL_OBJECT` | `0x00CC0D88` | Field module global struct; **PSX decomp struct (include/game.h ~370) matches field-for-field across +0x28..+0x3B** — PSX comments identify unnamed PC fields |
| `GAME_MODE` | `0x00CC0D89` | +0x01, u8. Live-observed: **0=field play, 2=battle, 6=name entry, 9=menu**. ⚠ FFNx's `ff7_game_modes` enum does NOT describe this byte (it's for a different variable) |
| `FIELD_UC_LOCK` | `0x00CC0DBA` | +0x32, u8. Player-control lock (field opcode UC); nonzero = scripted scene, input ignored. Via PSX struct match |
| `FIELD_BGMOVIE_FLAG` | `0x00CC0DC2` | +0x3A, u8. Movie is background-only (player walkable) |
| `FIELD_KEY_INPUT_STATUS` | `0x00CC0DF0` | +0x68, u32. Digested input: UP=0x1000 RIGHT=0x2000 DOWN=0x4000 LEFT=0x8000, Cancel/run=0x40. **Freezes at last value when battle starts** |
| `FIELD_EVENT_DATA_PTR` | `0x00CC0B60` | → per-model array, stride 0x88: model_pos 3×i32 at +0x0C, movement_speed u16 at +0x76. Observed target: static 0xCC1670 |
| `FIELD_PLAYER_MODEL_ID` | `0x00CC162C` | u16 player index into event-data array (player ≠ always model 0) |
| `FIELD_N_MODELS` | `0x00CFF73E` | u16 model count on current field |
| `FIELD_MOVIE_PLAYING` | `0x00CC1638` | u16 nonzero while movie plays on field. FFNx movie test: `word && !BGMOVIE_flag` |
| `BATTLE_MENU_STATE` | `0x0091EF9C` | u16, current battle menu widget — **LIVE-CONFIRMED 2026-07-12** (two runs, logs battle_menu_live_20260712_2136/2144): **1=command menu, 6=magic list, 24=limit select, 0=waiting/ATB AND post-Confirm targeting (with PREV=1), 0xFFFF=menu closed/turn executing**. 3=Change-row dispatch (fired on Right press). Statics: 5=item list (global inventory table), 7=summon list, 2=Defend dispatch — not yet crossed live. ⚠ targeting does NOT use state 19 in the normal flow |
| `BATTLE_MENU_PREV_STATE` | `0x0091EF98` | u16, written on every state transition (static 2026-07-12) |
| `BATTLE_MENU_FN_TABLE` | `0x0091E6B8` | uint32[64] per-state handler table (= FFNx battle_menu_state_fn_table; resolved from battle_sub_6DB0EE+0x1B4) |
| `BATTLE_ACTIVE_SLOT` | `0x00DC3C7C` | u8 party slot (0–2) whose battle menu is open; selects the widget block AND the char data block below (✓ live 2026-07-12, slot=0) |
| `BATTLE_MENU_BUSY` | `0x00DC35AC` | u32, 1 = menu transition/animation in progress; handlers skip input while set (static 2026-07-12) |
| `BATTLE_WIDGET_BLOCK` | `0x00DC20A0` | **THE BATTLE MENU CURSOR — LIVE-CONFIRMED 2026-07-12** (spoke Attack/Magic/Item correctly through two full battles). Per-slot block at +slot·0x700; 0x38-byte widget structs: +0x00 command widget, +0x38 state-5 (item) list, +0x70 state-6 (magic) list, +0xA8 state-7 (summon) list. Widget fields: +0 horiz cursor (LEFT/RIGHT), +4 vert cursor (UP/DOWN), +0x08 horiz wrap count, +0x0C visible rows, +0x14 scroll offset, +0x1C total entries, +0x28/+0x2C axis modes, +0x30 scroll-busy. Command menu: selected entry index = **row + col·4** (column-major, 4 rows/col, `and 3` wrap); col wraps mod u8[0xDBA4B9+slot·0x440]. List widgets: selected index = w0+w4+scroll (✓ live for magic list) |
| `BATTLE_CHAR_BLOCK` | `0x00DBA498` | Per-slot battle char data, stride 0x440. +0x21 = command column count; **+0x4C (0xDBA4E4) = command table**, 6-byte entries indexed row+col·4: u8[+0] command id, u8[+1] action type (Confirm jump-table selector 0–0xB), u8[+2] action id. **Command ids are 1-BASED for basic commands** (✓ live: 1=Attack, 2=Magic, 4=Item; 0xFF=empty cell) **but Limit keeps kernel id 0x14=20** (✓ live: replaces Attack's row-0 entry when the gauge fills; Confirm → state 24). +0x108 (0xDBA5A0) magic list (✓ live via state 6), +0x2C8 (0xDBA760) summon list, both 6-byte entries |
| `BATTLE_LIST5_TABLE` | `0x009AC354` | Global (not per-slot) 6-byte entries for the state-5 list = ITEM list (inventory is party-wide; the magic guess was wrong — magic is the per-actor state-6 table): u16[+0] entry id (0xFFFF=empty), u8[+3] → 0xDC3C84 on Confirm, u8[+4] enable-flag bits |
| *(list entry format)* | — | List entry u16 = **low byte action index + high byte flags** (✓ live: Ice showed 0x41E = spell 30 + flag 0x04; ISSUED_ACTION received 30 on Confirm — same index v2.7 logged for Ice). id 0 = empty/padding row |
| `BATTLE_ISSUED_CMD` | `0x00DC3C70` | u8 = FFNx issued_command_id (✓ live: 1 on Attack confirm, 2 on Magic, 19=0x13 on Right press = Change-row, 20 on Limit) |
| `BATTLE_ISSUED_ACTION` | `0x00DC3C78` | u16 = FFNx issued_action_id (✓ live: 30 after confirming Ice) |
| `BATTLE_TARGET_TYPE/INDEX` | `0x00DC3C90/94` | u8 pair = FFNx issued_action_target_type/index. INDEX tracks the moving target selection live (✓: 4↔5 across enemies, 0 = party slot 0) |
| `BATTLE_TARGETING_ACTOR` | `0x00DC3C98` | u8 = FFNx targeting_actor_id_DC3C98 — live target cursor actor id (✓ 2026-07-12: 4/5 = enemy slots, party 0–2). Updates during state-0 targeting after a Confirm |
| `BATTLE_FORMATION_SLOTS` | `0x009A8794` | Per-enemy-slot formation table, stride 0x10: u16 (movsx→signed, -1 = empty) = index into the loaded enemy records, indexed by enemy list index 0–5 (= actor slot − 4). From get_kernel_text SECTION 7 = the game's own target-name lookup (jump table 0x419A38, handler 0x4197D3; static disasm 2026-07-13, v2.10) |
| `BATTLE_ENEMY_RECORDS` | `0x009A8E9C` | The 3 loaded scene.bin enemy records, stride 0xB8 (= exact scene.bin record size); FF7-encoded display name = bytes 0–0x1F, 0xFF-padded but possibly UNterminated at 0x20 — the game copies max 0x20 then writes its own 0xFF (0x41999B); never Decode() in place (v2.10) |
| `BATTLE_DUP_LETTER_TABLE` | `0x009A8B1F` | Per-ACTOR-SLOT duplicate-name letter, stride 0x44: u8 index appended as FF7-char(dword[0x9AB070]+idx) → "MP A"/"MP B"; 0xFF = enemy type unique in formation. dword[0x9AB070] = encoded 'A' base (v2.10) |
| *(target-name extras)* | `0x9AB0E0/0x9A8B39` | From the v2.10 disasm, identities RESOLVED in v2.11 via BATTLE_ACTOR_VARS below: u32[0x9AB0E0+slot·0x68] = actor_vars stateFlags (+0x04), bit 0x40 → game appends kernel string 0x71 (unused); u8[0x9A8B39+slot·0x44] bit 0x40 = **SENSED display flag** → game formats "cur/max" HP from u16[0x9A8B4C+slot·0x44] (display-cached cur) + u16[0x9AB10C+slot·0x68] (= actor_vars maxHP low word) via kernel strings 0x7F/0x72. 0x9A80F0 = the game's target-name scratch buffer (write-on-render only — do NOT poll) |
| `BATTLE_ACTOR_VARS` | `0x009AB0DC` | FFNx battle_ai_context::actor_vars — per-actor battle stats, 10 slots × stride 0x68 (= sizeof battle_actor_vars). Static, two agreeing derivations (ff7_sense_hp_static.py, v2.11): (1) FFNx chain battle_context = u32 operand at 0x41CCB2+0x5F = 0x9AB0A0, actor_vars = +0x3C; the operand sits in "mov edi,0x9AB0A0 / rep stosd" — sub_41CCB2 is the battle-init memset whose OTHER memsets clear exactly the v2.10 formation/enemy-record regions; (2) section 7's reads land on named fields with this base. Key offsets: +0x04 stateFlags, +0x24 formationID (u16, = FFNx voice enemy_id), +0x28/+0x2A cur/max MP (u16), **+0x2C/+0x30 cur/max HP (i32)** — read the i32s, not the game's u16 display words (>65535-HP bosses truncate) |
| `BATTLE_SENSED_FLAG_TABLE` | `0x009A8B39` | u8 per actor slot, stride 0x44 (same display struct as the dup-letter byte); bit 0x40 = target window shows HP (set by Sense). v2.11 gates the enemy HP readout on it — exact info parity with the sighted window; party slots 0-2 speak HP unconditionally (party HP is always on-screen) |

---

## 5. Field File Buffer Architecture (Confirmed 2026-06-27)

**Dialog text is embedded in section 0 (the script section) of the field file.**

FF7 field files have 9 sections (indices 0–8). For the bombers_start field (confirmed by runtime DIAG logging):

| Section | Offset | Content |
|---------|--------|---------|
| 0 | 0x2A | **Script** — entity bytecodes + dialog text strings at the end |
| 1 | 0x17EA | Camera placement data |
| 2 | 0x183A | (empty/padding) |
| 3 | 0x1844 | Walkmesh / collision data |
| 4 | 0x2054 | Tile map |
| 5 | 0x22B4 | Encounter table |
| 6 | 0x43B0 | (empty) |
| 7 | 0x43E4 | **Background** ("blackb..." — background layer data) |
| 8 | 0x46CC | Triggers |

There is **no separate text section** in this field file. The dialog strings live at the end of section 0,
after all entity bytecodes. `field_text_box_window_create_631586` reads the text from within section 0
by `dialog_id` and stores the pointer in `DIALOG_TEXT_PTRS[window_id]`.

The buffer layout: `*(char**)0xCFF594 = buf`. Section table at `buf+6`: nine consecutive `uint32_t` values,
each an offset from buf start to the beginning of that section's block (including a 4-byte size prefix).
Section i data: `buf + *(uint32_t*)(buf + 6 + i*4) + 4`.

**`get_field_dialog_text()` behavior**: We implemented a function that searches all 9 sections for the
text section by validating the offset table format (`first_off` even, 2–2048 range, monotonically
increasing subsequent offsets). It skips section 0 (the script) by comparing against `field_script_ptr`.
In practice, every other section fails validation, so this function always returns nullptr and the rawptr
fallback handles all dialogs. The function remains as a correct no-op for fields that might have a
standalone text section.

**Rawptr validation**: `DIALOG_TEXT_PTRS[window_id]` points within the script section's data
(confirmed buf offsets 0xA43–0xC78 for bombers_start dialogs). Before using rawptr, we validate it
falls within `[field_buf, field_buf + 512KB)`. This prevents reading binary data from outside the
field buffer when the pointer is stale or corrupt.

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
- `0 → nonzero` or `7 → nonzero`: dialog starting — PRIMARY speak path
- `14 → 2` or `4 → 8`: page advance
- `any → 7`: dialog closing — reset `last_dialog_id`, silence TTS

The state machine works reliably for win=0 and win=1 but **never transitions for win=2 and win=3**
(state byte stuck at 0 perpetually). Those windows rely entirely on the dialog_id tracking path.

### Two-Frame Delay

`field_text_box_window_create_631586` runs *inside* `s_old_message()`, which we call *after* reading
the text pointer. So on frame N (when `dialog_id` first changes), `DIALOG_TEXT_PTRS[window_id]` is
still stale from the previous dialog. On frame N+1, `s_old_message()` has run and the pointer is valid.

The DLGID fallback path handles this naturally: frame N fails (`rawptr` invalid or 0xFF), does NOT
update `last_dialog_id`; frame N+1 tries again, succeeds, speaks, updates `last_dialog_id`. The state
machine START path (win=0/1) works because the 0→1 transition happens one frame after 7→0, by which
time the previous frame's `s_old_message()` has already set the new dialog's rawptr.

### Preventing Duplicate Speaks

Without a guard, both PRIMARY (state machine) and DLGID paths could fire for the same dialog:
- DLGID fires on frame N (state=0, new `dialog_id`), speaks, sets `last_dialog_id`
- PRIMARY fires on frame N+1 (0→1 transition), would speak again without a guard

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
0x00–0xDF  :  byte + 0x20  =  encoded character
               (0x00 = space, 0x21 = 'A', etc.)
               NOTE: bytes 0x5F–0xDF map to extended Latin (U+007F–U+00FF),
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
0xEB–0xF0  :  mid-string dynamic token — 4 bytes total (type byte + 3 data bytes)
               placeholder: [item name], [number], [target], [attack], [special], [target letter]
0xF8       :  formatting skip — consume this byte + 2 data bytes (3 total)
0xFF       :  end of string
```

### Speaker Token Detection

The first byte of a dialog string can be a character name token (0xEA–0xF2), indicating the speaking
character. We detect this by tracking `at_start`: if the very first byte is in that range, we emit
`"CharName: "` before the dialog text. Mid-string appearances of these same bytes are inline name
references (Cloud, Barret) or 4-byte dynamic tokens (0xEB–0xF0).

The 4-byte mid-string dynamic token is the key distinction: 0xEB at position 0 = "Barret:" speaker,
0xEB mid-string = `[item name]` placeholder (4-byte token). Missing this caused the `ö­ùBarret`
prefix garbage in early builds.

### Extended Character Problem (Temporary Fix)

Bytes 0x5F–0xDF add 0x20 and land in the Unicode extended Latin range (U+007F–U+00FF). FF7's bitmap
font renders completely different glyphs at those positions — the mapping is *wrong* for what the screen
reader will say. Examples:
- 0xB5 → U+00D5 'Õ', but FF7 renders `'` (apostrophe) → "I'm" becomes "I Õm"
- 0xB2 → U+00D2 'Ò', but FF7 renders `"` (left quote)
- 0xB3 → U+00D3 'Ó', but FF7 renders `"` (right quote)
- 0x82 → U+00A2 '¢', but FF7 renders `-` (hyphen)

**Temporary fix (current)**: ASCII filter — strip everything outside U+0020–U+007E, replace with a
single space to preserve word boundaries. Apostrophes become spaces ("I'm" → "I m"), which is
sub-optimal but prevents garbled speech.

**Permanent fix needed**: A lookup table mapping each FF7 byte 0x5F–0xDF to the correct Unicode
character. The table must be derived from the actual FF7 font texture / character set documentation.

### 3-Byte Window Header Codes

Some dialogs begin with `0xD6 ?? 0xD9` — FF7 window-formatting control bytes. These decode to
extended Latin characters under byte+0x20 and appear before the speaker token, breaking speaker
detection (`at_start` becomes false before the 0xEA–0xF2 check). The ASCII filter currently strips
these silently. A proper fix would require detecting and skipping bytes in the 0xD0–0xDF range at
position 0.

---

## 8. Build History

### v1.0 (2026-06-24) — First compile; crashed immediately

- Proxy: `winmm.dll`, 168 exports, 220 KB
- Crash cause: FFNx's `ff7_find_externals` uses `GetModuleHandle("winmm.dll")` as an anchor for
  machine code analysis. Got our naked JMP stub instead of real winmm code; invalid bytes caused
  `0xC0000005` access violation.
- Also: address readiness check `< 0x9FFFFF` was too narrow; FFNx-patched addresses (0x69xxxxxx)
  would never pass, so hooks would install prematurely.

### v1.1 (2026-06-24) — Switched to `version.dll`; still crashed

- Proxy: `version.dll`, 17 exports, 205 KB
- Crash cause: background thread's 200ms sleep was not long enough. Our hooks were installed *before*
  FFNx's `voice_init()` ran. FFNx then read our hook from the table and walked our x86 prologue as if
  it were the original opcode handler code, crashing inside `get_absolute_value`.

### v1.2 (2026-06-24) — Fixed FFNx timing race; first successful run

- `Resolve()` now waits for `execute_opcode_table[0x40]` to be in DLL address space (> 0x9FFFFF),
  which only happens after FFNx's `voice_init()` has patched the entry. Without FFNx, any value
  ≥ 0x401000 is accepted immediately.
- First confirmed TTS output: field dialog spoken via NVDA.

### v1.3 (2026-06-26) — First real-game test; chunking and duplicate bugs identified

- `starting` condition only checked `last==0`, missed the `last==7` reuse case. Windows reused
  directly from closed (state=7) to new dialog fired no "starting" event; subsequent dialogs on
  that window were all missed.
- Fix: `starting = ((last==0 || last==7) && current!=0 && current!=7)`.
- Debounce threshold set too high → some dialogs silenced. Removed debounce in favor of dialog_id
  tracking.

### v1.4 (2026-06-26) — Dialog ID tracking; win=2 still silent

- Introduced `last_dialog_id` per window. Replaced debounce with "speak when dialog_id changes."
- win=2 (Barret, Jessie lines): state machine stuck at 0 permanently → `starting` never fired →
  all win=2 dialogs silently dropped.
- Fix: added DLGID fallback that fires whenever `dialog_id != last_dialog_id`, regardless of state.

### v1.5 (2026-06-26) — Duplicate speak bug fixed; win=2 restored

- Duplicate root cause: DLGID fired on the state=0 frame (before START), set `last_dialog_id`.
  Then START fired on the 0→1 frame, `dialog_id == last_dialog_id` was FALSE (forgot DLGID had
  already spoken it), so PRIMARY spoke again.
- Fix: PRIMARY path checks `dialog_id != last_dialog_id` before speaking. DLGID guard now works
  bidirectionally.
- Added `rawptr` fallback in DLGID path: if field text section returns nullptr, try
  `DIALOG_TEXT_PTRS[window_id]`.

### v1.6 (2026-06-27) — ASCII filter; garbage block; section diagnostic

- Added ASCII filter at end of `FF7Text::Decode()`: strip everything outside U+0020–U+007E,
  replace with space. Eliminated garbled TTS from extended Latin characters and window-header codes.
- Added DIAG logging: sections 7 and 8 structure. Confirmed section 8 is NOT the text section
  (`first_off=0`, bytes `00 00 01 00 01 50`). Section 7 is background data (`first_off=27746`,
  bytes "blackb..."). Both fail validation. `get_field_dialog_text` always returns nullptr.
- win=3 TUTOR window: garbage rawptr (reading binary data) produced a large block of junk TTS.
  Filtered by ASCII filter to empty string → not spoken → win=3 silent.

### v1.7 (2026-06-27) — All field dialogs working; garbage block fixed

- Expanded DIAG to all 9 sections + rawptr offset logging. Confirmed dialog text is in section 0
  (script section). All rawptr values (buf_off 0xA43–0xC78) land within section 0's data range.
- `get_field_dialog_text()` updated to search all 9 sections instead of hardcoding section 8.
  Skips section 0 (script) explicitly. Monotonicity validation on first 4 offsets rejects all
  other sections. Still always returns nullptr — rawptr remains the only source.
- Rawptr bounds check: validate rawptr ∈ `[field_buf, field_buf+512KB)` before use. Garbage win=3
  pointer (which previously passed `is_readable_ptr` and decoded to junk) now rejected if it falls
  outside the field buffer.
- All dialogs in the opening mission now spoken correctly, including the previously-missing Barret
  "The hell you all doin'!?" (win=3 id=13, caught via DLGID two-frame delay path).
- DIAG logging reduced to one summary line. Diagnostic SAMEID branch removed after confirmation.

### v2.7 (2026-07-11) — Battle action TTS: exact names replace generic labels

Investigation chain (all scripts + logs in `investigate/`):
1. `ff7_kernel2_result_verify.py`: the doc'd result pointer 0xDC208C stays 0 through
   every battle action — FFNx replaces the whole flash-text consumer path, so the
   original `mov [0xDC208C], eax` stores never execute. Dead end confirmed live.
2. FFNx source (battle.cpp/voice.cpp): the "kernel2 request struct" is actually FFNx's
   `battle_actor_data` (0xDC38E0) — command_index/action_index written at FLASH time.
3. `ff7_kernel2_consumer_disasm.py` + `ff7_kernel2_dispatch_map.py`: full static
   derivation of dispatcher sub_6D1CC0's cmd→branch→section mapping, get_kernel_text
   (=sub_41963C) internals, and the bias tables (magic file entries: 0–55 spells,
   56–71 summons, 72–95 E.Skills, 128+ limits).
4. `ff7_kernel2_table_probe.py`: get_kernel_text's static scratch (0x9A13C8) is ALL
   ZERO in battle — explains why blanks came back; the text really lives in a heap
   block (`ff7_name_memory_scan.py`), with NO stable static anchor
   (`ff7_kernel2_anchor_chain.py` / `ff7_kernel2_section_ptrs.py`).
5. `ff7_action_name_final_verify.py`: signature-scan + walk-back rule
   (`u16[base] == distance-to-first-string`) locates magic/item/weapon sections;
   live battle resolved 'Tentacle', 'Machine Gun', 'Potion', 'Ice' — all exact.

Implementation (BattleActionThread v2.7 in proxy.cpp):
- Turn detection unchanged (actor change + commandID≠0).
- Name-bearing commands defer the announce until battle_actor_data changes (flash
  appeared) or 2.5s timeout; struct-cmd must match model-cmd or the generic v2.5
  label is used — degraded, never wrong. Branch-9 commands (plain Attack, Steal)
  announce generic labels immediately (they never flash).
- Kernel2 sections found by one in-process signature scan (lazy, retry ≤1/min).
  English-only signatures; other languages fall back to generic labels entirely.
- Limit names carry a leading F8+param colour code — skipped locally (the dialog
  decoder's single-byte 0xF8 handling is correct for dialog, wrong for these).

### v2.9 (2026-07-12) — Battle menu navigation TTS (the battle cursor, solved)

The battle command-menu cursor — unsolved through three live-scanning sessions —
fell to static analysis in one session. Full derivation in §14 (battle module
block note) and §4 (BATTLE_* entries); investigation scripts
`ff7_battle_menu_static.py`, `ff7_battle_menu_handler_disasm.py`,
`ff7_battle_menu_submenu_disasm.py`, live verify
`ff7_battle_menu_cursor_live_verify.py` (two battles, user-confirmed:
"I think that's got it").

Implementation (BattleMenuThread in proxy.cpp, 50ms poll, gated on new config
key `speak_battle_menu`):
- **Command menu (state 1)**: speaks the command under the cursor on every
  (slot,col,row) change AND on menu open (state entry invalidates the key, so
  the landing command speaks immediately — that is the "your turn" cue).
  Names resolve via a NEW kernel2 section — command names, signature
  `"Attack|Magic|"` — at entry id-1 (ids are 1-based); Defend (0x12),
  Change-row (0x13), and Limit (0x14, unshifted) are hardcoded ahead of the
  lookup; GenericActionLabel is the final fallback. Empty cells (0xFF) stay
  silent: the game's own nav skips them, we only ever read one mid-move.
- **Lists (states 5/6/7)**: selected index = w0+w4+scroll; the entry's u16
  packs action index (low byte) + flags (high). The name section is chosen by
  the command that OPENED the list (BATTLE_ISSUED_CMD → dispatch branch →
  ResolveActionName), reusing the entire v2.7 machinery including the
  item/thrown-weapon namespace split. Unknown commands degrade to "row N".
- **Targeting**: armed only on a menu-state→0 transition (state 0 is also
  plain ATB wait — prev-state gating is the difference between "target cursor"
  and silence), disarmed on 0xFFFF/new menu/battle exit. Speaks target labels
  on TARGET_INDEX (0xDC3C94) change: leader name for slot 0, "ally N"/
  "enemy N" positionally. Real enemy names (scene.bin): DONE in v2.10 below.
- Kernel2 scan now guarded by an interlocked busy flag — two threads
  (BattleActionThread + BattleMenuThread) can trigger it lazily; duplicate
  concurrent walks are wasteful though harmless, so one runs and the other
  skips to its rate-limited retry.

### v2.10 (2026-07-13): Real enemy names in battle announcements

**USER PLAY-TEST CONFIRMED 2026-07-13** (same pass also confirmed v2.9's
command menu and submenus): enemy names with duplicate-letter suffixes spoken
correctly in-game.

Target selection and enemy-turn announcements now speak the actual enemy name
("Guard Hound", "MP A") instead of positional "enemy N"/"enemy" labels — for
both BattleMenuThread targeting and BattleActionThread turn announces, via a
shared `EnemySlotName()` helper in proxy.cpp.

**Derivation — fully static, no live scan needed**: the 2026-07-11 consumer
disasm had dumped the first half of an unexplained branch inside get_kernel_text
(sub_41963C); `ff7_target_name_disasm.py` (2026-07-13) completed it and printed
the section jump table at 0x419A38, which proved sections 6–9 are the BATTLE
text sections: 6 = summon-attack names, **7 = TARGET NAMES (handler 0x4197D3)**,
8 = item-namespace, 9 = enemy-attack names (0x9A9484, matching v2.7). Section 7
is the exact code the on-screen targeting window renders from, so its tables
are authoritative by construction:

```
record = movsx( u16[0x9A8794 + enemy_idx*0x10] )   ; enemy_idx = actor slot − 4
name   = 0x9A8E9C + record*0xB8, bytes 0–0x1F       ; 0xB8 = scene.bin record
letter = u8[0x9A8B1F + actor_slot*0x44]             ; 0xFF = unique, else
append FF7-char( dword[0x9AB070] + letter )          ; "MP A" / "MP B"
```

Implementation notes: record −1/out-of-range (scene holds 3 records) or a
blank decoded name falls back to the old generic labels; the name field can
occupy all 0x20 bytes with NO 0xFF terminator, so it is decoded per byte via
`FF7Text::DecodeChar` under the length cap (the game itself copies max 0x20
then writes its own terminator at 0x41999B) — never `Decode()` the record in
place. Party slots are untouched by section 7 (idx ≥ 6 returns the empty
default), so leader-name/"ally N" labels stay; party members 2/3 by name
remain a follow-up. Bonus finds documented in §4/§14: per-actor Sensed flag +
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

**Derivation — fully static again** (`ff7_sense_hp_static.py`): the missing
piece from v2.10 was WHICH battle struct the Sense path's HP word `0x9AB10C`
belongs to. FFNx's own resolution chain (`battle_context =
get_absolute_value(battle_sub_41CCB2, 0x5F)`) read off the exe gives
`battle_context = 0x9AB0A0` → `actor_vars[0] = +0x3C = 0x9AB0DC`, stride
0x68 = exact `sizeof(battle_actor_vars)` from FFNx ff7.h. Cross-checks that
all landed: the operand sits inside `mov edi, 0x9AB0A0 / rep stosd` —
sub_41CCB2 is the battle-state init memset, and its sibling memsets clear
exactly the v2.10 regions (formation slots, enemy records, attack names);
and with this base, section 7's two unexplained reads become named fields
(`0x9AB0E0` = stateFlags+0x04, `0x9AB10C` = maxHP+0x30 low word — so the
window's "cur/max" takes cur from the display struct's u16 cache at
`0x9A8B4C+slot·0x44` and max from actor_vars).

The mod reads the full i32 `currentHP`/`maxHP` pair at +0x2C/+0x30 instead
of the game's u16 display words (Ruby/Emerald-class HP would truncate), and
gates on the Sensed flag byte `u8[0x9A8B39 + slot·0x44] & 0x40` for enemies
— exact information parity with the sighted window. Plausibility gate
(max in (0, 10M], 0 ≤ cur ≤ max) drops garbage during battle init. MP
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
   cur > 0, no Death bit) — battle-init memset zeroes and empty formation
   slots can therefore never false-positive; the tracker resets whenever
   GAME_MODE leaves 2 (between battles). Names via v2.10's EnemySlotName
   with "enemy N" fallback. Bonus static confirmation this session: PSX
   decomp battle.h `SceneEnemy \ size:0xB8` matches the v2.10 enemy-record
   stride exactly.

**v2.12.1 fix — defeats must speak in a QUIET GAP, not at detection.** The
first play test heard no defeats; the debug log showed detection perfect but
the speech cancelled within the same millisecond: the killing blow's tick
also fires action announcements (pending-flash resolution + next-turn), and
their interrupt=true wipes queued speech — every time, reproducibly (two
kills, two identical traces). Detected defeats now accumulate in a pending
string and speak (interrupt=false) once no thread has issued ANY speech for
600ms (new cross-thread stamp `TTS::LastSpeakTick()`), with a 5s overdue cap
and an immediate flush on leaving battle so a battle-ending kill is never
dropped. General lesson recorded: **any low-priority battle announcement
must use this quiet-gap pattern** — the battle threads' interrupt=true
bursts arrive in same-tick clusters. (Same trace also showed the phase-2
flush "MP B, attacks" being instantly clobbered by "Cloud, Attack" — the
pending-flush announce is inaudible in this collision case; noted as a known
polish item, not fixed here.)

---

## 9. Menu and Config TTS (v2.0–v2.3, 2026-07-01–02)

### Overview

Menu TTS does not use opcode hooks. The field script VM is frozen while any overlay is open, so
there are no MESSAGE or ASK opcodes to intercept. Instead, we use background polling threads that
read BSS addresses every 150ms and speak on changes. All threads share a manual-reset stop event
(`g_cursor_stop_event`) so a single `SetEvent()` in `Shutdown()` wakes them all cleanly.

### Address discovery methodology

For each menu feature, we wrote a Python investigation script using `ctypes.ReadProcessMemory` over
the full 0x00400000–0x00DE0000 BSS range:

- **Isolate scan** (title cursor, menu cursor, config row, config values): take two snapshot passes
  with the game in different states, subtract the idle-noise pass from the nav pass. Addresses that
  only changed during active navigation are candidates.
- **Symmetric toggle scan** (MENU_OPEN): three snapshots A→B→A (closed→open→closed). Candidates
  are addresses that changed A→B and reverted B→C.
- **Delta scan** (Sound sub-menu cursor, SOUND_CURSOR): take a baseline snapshot, guide the user
  through exactly N button presses via a beep countdown, take a second snapshot. Search for
  addresses where `(snap_b - snap_a) == ±N` (signed byte delta). Designed to filter out the audio
  subsystem noise that contaminates the isolate scan when the Sound sub-menu is open. For the cursor
  (0=Music / 1=FX), N=±1 suffices; two full Down+Up rounds × 2 intersected to one confident address.
- **Beep countdown** (timing-critical scans): `winsound.Beep(freq, ms)` is **synchronous** — it
  blocks until the tone finishes. This makes pre-snapshot timing deterministic unlike SAPI, which
  fires asynchronously and returns immediately. Pattern: three 800 Hz warning tones (200ms each, 1s
  period) then one 1400 Hz press tone (400ms); user presses ON the high beep; script waits SETTLE_S
  (1.5s) after the high beep before snapshotting. An `input()` prompt + 3s pre-countdown delay lets
  the user switch focus to FF7 before beeps start.

All scripts tee stdout to a timestamped log file automatically (Tee class wrapping sys.stdout).
All instructions are spoken aloud via a fire-and-forget PowerShell SAPI subprocess so the terminal
can stay in the background while FF7 is in focus.

### Confirmed addresses (2026-07-01–03)

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
| `0x00DD46F0` | NAME_ENTRY_CARET | ff7_name_entry_panel_probe.py (tracked 5→8 during appends) |

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
0,4,8,12,16,20 (step=4, stored in bits 4:2) confirming 6 distinct choices (No.1–No.6).

### Sound sub-menu investigation (2026-07-03)

**Isolate scan failure**: Opening the Sound sub-menu activates the audio subsystem (FFNx/SoLoud
sample streaming), flooding the BSS region with constantly-changing timer and buffer bytes. The
idle-phase baseline is immediately contaminated, producing ~47 false candidates for Music volume.
Ruled out the isolate scan approach entirely for this sub-menu.

**Volume address scan via FFNx DLL range**: FFNx's `dotemuRegSetValueExA` (not a real Windows
registry call — FF7 routes all `RegSetValueExA` calls through this FFNx function) stores
`external_music_volume` and `external_sfx_volume` as global `long` variables deep in AF3DN.P's
address space (~27MB into the DLL). To find them, `ff7_sound_submenu_scan.py` was extended with
`CreateToolhelp32Snapshot`/`MODULEENTRY32` to enumerate AF3DN.P's actual load range and scan it
alongside BSS. Found one Music candidate at +0x1DA2A68 from AF3DN.P base (Before=0, After=236).

**Audio ring buffer false positive** (`ff7_sound_verify.py`): A live monitor polling ±32 bytes
around the scan candidate at 200ms intervals revealed that the entire region is SoLoud's audio
engine streaming ring buffer. Every byte churns with random values every 200ms regardless of any
user input. The Before=0/After=236 result was a coincidence — the byte happened to be 0 at
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
DC10xx structure. First attempt with SAPI countdown failed — "press now" finished too late for
the post-press settle window to capture valid data (Up-pass found zero results both rounds). Fixed
by replacing SAPI with `winsound.Beep()` (synchronous), adding `input()` prompt + 3s delay.

### False candidates and rejected approaches

**QUIT_OPEN (0x00DC0FB1)**: Confirmed 0→1 when the Quit dialog opens, but does NOT return to 0
when dismissed with No. Gating MenuCursorThread's quit-dialog handler on this flag caused it to
loop in the handler indefinitely, silencing the main menu. Not used; QUIT_CURSOR is polled without
a gate instead.

**0x009A8729**: Top candidate for Battle message speed in the isolate scan (count=highest, last=0).
Identified as a button-transient address — changes when any directional button is held, regardless
of which row is active. The real address (DC0E11, rank 5 in the scan) was confirmed by the verify
script showing DC0E11 changing exclusively during row 6.

**0x6B852A68 (+0x1DA2A68 in AF3DN.P)**: Top candidate from the FFNx-range delta scan for Music
volume. Appeared to change from 0 to 236 during the scan window. Confirmed false positive by
`ff7_sound_verify.py`: the entire ±32-byte region is SoLoud's audio engine streaming ring buffer;
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
- Voice acting (FFNx) and TTS coexist — hook chain passes through both
- Config file: `speak_dialog`, `speak_choices`, `interrupt`, `speak_menus` toggles
- No duplicate speaks; no garbage TTS blocks
- ASCII filter: printable ASCII only; word boundaries preserved
- Title screen cursor TTS: "New Game" / "Continue" on each Up/Down press
- Main menu cursor TTS: option name (Item/Magic/Equip/…/Quit) on each Up/Down press
- Quit confirmation cursor TTS: "Yes" / "No"
- Config sub-menu row TTS: row name on Up/Down + current value on row entry and Left/Right changes
  - Toggle rows (Cursor, ATB, Camera, Magic order): option name spoken
  - Slider rows (Battle speed, Battle message, Field message): numeric value spoken
  - Rows 0/1/2 (Window color, Sound, Controller): row name only (value addresses not yet found)
- Sound sub-menu cursor TTS: "Music volume" or "FX volume" on Up/Down within the Sound sub-menu
  (Config row 1 → Confirm). Announces slider name on each cursor change; if the cached volume is
  known it is appended (e.g., "Music volume, 100"). Numeric value from Left/Right not yet functional.
- Battle action TTS with exact names (v2.7): "Cloud, Ice" / "Cloud, Potion" / "enemy, Machine Gun" —
  the flash-message text — for Magic/Summon/Item/E.Skill/Limit/enemy attacks; generic labels
  ("Attack", "Steal") for commands with no flash text, and as fallback on any resolution failure.
  Wall-bump navigation tone (v2.6) on dead-stop wall contact during field play.

### Known Issues / Limitations

| Issue | Severity | Fix |
|-------|----------|-----|
| Apostrophe → space ("I'm" → "I m") | Moderate | Needs proper byte→char lookup table |
| Other extended chars garbled (curly quotes, em-dash, etc.) | Moderate | Same lookup table |
| Speaker detection broken when 3-byte window header precedes speaker token | Minor | Detect/skip 0xD0–0xDF at position 0 |
| Dynamic token placeholders spoken literally ("[item name]") | Minor | Resolve tokens from script banks |
| "X <" artifact occasionally in ASK output | Minor | ASK formatting codes not yet filtered |
| Sound sub-menu volume value (Left/Right) not announced | Moderate | IAT hook on dotemuRegSetValueExA not functional — likely GetProcAddress at runtime; TODO v2.5 |
| Config menu entry does not re-announce row if last session ended on row 0 | Minor | Need CONFIG_OPEN flag or entry detection |

### Not Yet Implemented

| Feature | Hook Point / Approach |
|---------|----------------------|
| Sound sub-menu volume value TTS (Left/Right) | IAT hook on `dotemuRegSetValueExA` implemented but non-functional (v2.4). Alt: hook `GetProcAddress` call for this fn, or find `external_music_volume`/`external_sfx_volume` in a stable AF3DN.P data section |
| ASK per-option TTS as cursor moves | `opcode_ask + 0x8E` → inner loop; needs FF7 original opcode_ask address |
| Item/Magic/Equip/Status/Order/Limit sub-menu cursors | Isolate scan within each sub-menu |
| Main menu unlockable slots 6 and 8 | Identity TBD — not yet encountered in-game |
| Battle turn announcement | `battle_set_do_render_menu_call` — but BATTLE_MENU_STATE 0→1 transition + ACTIVE_SLOT (2026-07-12) is likely the cleaner poll-based signal |
| ~~Battle menu cursor TTS~~ | **DONE v2.9 (2026-07-12)** — BattleMenuThread; see §8 v2.9 entry. Remaining battle-menu polish: ~~real enemy names in target announcements~~ (DONE v2.10), ~~Sense HP readout during targeting~~ (DONE v2.11), ~~enemy defeat announcements~~ (DONE v2.12, 2026-07-13), limit/E.Skill/W-command list widgets (states 0x14/0x18/0x1A/0x1B, 26/27), list-entry disabled-flag announce (u8[entry+4] bits), party-KO announcements (same watcher pattern as v2.12, slots 0-2) |
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
| `update_display_text_queue` / `add_text_to_display_queue` addresses | Battle MESSAGE text TTS ("Cloud gained a level", enemy dialogue) — distinct from the v2.7 action-name flash | FFNx chains: `add_text_to_display_queue = get_relative_call(battle_sub_42CBF9, 0x1C7)`; queue array = `get_absolute_value(add_text, 0x25)`, 64×6-byte entries {s16 buffer_idx, s16, u8 wait, u8 frames}; text = kernel2 battle-text section entry buffer_idx (accessors 0x419442 / 0x41D2E5 for idx≥256) |
| FF7 byte 0x5F–0xDF → correct Unicode | Extended character lookup table | FF7 font texture / Makou Reactor character table |

---

## 12. FF7 Text Encoding — Byte Lookup Table (Partial)

Confirmed mappings based on in-game observation:

| Byte | FF7 Renders | Current Output (byte+0x20) | Correct Unicode |
|------|------------|---------------------------|-----------------|
| 0x00 | (space)    | U+0020 space ✓            | U+0020          |
| 0x21 | A          | U+0041 A ✓                | U+0041          |
| 0x27 | G          | U+0047 G ✓                | U+0047          |
| 0x3F | ?          | U+005F _ (wrong: prints as space in ASCII filter) | U+003F ? |
| 0x80 | à / special| U+00A0 nbsp (stripped)    | TBD             |
| 0x82 | - (hyphen) | U+00A2 ¢ (stripped)       | U+002D          |
| 0xB2 | " (left)   | U+00D2 Ò (stripped)       | U+201C          |
| 0xB3 | " (right)  | U+00D3 Ó (stripped)       | U+201D          |
| 0xB5 | ' (apos)   | U+00D5 Õ (stripped)       | U+0027          |
| 0xB4 | ' (left)   | U+00D4 Ô (stripped)       | U+2018          |

The full table (0x5F–0xDF) needs to be derived from the FF7 PC US font texture or sourced from
Makou Reactor's character encoding documentation.

---

## 13. Source Reference

- **`FFNx/src/voice.cpp`** — complete dialog + battle hook template; our hooks are a TTS-only subset
- **`FFNx/src/externals_102_us.h`** — all hardcoded absolute addresses for 2013 Steam exe
- **`FFNx/src/ff7_data.h`** — dynamic address discovery chains (authoritative reference)
- **`FFNx/src/ff7.h`** — game data structure declarations with commented addresses
- **`FFNx/src/field/opcode.h`** — full FieldOpcode enum (246 opcodes)
- **`FFNx/src/field.h`** — `get_field_parameter` implementation (opcode parameter reading)
- [Makou Reactor](https://github.com/myst6re/makoureactor) — field editor; source reference for field file format
- [FF7 Field Script Opcodes](https://wiki.ffrtt.ru/index.php/FF7/Field/Script/Opcodes) — opcode reference
- [FF7 Savemap](https://wiki.ffrtt.ru/index.php/FF7/Savemap) — save file layout (live addresses derived from base 0xDBFD38)
- [Tolk](https://github.com/ndarilek/tolk) — screen reader abstraction library

---

## 14. Memory Region Map — Running Analysis

Every address this project has confirmed, organized spatially instead of by feature.
The clustering is itself a discovery tool: FF7 statically allocates each engine
module's globals in a contiguous block, so **a new unknown for module X is almost
certainly within a few KB of module X's known addresses** — start every new scan
there before falling back to full-memory delta scans. This section should be
extended every time a new address is confirmed.

Proven payoffs of cluster reasoning so far:
- `FIELD_PLAYER_MODEL_ID` (0xCC162C) landed 0x5C bytes after `FIELD_ID` (0xCC15D0).
- `SOUND_CURSOR`, `CONFIG_ROW`, `MENU_CURSOR` were all found within 0xD0 bytes of
  each other after the first menu address anchored the region.
- The `modules_global_object` struct at 0xCC0D88 matches the PSX decomp's struct
  field-for-field (+0x28..+0x3B verified), so PSX decomp comments name PC bytes
  that FFNx leaves as `field_XX` — this is how the UC control lock was found
  without any scanning.

### Code (.text): 0x401000 – 0x9FFFFF

| Address | Symbol | Notes |
|---------|--------|-------|
| `0x40B27B` | sub_40B27B | anchor for movie-playing word (+0x25) |
| `0x41963C` | sub_41963C = **get_kernel_text** (FFNx external, confirmed via kernel2_get_text call at +0xF7) | `(section, idx, 8)`; result → 0xDC208C; reads menu scratch 0x9A13C8 — EMPTY in battle |
| `0x419457` | kernel2_get_text | `base = 0x9A13C8 + u16[0x9A7FC8 + file*2]; text = base + u16[base+idx*2]` |
| `0x6D1CC0` | flash-name dispatcher | branch tables 0x6D7080 (jump) / 0x6D70A8 (byte, per cmd 0x00–0x20); per-branch sections in §4 |
| `0x6D70F1` | enemy-attack name copier | branch 4 (cmd 0x07) → buffer 0xDC3640 |
| `0x7B7488/8A/98` | item-namespace remap tables | idx<128→items, <256→weapons(−128), <288→armor, <384→accessory |
| `0x7B74A0` / `0x7B74A8` | section bias / section→file tables | biases {0,56,72,128} map sections 0–3 into ONE magic-names file: 0–55 spells, 56–71 summons, 72–95 E.Skills, 128+ limits |
| `0x42782A` | display_battle_action_text | FFNx trampolines this — do not hook |
| `0x60BACF` | field_init_event | PRIMARY ANCHOR: +0x80→execute_opcode, +0x20→modules_global_object, +0x1C→field_global_object_ptr |
| `0x60C683` | execute_opcode | +0x10D → opcode table |
| `0x614E3E` | opcode_canm1_canm2 (table[0xB1]) | +0xC1 → field_event_data_ptr |
| `0x630D50` | opcode MESSAGE update loop | +0x12 → dialog state array |
| `0x6310A1` | opcode ASK update loop | v2 hook target |
| `0x6342C6` | field_update_models_positions | +0x45D→player_model_id, +0x25→n_models |
| `0x63C17F` | field_loop | +0x5DD → field_update_models_positions |
| `0x6D71FA` | kernel2 request writer | stores section/idx to 0xDC38E8; returns void; FFNx-trampolined |
| `0x6CE8B3` | battle_menu_update (FFNx name) | per-frame battle menu tick; +0xD9 CALL → 0x6DB0EE (FFNx trampolines THIS call site — hook wary) |
| `0x6DB0EE` | battle menu state dispatcher | +0x1B4 → fn table 0x91E6B8; +0x276 → battle_actor_data 0xDC38E0; +0x1F9 CALL → 0x6E6291; +0x50E CALL → dispatch_chosen_battle_action 0x6D86D2 |
| `0x6D8C75` / `0x6D91FA` | state 0 (actor ready) / state 1 (command menu) handlers | state 1 is where the command cursor logic lives; Confirm jump table at 0x6D97F7 |
| `0x6D98E3` / `0x6D9B98` / `0x6DA072` | state 5/6/7 list handlers | magic-shaped/per-actor lists; widget ptr = 0xDC20D8/0xDC2110/0xDC2148 + slot·0x700 |
| `0x6F4DB2` | shared widget navigation helper | takes widget ptr arg; ALL cursor inc/dec/wrap/scroll logic — cursor ops are [reg+disp], invisible to absolute-operand scans |
| `0x6E5C52` | set_battle_targeting_data (FFNx) | +0x14E/+0x164 → target type/index globals |
| `0x6E6291` | battle_update_targeting_info (FFNx) | +0x684 → targeting_actor_id 0xDC3C98 |
| `0x6D72E9` / `0x6D1CC0` | kernel2 request consumer / dispatcher | real CALL to 0x41963C at 0x6D72C6 |
| `0x6E97E0` | build_dialog_window | |
| `0x75EE86` / `0x75EEBB` | world MESSAGE / ASK | world module is adjacent code (0x75xxxx) |

Pattern: field module code sits in 0x60xxxx–0x6Exxxx, world map in 0x75xxxx,
battle UI text in 0x42xxxx, shared low-level services in 0x40–0x41xxxx.

### Static data (.data): 0x900000 – 0x9Fxxxx

| Address | Symbol | Notes |
|---------|--------|-------|
| `0x9055A0` | execute_opcode_table | uint32[256] |
| `0x91E6B8` | BATTLE_MENU_FN_TABLE | uint32[64] battle menu state handlers (2026-07-12) |
| `0x91EF98` / `0x91EF9C` | BATTLE_MENU_PREV_STATE / BATTLE_MENU_STATE | u16 pair — the battle "current widget" selector; same .data neighborhood as NAME_ENTRY_PANE_FLAG 0x921ED4 (menu-module state cluster) |
| `0x9AC354` | BATTLE_LIST5_TABLE | global 6-byte entries for the state-5 (magic-shaped) battle list |
| `0x921ED4` | NAME_ENTRY_PANE_FLAG | 0=grid, 1=side panel on the naming screen (v2.8.2). Sole clean candidate of a full-static A/B/A revert scan; live-verified across 6 crossings. Far from the DD name-entry block — menu-module .data |
| `0x9A8729`, `0x9A872A`, `0x9ADE30`, `0x9ADE34` | input-event/SFX pulse flags | pulse-and-reset on any d-pad press; REJECTED as cursor candidates |
| `0x9A8731` | grid/panel covariant | 44 on grid, 49 on panel, reverted (pane-flag scan 2026-07-12); secondary candidate, likely cursor-SFX/sprite id — unused, PANE_FLAG is cleaner |
| `0x9A13C8` / `0x9A7FC8` | kernel2 text scratch + u16 offset table | menu-module staging; **ALL ZERO during battle** (probed live 2026-07-11) — battle code never populates it |
| `0x9A9484` | ENEMY_ATTACK_NAME_TABLE | CONFIRMED (was "section-8 table?"): current formation's attack names from scene.bin, stride 0x20; = get_kernel_text section 9 (`ret 0x9A9484 + idx*0x20`) |
| `0x9A80F0` | target-name scratch buffer | get_kernel_text section 7 composes "name + dup letter (+ status/Sense text)" here on render; write-on-render only, do NOT poll (2026-07-13) |
| `0x9A8794` | BATTLE_FORMATION_SLOTS | stride 0x10 × 6 enemy slots (ends 0x9A87F4); u16[+0] = loaded-record index, movsx (−1 = empty). Note 0x9A8729/2A pulse flags above sit INSIDE the region just before it — this 0x9A87xx area is the battle formation block (2026-07-13, v2.10) |
| `0x9A8B1F` | BATTLE_DUP_LETTER_TABLE | per-actor-slot DISPLAY struct array, stride 0x44 (letter byte at 0x9A8B1F + slot·0x44); u8[0x9A8B39+slot·0x44] bit 0x40 = **SENSED flag** (v2.11 gates the HP readout on it), u16[0x9A8B4C+slot·0x44] = display-cached CURRENT HP the game formats as "cur/max" (2026-07-13) |
| `0x9A8E9C` | BATTLE_ENEMY_RECORDS | 3 × 0xB8 scene.bin enemy records (ends 0x9A90C4); name = bytes 0–0x1F, possibly unterminated. Sits between the formation/per-actor block and ENEMY_ATTACK_NAME_TABLE 0x9A9484 — one contiguous loaded-scene cluster 0x9A87xx–0x9A98xx (2026-07-13, v2.10) |
| `0x9AB070` | encoded-'A' base for dup letters | dword; game emits FF7-char(value + letter idx) for "MP A"/"MP B" suffixes (2026-07-13). Region 0x9AAD70–0x9AB070 (0x300 bytes) is cleared as one block by the battle-init memset |
| `0x9AB0A0` | battle_ai_context (FFNx battle_context) | = u32 operand at 0x41CCB2+0x5F (FFNx's own chain; sub_41CCB2 = battle-init memset, clears 0x253 dwords from here). Header 0x3C bytes (10 flag bytes + 23 u16 masks + u32 partyGil), then **actor_vars[10] at 0x9AB0DC = BATTLE_ACTOR_VARS**, stride 0x68: +0x04 stateFlags (the 0x9AB0E0 read from the v2.10 disasm), +0x24 formationID, +0x28/+0x2A cur/max MP u16, +0x2C/+0x30 cur/max HP i32 (+0x30 low word = the 0x9AB10C read). Array ends 0x9AB4EC (v2.11, 2026-07-13) |
| `0x9ADF0C` | kernel2 data pointer candidate | REJECTED — reads 0 at runtime (2026-07-11) |
| *(heap, varies)* | decompressed kernel2 text block | magic/item/weapon/etc. name sections resident for process lifetime; each section = u16 offset table + 0xFF-terminated strings, `u16[base]` = offset of entry 0. Located at runtime by English signature scan ('Cure\|Cure2', 'Potion\|Hi-Potion', 'Buster Sword') + walk-back rule `u16[base]==distance` (v2.7). No stable static anchor exists — the only exe-static pointers into the block are font tables (0xCFF3F8 cluster) |

### Battle module block: 0xBE1170 – 0xBFxxxx

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xBE1170` | G_ACTIVE_ACTOR_ID | u8; never resets between battles |
| `0xBE1178` | G_BATTLE_MODEL_STATE | stride 0x1AEC × 10 slots ≈ ends 0xBF1EF0 |
| `0xBF23B8` | G_SMALL_BATTLE_MODEL_STATE | stride 0x74; starts right after the large array |
| `0xBFC3E0–0xBFC5E0` | SFX/audio playback buffer | random churn; noise source in scans |

The battle command-menu CURSOR is confirmed NOT in either known per-actor array
(3 investigation sessions). RESOLVED STATICALLY 2026-07-12: the PSX "menu-widget
struct selected by a current-widget global" architecture DID carry over — the
widget global is `BATTLE_MENU_STATE` 0x91EF9C (menu-module .data, like the
name-entry PANE_FLAG at 0x921ED4), and the widget structs live in the menu
module block at 0xDC20A0+slot·0x700 (see §4 BATTLE_WIDGET_BLOCK). The three
live-scan sessions failed because the cursor is two u32 components inside a
0x38-byte struct at an address 0x1000+ bytes from any then-known anchor, in a
region that also hosts constantly-churning scroll/animation fields (+0x24/+0x30
change during list scrolling — classic delta-scan poison).
**LIVE-CONFIRMED 2026-07-12** by `ff7_battle_menu_cursor_live_verify.py`
(two battles: command names, magic-list rows incl. Ice by name, target cursor,
and the Limit-replaces-Attack row-0 swap all spoken correctly in real time).

### Field module block: 0xCBF578 – 0xCC1B42

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xCBF578` | DIALOG_TEXT_PTRS[8] | authoritative dialog text pointers |
| `0xCBF5E8` | field_script_ptr | section 0 pointer |
| `0xCBF9D8` | field_global_object_ptr | → modules_global_object |
| `0xCC0418` | current_dialog_message_speed | from ff7.h comment (unused by us so far) |
| `0xCC0960` | field_entity_id_list | |
| `0xCC0964` | current_entity_id | |
| `0xCC0B60` | field_event_data_ptr | → 0xCC1670 (observed) |
| `0xCC0CF8` | field_curr_script_position | WORD per entity |
| `0xCC0D88` | **modules_global_object struct** | spans ≈0x138 bytes → 0xCC0EC0; see sub-map below |
| `0xCC15D0` | FIELD_ID | does NOT zero in battle |
| `0xCC162C` | FIELD_PLAYER_MODEL_ID | |
| `0xCC1638` | FIELD_MOVIE_PLAYING word | |
| `0xCC1670` | field_event_data array (static) | stride 0x88 per model |
| `0xCC1B42` | field-script variable | FALSE cursor candidate (freezes when menu opens) |

Sub-map of `modules_global_object` (0xCC0D88 + offset; PSX decomp names in quotes):

| Offset | Address | Field | Confirmed? |
|--------|---------|-------|------------|
| +0x01 | `0xCC0D89` | game_mode: 0=field, 2=battle, 6=name entry, 9=menu (live) | ✓ live |
| +0x02 | `0xCC0D8A` | battle_id | FFNx label only |
| +0x04/06 | `0xCC0D8C/8E` | field_model_pos_x/y (u16) | FFNx label only |
| +0x22 | `0xCC0DAA` | field_model_triangle_id | FFNx label only |
| +0x26 | `0xCC0DAE` | previous_game_mode / PSX "movieState" | labels disagree |
| +0x28 | `0xCC0DB0` | num_models | PSX+FFNx agree |
| +0x2A | `0xCC0DB2` | field_model_id ("pc model id") | PSX+FFNx agree |
| +0x2C/2E/30 | `0xCC0DB4…` | PSX: idle/walk/run animation ids | PSX only |
| +0x32 | `0xCC0DBA` | UC player-control lock | ✓ live (v2.6 gate works) |
| +0x33 | `0xCC0DBB` | PSX: "suspend walk animation" | PSX only |
| +0x34 | `0xCC0DBC` | PSX: "menus disabled" (MENU opcode?) | PSX only — candidate for menu-availability TTS |
| +0x36 | `0xCC0DBE` | PSX: "map jump disabled" | PSX only |
| +0x37–0x3B | `0xCC0DBF–C3` | SCRLO / MPDSP / MVCAM / BGMOVIE / BTLON flags | PSX+FFNx agree |
| +0x3C | `0xCC0DC4` | PSX: "encounter table id" | PSX only |
| +0x44 | `0xCC0DCC` | midi_id | FFNx label only |
| +0x4C–0x62 | `0xCC0DD4…` | fade type/adjustment/speed/rgb | FFNx labels |
| +0x64 | `0xCC0DEC` | field_id (module copy — distinct from 0xCC15D0) | FFNx label only |
| +0x68 | `0xCC0DF0` | current_key_input_status (u32) | ✓ live |
| +0x6C | `0xCC0DF4` | previous_key_input_status | FFNx label only |

### Savemap: 0xDBFD38 – ≈0xDC0E2C (0x10F4 bytes)

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xDBFD38` | savemap base | live game state, persisted on save |
| `0xDC0E10–0xDC0E24` | CONFIG_* value bytes | **these sit INSIDE the savemap range** — FF7 persists config in the save header region, which is why the sliders live here and not with the menu cursors |

### Menu module block: 0xDC0FA0 – 0xDC38F0

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xDC0FA0` | QUIT_CURSOR | |
| `0xDC0FB1` | QUIT_OPEN | unreliable (never re-zeroes) — do not gate on it |
| `0xDC0FC0` | menu_objects | FFNx externals |
| `0xDC108C` | SOUND_CURSOR | |
| `0xDC10F0` | CONFIG_ROW | |
| `0xDC1154` | MENU_CURSOR | |
| `0xDC12DC` | MENU_OPEN | also 1 on post-battle results screen AND the naming screen (v2.8.3) |
| `0xDC208C` | kernel2 lookup result ptr | written after every consumer CALL to 0x41963C — but consumer is FFNx-replaced, so **never written in practice**; observed 0 always (2026-07-11) |
| `0xDC20A0` | BATTLE_WIDGET_BLOCK | per-slot (+slot·0x700) battle menu widget structs — command cursor at +0/+4; see §4 (2026-07-12) |
| `0xDC35AC` | BATTLE_MENU_BUSY | u32 transition flag; `0xDC35A8` = command-menu-opened SFX-played byte |
| `0xDC3C54–0xDC3C98` | issued-action staging block | 0xDC3C70 cmd id, 0xDC3C78 action id, 0xDC3C7C ACTIVE SLOT, 0xDC3C84 action idx, 0xDC3C90/94 target type/idx, 0xDC3C98 targeting actor (all = FFNx externals; static 2026-07-12) |
| `0xDC3640` | flash-name compose buffer | dispatcher branch 4 (cmd 0x07) output |
| `0xDC38E0` | BATTLE_ACTOR_DATA (FFNx struct) | +0x08 pending pulse, +0x0C command_index, +0x10 action_index — the v2.7 flash-message source |

### Title / name-entry block: 0xDD4400 – 0xDD6F24

| Address | Symbol | Notes |
|---------|--------|-------|
| `0xDD4400` | (noise) | frame-parity blink byte, toggles 0↔1 every frame on the naming screen |
| `0xDD4538` | NAME_ENTRY_COL | grid column 0–9 (v2.8). 4-byte slot spacing, but READ AS u8 — only the low byte is verified (v2.8.1) |
| `0xDD453C` | NAME_ENTRY_ROW | grid row 0–6 (v2.8). Read as u8, same reason. Can CHANGE when entering the side panel (1→4 observed) |
| `0xDD4574` | NAME_ENTRY_PANEL_INDEX | RESOLVED (v2.8.2): side-panel button index 0=Space 1=Delete 2=Select 3=Default (0/1 proven by buffer effects; 2/3 order ear-confirmed). Wraps 0↔3. Retains last value after leaving the panel and idles 0 — gate on PANE_FLAG (0x921ED4), never alone. The old "3→2 alongside a delete" anomaly was a Confirm press ON the panel's Delete button |
| `0xDD45E8` | unknown u32 | small values during editing, 0xFFFFFFFF at times, reset per screen. Unresolved |
| `0xDD45F0` | NAME_ENTRY_BUFFER | FF7-encoded, 0xFF-terminated, ≥9 chars (v2.8) |
| `0xDD4630` | (noise) | u16 frame/animation counter, changes every poll on the naming screen |
| `0xDD46F0` | NAME_ENTRY_CARET | RESOLVED (v2.8.2): caret position, clamped 0–8. Tracked 5→6→7→8 live as letters were appended to 'Cloud', pinned at 8 when full. Explains the 9-char name cap: at cap, Confirm REPLACES the 9th char instead of appending |
| `0xDD46F8` | NAME_ENTRY_CHAR_INDEX | 0=Cloud, 1=Barret. The Echo mod hext patch called this "cursor column" — wrong label, it's the character being named |
| `0xDD46FC` | NAME_ENTRY_ACTIVE | 1 while naming screen open (v2.8 gate, with GAME_MODE==6) |
| `0xDD6F24` | TITLE_CURSOR | 0=New Game, 1=Continue; unrelated BSS data outside title screen |

### Discovery techniques ranked by success rate (as of 2026-07-12)

1. **Static chain resolution against the exe on disk** (v2.6; battle menu
   cursor 2026-07-12): replicate FFNx `ff7_data.h` chains on the file image;
   cross-check against `ff7.h` address comments. Zero user effort, immune to
   FFNx trampolines. Best first move. The battle-cursor break came from
   pairing it with **capstone disassembly of the resolved functions**:
   extract every absolute data-region operand per handler, then intersect
   "written by input handlers" with "read by draw code" — that intersection
   is tiny and cursor-shaped even when no single +-1 instruction exists
   (the mutation lived in a shared helper behind a struct pointer).
2. **PSX decomp struct matching** (v2.6 UC lock): once a PC struct base is known,
   align it with the PSX decomp's version and lift the PSX field comments.
3. **Targeted isolate delta scan** (MENU_CURSOR, CONFIG_ROW, SOUND_CURSOR,
   NAME_ENTRY_ROW/COL/BUFFER): two snapshot phases inside the same frozen
   context, subtract. Succeeded again v2.8 — and its validation phase
   correctly EXPOSED a bad external anchor (see item 7).
4. **Live change-monitor with the player narrating** (GAME_MODE values): passive
   500ms change-logger, no staged phases; good for enum-value discovery.
5. **Full-heap delta scans**: FAILED at scale (battle cursor, ~1.5M bytes of
   background churn per quiet window). Use only inside frozen contexts.
6. **Hardware-breakpoint debugging**: game self-terminates (anti-debug). Never retry.
7. **Third-party mod hext-patch labels**: UNRELIABLE (v2.8). The Echo mod's
   '01 - Disable Name Change.txt' labeled 0xDD46F8 "name-entry cursor column";
   live scanning proved it's the character-being-named index — it never changes
   during grid navigation. The ADDRESS a patch touches is a useful region hint
   (it did point at the right DD45xx-DD46xx block), but the LABEL describes what
   the patch author needed to break, not what the byte is. Never use one as a
   validation anchor without live confirmation.
