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

All other symbols are either hardcoded fixed addresses (confirmed from `externals_102_us.h` and `ff7.h`)
or read at runtime from opcode parameters.

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

---

## 9. Current Status

### Working (as of v1.7)

- All field story dialog (MESSAGE opcode 0x40) spoken via NVDA on dialog start and page advance
- All field choice menus (ASK opcode 0x48) spoken with "Choose: " prefix
- Speaker identification (Cloud, Barret, Tifa, etc.) from token at dialog position 0
- Win=0 and win=1: state machine primary path (earlier, cleaner detection)
- Win=2 and win=3: DLGID fallback path (two-frame delay, reliable in practice)
- Voice acting (FFNx) and TTS coexist — hook chain passes through both
- Config file: `speak_dialog`, `speak_choices`, `interrupt` toggles
- No duplicate speaks; no garbage TTS blocks
- ASCII filter: printable ASCII only; word boundaries preserved

### Known Issues / Limitations

| Issue | Severity | Fix |
|-------|----------|-----|
| Apostrophe → space ("I'm" → "I m") | Moderate | Needs proper byte→char lookup table |
| Other extended chars garbled (curly quotes, em-dash, etc.) | Moderate | Same lookup table |
| Speaker detection broken when 3-byte window header precedes speaker token | Minor | Detect/skip 0xD0–0xDF at position 0 |
| Dynamic token placeholders spoken literally ("[item name]") | Minor | Resolve tokens from script banks (v2) |
| "X <" artifact occasionally in ASK output | Minor | ASK formatting codes not yet filtered |

### Not Yet Implemented (Planned v2)

| Feature | Hook Point |
|---------|-----------|
| ASK per-option TTS as cursor moves | `opcode_ask + 0x8E` → inner loop; needs FF7 original opcode_ask address |
| Battle action text | `display_battle_action_text_42782A` |
| Battle turn announcement | `battle_set_do_render_menu_call` |
| World map dialog | `world_opcode_message_sub_75EE86`, `world_opcode_ask_sub_75EEBB` |
| Main menu navigation | Text render function hook (general) or per-menu cursor index RE |
| Name entry screen | Cheat Engine scan for cursor X/Y index |
| Field navigation spatial audio | Entity position list + audio panning |

---

## 10. Remaining RE Work

| Symbol | Needed For | How to Find |
|--------|-----------|------------|
| FF7 original `opcode_ask` address | ASK per-option cursor hook at +0x8E | Disassembly; scan for CALL 0x6310A1 within known function range |
| Per-menu cursor index offsets | Main menu, item, magic, equip, status, PHS, shop | Cheat Engine scan within `menu_objects` (0xDC0FC0) region |
| Name entry grid cursor X/Y | Name entry screen | Cheat Engine: value changes as keyboard grid cursor moves |
| ATB gauge offset in `battle_context` | "Whose turn" announcement timing | Within `battle_context->actor_vars`; ~2 bytes per actor |
| `battle_set_do_render_menu_call` address | Battle menu entry hook | Relative call chain from battle init |
| `update_display_text_queue` address | Battle text queue | Relative call from battle render loop |
| `get_kernel_text` address | Battle action name lookup | Relative call from `display_battle_action_text_42782A` |
| FF7 byte 0x5F–0xDF → correct Unicode | Extended character lookup table | FF7 font texture / Makou Reactor character table |

---

## 11. FF7 Text Encoding — Byte Lookup Table (Partial)

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

## 12. Source Reference

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
