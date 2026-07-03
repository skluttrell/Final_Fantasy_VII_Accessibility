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
| `TITLE_CURSOR` | `0x00DD6F24` | 0=New Game, 1=Continue — only valid on title screen; guard with FIELD_ID==0 |
| `MENU_CURSOR` | `0x00DC1154` | Main menu row 0–10 (Item…Quit); constant during field play |
| `MENU_OPEN` | `0x00DC12DC` | 1 when main menu or post-battle results active; must gate with FIELD_ID!=0 |
| `CONFIG_ROW` | `0x00DC10F0` | Config sub-menu row 0–9 (Window color…Magic order); proxy gate: MENU_CURSOR==7 |
| `CONFIG_SPEED_BATTLE` | `0x00DC0E10` | Row 5 Battle speed — raw byte, 0=Fast → 255=Slow |
| `CONFIG_SPEED_MSG` | `0x00DC0E11` | Row 6 Battle message speed — raw byte, 0=Fast → 255=Slow |
| `CONFIG_PACKED_CURSOR_ATB` | `0x00DC0E12` | Packed byte: bit 4=Cursor (0=Initial/1=Memory); bits 7:6=ATB (0=Active/1=Recommended/2=Wait) |
| `CONFIG_PACKED_CAMERA_MAGIC` | `0x00DC0E13` | Packed byte: bit 0=Camera (0=Auto/1=Fixed); bits 4:2=Magic order index 0–5 (No.1–No.6) |
| `CONFIG_SPEED_FIELD_MSG` | `0x00DC0E24` | Row 7 Field message speed — raw byte, 0=Fast → 255=Slow |
| `SOUND_CURSOR` | `0x00DC108C` | 0=Music slider highlighted, 1=FX slider highlighted; inside Sound sub-menu only |
| `QUIT_CURSOR` | `0x00DC0FA0` | 0=Yes, 1=No inside Quit confirmation dialog |

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
| Battle action text | `display_battle_action_text_42782A` |
| Battle turn announcement | `battle_set_do_render_menu_call` |
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
| `update_display_text_queue` address | Battle text queue | Relative call from battle render loop |
| `get_kernel_text` address | Battle action name lookup | Relative call from `display_battle_action_text_42782A` |
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
