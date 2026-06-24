# FFVII Blind Accessibility — Narrowed Research & Approach Analysis

This document focuses the broader resource research into concrete approaches for adding
screen reader / blind accessibility to Final Fantasy VII (2013 Steam version).

---

## 1. The Core Problem

A blind player needs audio feedback for:

| Game Context | What They Need to Know |
|-------------|----------------------|
| **Menus** (main, item, magic, equip, etc.) | Which item is highlighted, how many options, current value, description |
| **Dialog / Story** | Text of dialog windows, current speaker |
| **Choices** | Options in yes/no or multi-choice windows |
| **Field (exploring maps)** | Where the player is, what interactable objects are nearby, which direction to move |
| **Battle** | Whose turn it is, which targets are available, action results (damage, status effects), enemy names/HP rough state |
| **World Map** | Current position, nearby locations |
| **Screen transitions** | Which screen/area was just entered |

---

## 2. Why FF7 2013 Steam Is Harder Than the Pixel Remasters

The accessible FF5/FF6 mods (see FFVII-Modding-Resources.md §7) use **MelonLoader**, which only works for **Unity-based** games. FF7 2013 Steam uses a proprietary C++ engine with a custom DirectX 8 wrapper (`AF3DN.P`). MelonLoader is not applicable.

The Pixel Remaster games give mod authors in-process access to typed C# game objects. For FF7, the equivalent requires either:
- Running a **reimplemented engine** in managed code (Braver's approach), or
- **Hooking into the original process** via DLL replacement/injection, or
- **Reading process memory** from an external process

---

## 3. Approaches Compared

### Approach A: Braver Engine Reimplementation (Current)

**How it works**: Braver replaces FF7.exe entirely. It reads the original data files (LGP archives, `kernel.bin`, the original `.exe` for embedded data) and re-runs the game in .NET 7 / MonoGame. Game state is directly accessible as .NET objects.

**Accessibility status**:
- ✅ Field dialog → TTS via Tolk (`IDialog.Dialog()`)
- ✅ Menu items → TTS via Tolk (`IUI.Menu()`)
- ✅ Choice prompts → TTS (`IUI.ChoiceSelected()`)
- ✅ Screen change → TTS (`ISystem.ActiveScreenChanged()`)
- ✅ Footstep audio (spatial cue for movement)
- ✅ Focus tracking (shoulder buttons to cycle field interactables, pitch/pan audio toward them)
- ❌ Battle menu/turn announcements → `IBattleUI` interface declared but the battle screen doesn't call it yet
- ❌ Battle action results → commented-out stub (`BattleActionResult`)
- ❌ World map accessibility → not started
- ❌ Enemy names / HP state in battle → needs interface extension

**7th Heaven compatibility**:
- The `Braver.7HShim` plugin reads `.iro` archives and loose mod folders, mapping them into Braver's data source layer.
- **Gap**: Users cannot use 7th Heaven's GUI to manage which mods are active. They must copy `.iro` files or mod directories to a location Braver.7HShim scans. The 7th Heaven activation/ordering/profile workflow is bypassed entirely.
- Users accustomed to 7th Heaven must change their workflow: run BraverLauncher instead of 7th Heaven.

**Loading procedure complexity**:
- User installs Braver, configures paths in BraverLauncher (FF7 install dir, save dir, music dir).
- Enables plugins in BraverLauncher UI.
- Copies 7th Heaven mods to Braver's plugin folder.
- Runs BraverLauncher → Braver.exe.
- **Assessment**: More steps than standard 7H workflow, but not dramatically so. The issue is that it's a **parallel** setup rather than an **extension** of 7th Heaven.

**Strengths**: Deepest possible accessibility integration. All game state available as typed .NET objects. No reverse engineering of memory layouts needed for each game version.

**Weaknesses**: 
- Not all game features are implemented yet (battle effects, world map encounters, some menu screens).
- Not a drop-in replacement for the 7th Heaven workflow.
- Some 7th Heaven mods that depend on FFNx-specific features (voice acting packs that use FFNx's audio engine, shader-level graphical enhancements) won't work.

---

### Approach B: Standalone Proxy DLL Hook (Confirmed Viable)

**How it works**: A custom DLL is placed in the FF7 install directory using a proxy DLL technique (replacing a DLL ff7.exe loads at startup, such as `winmm.dll` or `dinput.dll`). This DLL injects itself into the ff7.exe process at launch, hooks the field script opcode dispatch table and battle functions using MinHook, and calls Tolk for screen reader output. It co-exists with FFNx (which handles graphics/audio for 7th Heaven mods) without conflicting.

**Architecture**:
```
ff7.exe
  └─ loads winmm.dll  →  our proxy (calls real winmm, then installs hooks)
  └─ loads AF3DN.P    →  FFNx (graphics/audio/voice mods, unchanged)
  └─ runs field opcode dispatch table
       ├─ [0x40] MESSAGE  →  our TTS hook → (chains to FFNx voice hook or original)
       └─ [0x48] ASK      →  our TTS hook → (chains to FFNx voice hook or original)
  └─ runs battle update loop
       └─ display_battle_action_text → our TTS hook
  └─ calls Tolk.dll → NVDA/JAWS/SAPI
```

**7th Heaven compatibility**: Full. 7th Heaven installs FFNx as `AF3DN.P`. Our `winmm.dll` proxy is loaded independently. Neither modifies the other. Voice acting mods work via FFNx's audio engine exactly as without this mod.

**Loading procedure**: User installs the accessibility DLL set (`winmm.dll` + `Tolk.dll` + `NVDA2019.dll`/`JAWS2019.dll`) into the FF7 install folder. Runs 7th Heaven as normal. Zero workflow change.

---

#### Hook Point Architecture (from FFNx source analysis)

**Field dialog (MESSAGE opcode 0x40 and ASK opcode 0x48)**:

FFNx hooks these identically for its voice acting system (`voice.cpp`, `voice_init()`):
```cpp
// Patch opcode table entry 0x40 (MESSAGE) to our wrapper
opcode_old_message = (int (*)())ff7_externals.opcode_message;
patch_code_dword((uint32_t)&common_externals.execute_opcode_table[0x40], (DWORD)&opcode_voice_message);

// Patch opcode table entry 0x48 (ASK) to our wrapper
opcode_old_ask = (int (*)(int))ff7_externals.opcode_ask;
patch_code_dword((uint32_t)&common_externals.execute_opcode_table[0x48], (DWORD)&opcode_voice_ask);
```

For TTS, we use the same table entries. If FFNx loads before our DLL, we chain after FFNx's handlers (the "old" pointer we save will point to FFNx's handler, not the original). This works transparently.

**Finding `execute_opcode_table` at runtime**:
The 2013 Steam exe function names embed their addresses. `field_init_event_60BACF` is at `0x60BACF`. The table is derived from it dynamically:
```cpp
// At runtime: read the relative call target at offset 0x80 from 0x60BACF to get execute_opcode
// Then read the absolute address embedded at offset 0x10D into execute_opcode to get the table
uint32_t execute_opcode = read_relative_call(0x60BACF + 0x80);
uint32_t* execute_opcode_table = read_absolute_ref(execute_opcode + 0x10D);
```
This is exactly what `ff7_data.h` does. It's ~10 lines of C++ using ReadProcessMemory-style inline reads.

**Reading dialog text**:

The dialog text pointer array is at absolute address `0xCBF578` (confirmed from ff7.h comment: `DWORD* current_dialog_string_pointer; //0xCBF578`). Each entry is a pointer to FF7's encoded text for that window.

FF7 text encoding (from `voice.cpp decode_ff7_text()`):
- Normal chars: `encoded_byte + 0x20` = ASCII character
- `0xEA`–`0xF2`: character name tokens (Cloud, Barret, Tifa, etc.)
- `0xEB`–`0xEF`: dynamic tokens (`{item_name}`, `{number}`, etc.) — 4 bytes total
- `0xFF`: end of string

**Dialog state machine** (from `voice.cpp get_dialog_opcode()` and `is_dialog_*` helpers):

The dialog state for each window is tracked in a 24-byte-stride array at `ff7_externals.opcode_message_loop_code`. State byte per window = `opcode_message_loop_code[24 * window_id]`.

State transitions that matter for TTS:
- `last==0, current!=0` → dialog starting → **speak dialog text now**
- `last==14→2` or `last==4→8` → page advance → **speak next page**
- `current==7` → dialog closing → silence/skip

**Choice option changes** (ASK):
- `replace_call_function(ff7_externals.opcode_ask + 0x8E, our_parse_options_hook)` intercepts `field_opcode_ask_update_loop_6310A1` 
- Current option index is passed as `*current_question_id` parameter
- When the tracked option index changes → **speak the new option text**

**Battle action text**:

FFNx hooks `ff7_externals.update_display_text_queue` (found dynamically in ff7_data.h):
```cpp
replace_function(ff7_externals.update_display_text_queue, ff7_update_display_text_queue);
replace_function(ff7_externals.display_battle_action_text_42782A, ff7_display_battle_action_text);
```
Battle action text is retrieved from: `ff7_externals.get_kernel_text(8, buffer_idx, 8)` and decoded with the same decode function. The `buffer_idx` comes from `battle_display_text_queue.front().buffer_idx`.

**Battle command menu**:

`battle_menu_enter` is called (hooked via `replace_call_function(ff7_externals.battle_set_do_render_menu_call, ...)`) each time the battle command menu opens. The active actor and menu state come from:
- `ff7_externals.g_active_actor_id` → which character's turn
- `ff7_externals.battle_context->actor_vars[id].index` → character ID (0=Cloud, 1=Barret, etc.)
- `ff7_externals.g_battle_model_state[id].commandID` → selected command
- `ff7_externals.menu_objects` at `0xDC0FC0` → main menu objects structure

**Known absolute addresses for 2013 Steam / 1.02 US exe**:
| Symbol | Address | Source |
|--------|---------|--------|
| `current_dialog_string_pointer` | `0xCBF578` | ff7.h comment |
| `build_dialog_window` | `0x6E97E0` | externals_102_us.h |
| `menu_objects` | `0xDC0FC0` | externals_102_us.h |
| `savemap` | `0xDBFD38` | externals_102_us.h |
| `field_init_event_60BACF` | `0x60BACF` | function name convention |
| `field_opcode_message_update_loop_630D50` | `0x630D50` | function name convention |
| `field_text_box_window_create_631586` | `0x631586` | function name convention |

**Implementation language**: C++ with MinHook and Tolk's C API (`Tolk_Load`, `Tolk_Speak`, `Tolk_Silence`, `Tolk_Unload`). The Tolk C API is in `tolk.h` / `Tolk.dll` — the same library Braver already uses via its NuGet wrapper.

**Feasibility**: High. The exact hook points are documented above based on the FFNx source. The implementation is essentially a TTS-only subset of what FFNx's `voice.cpp` does, replacing audio file playback with `Tolk_Speak()` calls. Estimated implementation: ~800–1200 lines of C++ for core field/battle dialog + menu coverage.

---

### Approach C: External Memory Reader Process

**How it works**: A separate standalone accessibility process runs alongside FF7.exe. It uses `ReadProcessMemory` (Windows API) to read FF7's address space and translate raw memory bytes into game state, then calls Tolk for screen reader output.

**7th Heaven compatibility**: Full. Completely independent of the game's loading mechanism.

**Loading procedure**: User launches FF7 via 7th Heaven as normal. Then launches the accessibility process (could be automated via a 7th Heaven startup script or simply a shortcut). Alternatively, configure 7th Heaven to auto-launch it.

**Challenges**:
- Requires finding absolute memory addresses for each game build (the 2013 Steam version and the 2026 re-release have different address layouts). 
- The savemap offsets documented in FFVII-Modding-Resources.md §4 are **save-file offsets**, not process-memory absolute addresses. The absolute live addresses require scanning.
- Polling-based: the external process must poll memory at a regular interval (e.g., 30Hz) to detect state changes. This introduces latency.
- If the game uses ASLR (Address Space Layout Randomization), base addresses change each launch. Must locate the base pointer dynamically.
- Cannot hook into game events — can only observe state, not intercept calls.

**What can be reliably detected via memory**:
- Player HP/MP, party composition
- Current field map ID (which map the player is on)
- Player X/Y position and triangle ID
- Menu visibility/locking masks (whether menu is accessible)
- Current module (field/world/battle)
- Story flags (event progression)

**What cannot be reliably detected**:
- Which specific menu item is currently highlighted (requires finding the menu cursor index in runtime data)
- The exact text of the currently displayed dialog box (text is in LGP archives, not stored verbatim in the savemap; would need to cross-reference)
- Battle-specific UI state (turn order, target highlights)

**Feasibility**: Lower implementation effort than Approach B for basic features, but fundamentally limited in what it can detect without deeper reverse engineering.

---

## 4. Decision: Standalone C++ Proxy DLL (Chosen Approach)

The standalone proxy DLL approach (Approach B) has been chosen over continuing Braver development.

### Why the DLL approach over Braver:
1. **Zero workflow change** — user runs 7th Heaven exactly as before; the DLL is simply present in the folder.
2. **Full mod compatibility** — voice acting packs, footstep audio, and every other 7th Heaven mod work via FFNx exactly as before. Nothing is replaced or reimplemented.
3. **The hook points are fully mapped** — `voice.cpp` analysis confirms we hook the same opcode table entries FFNx uses for voice acting. The implementation path is clear.
4. **Complete game coverage** — a DLL hook against the original engine covers 100% of the game by definition; Braver's battle system, world map, and several menu screens are not yet fully implemented.

### Design: Voice Acting + TTS Toggle

Story dialog TTS is **optional and user-configurable**. The default behavior is automatic detection:
- Before speaking a MESSAGE/ASK dialog, check whether a voice file exists for that field + dialog ID (e.g., `voice\{field_name}\{dialog_id}a.ogg` in the mod path).
- If a voice file exists → suppress TTS (voice acting plays via FFNx as normal).
- If no voice file exists → speak text via Tolk.
- A config file (`ffvii_accessibility.cfg`) allows users to override this: `prefer_voice=1` (always suppress TTS for dialog), `prefer_tts=1` (always speak), `auto` (default file-detection behavior).

This means users with voice acting mods installed get voice acting; users without get TTS; users who prefer the screen reader's speed over voice acting can force TTS with a single config line.

### DLL Install Spec

**DLL proxy name**: `winmm.dll` (Windows Multimedia API — ff7.exe imports it; safe proxy candidate).

**Fallback**: `dinput.dll` variant for users who already have a `winmm.dll` proxy installed (Reunion mod, some resolution hacks). The DLL can chain to an existing proxy by checking for a renamed copy.

**Files dropped into FF7 install folder**:
- `winmm.dll` — our proxy (forwards all real winmm exports to system winmm)
- `Tolk.dll` — screen reader abstraction
- `NVDA2019.dll` — NVDA driver
- `JAWS2019.dll` — JAWS driver (optional)
- `ffvii_accessibility.cfg` — user config file

### Implementation Priority Order

| Priority | Feature | Hook Point | Status |
|----------|---------|-----------|--------|
| 1 | **DLL init timing** | `timeGetTime` wrapper defers hook install until game is initialized | Not started |
| 2 | **winmm proxy chaining** | Check for existing proxy at load, forward exports | Not started |
| 3 | **Field dialog TTS** (MESSAGE 0x40) | Opcode table patch | Not started |
| 4 | **Field choice menus** (ASK 0x48) | Opcode table + `opcode_ask+0x8E` hook | Not started |
| 5 | **Battle action text** | `display_battle_action_text_42782A` replace | Not started |
| 6 | **Battle turn announcement** | `battle_set_do_render_menu_call` replace | Not started |
| 7 | **Main menu navigation** | Text render function hook (general) | Not started |
| 8 | **World map dialog** | `opcode_wm_message` / `opcode_wm_ask` chain | Not started |
| 9 | **Name entry screen** | Dedicated cursor tracking (requires RE) | Not started |
| 10 | **Field navigation spatial audio** | Entity position list + audio panning | Not started (v2) |
| 11 | **Mini-game mitigations** | Per-game audio cues | Not started (v2) |

---

## 5. Full Coverage Scope

Everything the DLL must handle for complete blind accessibility:

### Field Maps (Exploring)
- **Dialog text** — MESSAGE opcode: speak on dialog start and each page advance.
- **Choices** — ASK opcode: speak each option as cursor moves; announce option count.
- **TUTOR / tutorial boxes** — separate hook at `menu_sub_6CB56A+0x2B7` (same as FFNx).
- **Interactable objects** — entity positions from field entity list; spatial audio panning toward nearest interactable when shoulder button pressed (replicates Braver's `FootstepFocusPlugin`).
- **Map/area transitions** — announce field map name on `MAPJUMP` opcode (0x60) or when `current_field_id` changes.
- **Map name data** — ~800 field map IDs need human-readable name lookup table; data authoring work, not purely code.

### Battle
- **Whose turn it is** — `battle_menu_enter` hook; read character name from `battle_context->actor_vars[g_active_actor_id].index`.
- **Action/attack text** — `display_battle_action_text_42782A` and `update_display_text_queue`; text from `get_kernel_text(8, buffer_idx, 8)`.
- **Target selection** — announce enemy name (from `kernel.bin` via `get_kernel_text`) and rough HP % when targeting cursor changes.
- **Limit Break menu** — nested submenu inside battle; cursor tracking needed.
- **Item/Magic use in battle** — announce selected item or spell name.
- **Status effects** — announce when a status effect (Poison, Sleep, etc.) is applied/removed; from battle actor flags.
- **Victory screen** — announce EXP, AP, items received.
- **Priority queue** for ATB speech: (1) whose turn, (2) target change, (3) action started, (4) action result, (5) ambient HP state.

### Main Menu System
- **Menu cursor** — 12+ distinct menu screens each with their own cursor index. General solution: hook text rendering function to intercept strings drawn at cursor position.
- **Item menu** — item name, quantity, description.
- **Magic menu** — spell name, MP cost, element.
- **Materia menu** — materia name, AP, slot.
- **Equip menu** — equipment slot, item name, stat comparison.
- **Status screen** — character name, HP/MP/level, all stats.
- **Config menu** — setting name and current value.
- **PHS menu** — party member names and HP.
- **Save menu** — save slot number, location, playtime.
- **Name entry screen** — current selected letter, cursor position on keyboard grid; requires dedicated RE (see Hurdle §8).
- **Shop menus** — item name, cost, current quantity.

### World Map
- **Dialog / ASK** — `opcode_wm_message` and `opcode_wm_ask` hooks (separate from field, already in FFNx's `voice_init()`).
- **Location proximity** — world map X/Y from savemap at `0xDBFD38+0x0F5C`; lookup table of ~30 named locations with coordinate zones.
- **Location transitions** — announce location name when entering a town/dungeon gateway.

### Mini-games (Known Limitations — v2 or documented skip)
| Mini-game | Assessment |
|-----------|-----------|
| Motorcycle chase (Midgar escape) | Audio distance cues possible but complex; can fail and retry |
| Snowboard | Skip option at slope entrance; item is non-critical |
| Chocobo racing | Breeding matters; racing mostly skippable for story progress |
| Fort Condor | Abandon costs one Phoenix Down; battle UI accessible via existing battle hooks |
| Submarine | One-time event; can fail; torpedo count/enemy proximity feasible with work |
| Coaster ride | Failure has no permanent consequence |
| Motorball (opening) | Standard battle with scripted outcome; covered by battle hooks |

---

## 6. Hurdles and Mitigations

### Hurdle 1 — DLL initialization timing
When `winmm.dll` receives `DLL_PROCESS_ATTACH`, ff7.exe hasn't run its init yet. The opcode table doesn't exist; MinHook patches would crash.

**Mitigation**: Hook `timeGetTime` (a winmm function called every frame starting from the game loop). In our `timeGetTime` wrapper, on the first call after the game's field init is detected (check whether `*(uint32_t*)0x60BACF` region is code), install hooks once and stop intercepting `timeGetTime`. Standard pattern for DLL-injection mods.

### Hurdle 2 — winmm.dll proxy name collision
Some existing mods (Reunion, some resolution hacks) also use a `winmm.dll` proxy. Name collision silently disables one of the proxies.

**Mitigation**: At `DLL_PROCESS_ATTACH`, check for a file named `winmm_chain.dll` in the FF7 folder. If found, load it and forward all winmm exports through it. This gives a "DLL chaining" pattern that coexists with other proxies. Provide a `dinput.dll` variant as an alternative. Document the collision scenario clearly in the install README.

### Hurdle 3 — Load order relative to FFNx
FFNx loads as `AF3DN.P` (game's DirectX 8 driver) during the `d3d8.dll` import resolution phase. `winmm.dll` loads earlier, during the winmm import phase. By the time our `timeGetTime` first fires within the game loop, FFNx has already run its `voice_init()` and patched opcode table entries [0x40] and [0x48] to its own handlers.

**Result**: When we save the "old" handler before replacing it, we save FFNx's handler, not the original. Our chain calls FFNx's handler, which plays voice audio (if available) and calls the original. TTS and voice acting both work. This is the correct behavior and requires no special handling.

### Hurdle 4 — Detecting whether voice acting is installed
We cannot call into FFNx to check `nxAudioEngine.isVoicePlaying()`.

**Mitigation**: Before speaking any dialog, check if the voice OGG file exists on disk:
```
{FF7 folder}\mods\{active_mod}\voice\{field_name}\{dialog_id}a.ogg
```
If the file exists → voice acting is installed for this line → suppress TTS (unless user config forces TTS). This check is a simple `GetFileAttributesA` call — negligible cost. The active mod path can be read from `ffnx.toml` in the FF7 folder.

### Hurdle 5 — Menu cursor structures not mapped
`menu_objects` at `0xDC0FC0` is the global menu container, but the per-menu cursor index for each of the 12+ menu screens is not yet located.

**Mitigation phase 1**: Hook the text rendering function (a single function through which all on-screen text is drawn). Intercept each string drawn; when cursor moves, the string at the cursor position is the last string drawn in the cursor's pixel region. This gives automatic coverage for all menus without per-menu RE.

**Mitigation phase 2**: Reverse-engineer per-menu cursor offsets using Cheat Engine + the known `menu_objects` base. Add targeted cursor reads for each menu as they are discovered. This improves precision over the text-render interception approach.

### Hurdle 6 — ATB speech collisions in battle
In Active Time Battle, multiple characters can be "ready" simultaneously. Naive TTS fires all announcements at once.

**Mitigation**: Internal priority queue with a 200–300ms debounce per category:
1. "It is [character]'s turn" — highest priority, interrupts everything
2. Target selection change — interrupts lower-priority pending speech
3. Action name — queued behind (1) and (2)
4. Damage/result text — queued, can be dropped if (1) fires
5. Ambient HP — only spoken if no higher-priority item is pending

Respect the player's configured Battle Speed from the Config menu (readable from savemap offset `0x10D8`). At high battle speed, drop ambient announcements entirely.

### Hurdle 7 — Name entry screen
The character name entry grid uses a custom on-screen keyboard not covered by opcode hooks. The cursor X/Y index in the name entry data structure is not yet located.

**Mitigation**: Treat as a targeted RE sub-task. Use Cheat Engine to scan for a value that changes as the cursor moves over the letter grid. Once found, the hook is a simple change-detection read. This is isolated and self-contained. In the meantime, document "name entry is not yet accessible" in v1 release notes.

### Hurdle 8 — World map dialog uses different hook chain
World map MESSAGE/ASK dialogs are NOT routed through the field opcode table. They use `opcode_wm_message` and `opcode_wm_ask`, which are called via `replace_call_function` at specific offsets inside the world map module:
- `world_opcode_message_sub_75EE86 + 0x2B`
- `world_sub_75EF46 + 0x8C`
- `world_opcode_ask_sub_75EEBB + 0x3C`
- `world_sub_75EF46 + 0xAF`

**Mitigation**: Implement these hooks in addition to the field opcode table hooks. They use the same `opcode_wm_message`/`opcode_wm_ask` pattern already documented in FFNx's `voice_init()`. Address resolution is identical to the field hooks — read relative call targets from known function bases.

### Hurdle 9 — FF7 text encoding for dynamic tokens
Dialog strings contain dynamic tokens like `{item_name}`, `{number}`, `{target_name}`. These are 4-byte sequences in the encoded string. The actual values they resolve to are context-dependent (set by the field script before the MESSAGE opcode runs).

**Mitigation**: For TTS purposes, replace dynamic tokens with spoken placeholder phrases: `"[item name]"`, `"[target]"`, `"[number]"`. Most dialog is comprehensible with these placeholders. Full token resolution (looking up the actual item name from script memory banks) can be added later as a refinement.

### Hurdle 10 — 2013 Steam exe stability / future updates
The 2013 Steam exe has been stable since release (~12 years). But Square Enix could theoretically update it, shifting all hardcoded addresses.

**Mitigation**: Use dynamic address discovery for all non-trivially-derivable addresses (same approach as `ff7_data.h` — read relative call chains from anchor points). Hardcode only the topmost anchors (`0x60BACF`, `0xCBF578`, `0xDC0FC0`, `0xDBFD38`) and derive everything else dynamically. Document which addresses are hardcoded anchors vs. dynamically resolved. If the exe updates, only the anchors need updating.

---

## 7. Address Reference

### Confirmed Absolute Addresses (2013 Steam / 1.02 US exe)

| Symbol | Address | Source | Notes |
|--------|---------|--------|-------|
| `savemap` base | `0xDBFD38` | `externals_102_us.h` | 4340-byte game state region |
| `build_dialog_window` | `0x6E97E0` | `externals_102_us.h` | Dialog window creation |
| `menu_objects` | `0xDC0FC0` | `externals_102_us.h` | Global menu state container |
| `current_dialog_string_pointer` array | `0xCBF578` | `ff7.h` comment | DWORD[8] array of text pointers per window |
| `field_init_event_60BACF` | `0x60BACF` | FFNx function name convention | Anchor for opcode table discovery |
| `field_opcode_message_update_loop_630D50` | `0x630D50` | FFNx function name convention | Anchor for `opcode_message_loop_code` discovery |
| `field_text_box_window_create_631586` | `0x631586` | FFNx function name convention | Anchor for `current_dialog_string_pointer` confirmation |
| `field_opcode_ask_update_loop_6310A1` | `0x6310A1` | FFNx function name convention | Hook target for ASK option tracking |
| `world_opcode_message_sub_75EE86` | `0x75EE86` | FFNx function name convention | World map MESSAGE anchor |
| `world_opcode_ask_sub_75EEBB` | `0x75EEBB` | FFNx function name convention | World map ASK anchor |
| `world_sub_75EF46` | `0x75EF46` | FFNx function name convention | World map script sub, also calls message/ask |
| `display_battle_action_text_42782A` | `0x42782A` | FFNx function name convention | Battle action text entry |
| `menu_tutorial_sub_6C49FD` | `0x6C49FD` | FFNx function name convention | Tutorial/TUTOR dialog renderer |

### Dynamically Resolved (derived from anchors, not hardcoded)

| Symbol | How to Find | Used For |
|--------|------------|---------|
| `execute_opcode_table` | `read_rel_call(0x60BACF + 0x80)` then `read_abs_ref(result + 0x10D)` | Field opcode dispatch table to patch |
| `opcode_message` | `execute_opcode_table[0x40]` | Original MESSAGE handler (save before patching) |
| `opcode_ask` | `execute_opcode_table[0x48]` | Original ASK handler (save before patching) |
| `opcode_message_loop_code` | `read_abs_ref(0x630D50 + 0x12)` | Dialog state byte array (24-byte stride per window) |
| `battle_set_do_render_menu_call` | Dynamically from `ff7_data.h` chain | Battle menu entry point to hook |
| `update_display_text_queue` | Relative call chain from battle init | Battle text queue to replace |
| `get_kernel_text` | Relative call from `display_battle_action_text_42782A + 0x??` | Kernel.bin text lookup for battle strings |
| `g_active_actor_id` | `read_abs_ref(display_battle_action_text_42782A + 0x52)` | Current battle actor |
| `battle_context` | `read_abs_ref(battle_sub_41CCB2 + 0x5F)` | Full battle AI/state context |

### Addresses Still Needed (require additional RE)

| Symbol | Needed For | How to Find |
|--------|-----------|------------|
| Per-menu cursor index offsets | Main menu, item, magic, equip, status, etc. | Cheat Engine scan within `menu_objects` region; change value when cursor moves |
| Name entry grid cursor X/Y | Name entry screen accessibility | Cheat Engine scan; value changes as grid cursor moves |
| ATB gauge fill detection | "Whose turn" battle announcement | Within `battle_context->actor_vars` — ATB gauge is ~2 bytes per actor; exact offset needs confirmation |
| Field entity list base + entity count | Spatial audio for interactables | Known to exist near field initialization; needs exact pointer chase |
| World map player X/Y/Z (live address) | World map location announcements | Derives from savemap base `0xDBFD38 + 0x0F5C` |
| Text rendering function address | General menu text interception | Scan from `build_dialog_window` or menu rendering call chain |

---

## 8. Screen Reader Integration — Technical Details

### Tolk C API (used in the DLL)
- `Tolk_Load()` — initialize; auto-detects NVDA, JAWS, SAPI
- `Tolk_Speak(const wchar_t* str, bool interrupt)` — speak text; `interrupt=true` cancels ongoing speech
- `Tolk_Silence()` — stop current speech
- `Tolk_Unload()` — clean up on process exit
- `Tolk_Output(const wchar_t* str, bool interrupt)` — combined speech + braille output
- `Tolk_TrySAPI(bool tryIfNoDisplay)` — enable Windows SAPI fallback when no AT is running

Tolk is also used by Braver via its C# NuGet wrapper (`DavyKager.Tolk`). The DLL uses the native C API directly from `Tolk.dll` / `tolk.h`.

### Priority Queue for Battle
1. **Highest** — "It is [character]'s turn" (ATB full, command menu opened)
2. **High** — Target selection change (speak enemy name + rough HP)
3. **Medium** — Action started ("Cloud uses Fire 2")
4. **Lower** — Action result (damage numbers, status effects)
5. **Lowest** — Ambient state (enemy count, party HP) — dropped at high battle speed

Battle speed is readable from savemap at `0xDBFD38 + 0x10D8` (1 byte, 0–255). At speed > 200, drop priority 4 and 5 announcements.

### FF7 Text Encoding Quick Reference
```
0x00 – 0xE0  : encoded_byte + 0x20 = ASCII char
0xE0         : newline
0xEA         : Cloud
0xEB         : Barret
0xEC         : Tifa
0xED         : Aerith / Aeris
0xEE         : Red XIII
0xEF         : Yuffie
0xF0         : Cait Sith
0xF1         : Vincent
0xF2         : Cid
0xF8 + 2     : skip 2 bytes (used for formatting tokens)
0xEB + 3     : {item_name} dynamic token (4 bytes total)
0xEC + 3     : {number} dynamic token (4 bytes total)
0xED + 3     : {target_name} dynamic token (4 bytes total)
0xEE + 3     : {attack_name} dynamic token (4 bytes total)
0xFF         : end of string
```
Character name tokens (0xEA–0xF2) should be replaced with the actual equipped character name at runtime (readable from savemap). Dynamic tokens (0xEB–0xEF in the 4-byte sequence context) should be replaced with readable placeholders in v1.

---

## 9. Key Sources Used in This Research

- [Braver GitHub](https://github.com/ficed/Braver)
- [FFNx GitHub](https://github.com/julianxhokaxhiu/FFNx)
- [7th Heaven GitHub](https://github.com/tsunamods-codes/7th-Heaven)
- [FF7 Savemap — Final Fantasy Inside](https://wiki.ffrtt.ru/index.php/FF7/Savemap)
- [FF7 Field Script Opcodes — Final Fantasy Inside](https://wiki.ffrtt.ru/index.php/FF7/Field/Script/Opcodes)
- [FF6 Screen Reader Mod](https://github.com/BlindGuyNW/FF6ScreenReader) — MelonLoader + Tolk
- [FF5 Screen Reader Mod](https://github.com/bladestorm360/FF5-Screen-Reader) — MelonLoader + Tolk
- [Qhimm Forums](https://forums.qhimm.com/)
- [FFNx DeepWiki Architecture](https://deepwiki.com/julianxhokaxhiu/FFNx/1.1-getting-started-and-installation)
- [FF7 LGP Format — Qhimm Wiki](https://qhimm-modding.fandom.com/wiki/FF7/LGP_format)
- [Makou Reactor (field editor)](https://github.com/myst6re/makoureactor)
- [PCGamingWiki — FF7 2012/2013](https://www.pcgamingwiki.com/wiki/Final_Fantasy_VII_%282012%29)

---

## 9. Build History

### v1 — First Successful Compile — 2026-06-24

**Toolchain**: CMake 4.0.3 + MSVC 19.40 (Visual Studio BuildTools 2022), target x86 (32-bit)
**Output**: `AccessibilityMod/build/dist/Release/winmm.dll` — 220,672 bytes, x86 `14C machine`
**Exports**: 168 functions (167 runtime naked-JMP stubs + `timeGetTime` implemented by us)

**Scope of v1**:
- Field story dialog TTS (MESSAGE opcode 0x40) — state machine, page advance, silence on close
- Field choice menu TTS (ASK opcode 0x48) — speaks full text on open; per-option cursor tracking deferred to v2
- Config file (`ffvii_accessibility.cfg`) with per-feature toggles
- Full winmm proxy (168 exports), hook chain compatible with FFNx

**Key compile issues resolved**:

1. **`.def` forwarding is circular**: `funcname = WINMM.funcname` in a .def file requires `winmm.lib` at link time. Adding `winmm.lib` makes our DLL import from "winmm.dll" — which is us at runtime, creating infinite forwarding. **Fix**: runtime naked-JMP stubs loading the real System32 `winmm.dll` by absolute path via `LoadLibraryA`.

2. **MSVC STL requires `/EHsc`**: Disabling exceptions with `/EHs-c-` causes C4530 in every STL header (`string`, `fstream`, etc.) because MSVC's STL references exception internals even when the user never throws. **Fix**: use `/EHsc` (standard C++ exception handling).

3. **CMake .def file**: Use the source list, not `LINK_FLAGS "/DEF:..."`. Adding `winmm.def` to `add_library(... SHARED ...)` sources is the CMake-native idiom — it handles path quoting and establishes build dependencies automatically.

**What to test first** (before v2 work):
- Drop `winmm.dll` + `Tolk.dll` into FF7 install folder
- Verify story dialog is spoken on screen (MESSAGE opcode path)
- Verify "Choose:" prefix on first choice menu appearance (ASK opcode path)
- Confirm voice acting still works (FFNx chain not broken)
- Verify `speak_dialog = false` in config silences dialog TTS while menus still work
- If dialog TTS fires on wrong window: adjust `get_opcode_param_byte` index for ASK window_id (currently index 2; try 0 or 1 if wrong)
