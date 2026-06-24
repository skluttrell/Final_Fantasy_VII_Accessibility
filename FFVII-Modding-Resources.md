# Final Fantasy VII (2013 Steam) — Modding Resources

Compiled research for understanding and extending the FFVII-Access / Braver accessibility project.

---

## 1. Community Hubs

### Qhimm Forums
- **URL**: https://forums.qhimm.com/
- Primary hub for FF7 PC modding since the late 1990s. Contains threads on memory addresses, reverse engineering, tools, and mod releases.
- Key threads:
  - [Memory Addresses (FF7 1.02)](https://forums.qhimm.com/index.php?topic=12914.0) — documented hex addresses for the 1.02 retail build; many carry over to the 2013 Steam version
  - [Memory address in FF7 PC](http://forums.qhimm.com/index.php?topic=5796.0) — additional memory discussion
  - [Braver — open source FF7 engine reimplementation](https://forums.qhimm.com/index.php?topic=21360.0) — discussion thread for the Braver project
  - [FFNx — Next generation modding platform for FF7/FF8](https://forums.qhimm.com/index.php?topic=19970.0)
  - [The Big List of Mods](https://forums.qhimm.com/index.php?topic=12503.0)

### Technical Wikis
- **Final Fantasy Inside (FFRTT)**: https://wiki.ffrtt.ru/index.php/ — most complete technical reference for FF7/FF8 internals
- **FF7 Flat Wiki**: https://ff7-mods.github.io/ff7-flat-wiki/ — mirrors and extends FFRTT documentation
- **Qhimm Modding Wiki (Fandom)**: https://qhimm-modding.fandom.com/wiki/FF7 — additional format and tool documentation

### PCGamingWiki
- [Final Fantasy VII (2012/2013)](https://www.pcgamingwiki.com/wiki/Final_Fantasy_VII_%282012%29) — version info, DRM notes, save locations, mod compatibility

---

## 2. Open-Source Engine Reimplementations

### Braver (Primary project — current approach)
- **GitHub**: https://github.com/ficed/Braver
- **Website**: https://braver.ficedula.co.uk/
- .NET 7 / MonoGame reimplementation of the FF7 PC engine. Reads original game LGP archives and EXE data as input; does not run the original FF7.exe.
- Current status: Early beta. Field ~60% functional, battle ~75% AI implemented. Cannot yet support full playthrough.
- Accessibility: Tolk TTS plugin (screen reader + spatial audio). Field dialog, menu, and screen-change announcements implemented. Battle plugin interface declared but not yet hooked up.
- 7th Heaven compatibility: `Braver.7HShim` plugin reads `.iro` archives and loose mod directories, adding them as data sources. Does **not** integrate with 7th Heaven's GUI or activation workflow.

### ff7-fenrir (Web-based)
- **GitHub**: https://github.com/dangarfield/ff7-fenrir
- Complete FF7 engine in Three.js / JavaScript. Different target (browser). Useful reference for game logic.

---

## 3. FFNx — The Standard Modding Driver

### Overview
- **GitHub**: https://github.com/julianxhokaxhiu/FFNx
- Evolution of the original FF7_OpenGL driver by Aali. A "next generation modding platform" for FF7/FF8.
- Supports: 2013 Steam, 2026 Steam Re-release, GOG, Windows Store, and the original 1998/2000 retail releases.

### How It Hooks Into FF7
- **Proxy DLL replacement**: For the 2013 Steam version, FFNx replaces `AF3DN.P` (the original Eidos/Square Direct3D driver that FF7.exe loads automatically at startup). FFNx is dropped in as a drop-in replacement.
- **Memory scanning**: On load, FFNx scans the game's memory to locate engine-specific function addresses (`ff7_find_externals`), then replaces those original game functions with its own implementations via patching primitives.
- **Rendering backends**: DirectX 11 (default), DirectX 12, Vulkan, OpenGL.
- **Game state exposure**: FFNx exposes an `imgui`-based debug overlay that shows in-game engine data. The HEXT patching system allows byte-level patching of the game executable at runtime.
- **No formal third-party plugin API** has been found in the documentation. Extensions are built into FFNx itself (it is compiled from source). However, because it performs memory function replacement, a secondary proxy DLL wrapping it could theoretically intercept the same calls.

### 7th Heaven's Relationship to FFNx
- **7th Heaven** (https://github.com/tsunamods-codes/7th-Heaven) works by installing FFNx and then intercepting resource requests. 7th Heaven creates a separate modded copy of the game folder, points to ff7.exe, and FFNx handles redirecting texture/model/audio requests to mod files.
- When users run 7th Heaven, they are running the original `ff7.exe` with FFNx loaded as the graphics driver. Mod data is fed through FFNx's file override system.
- This means: **any accessibility hook that works with FFNx works transparently with 7th Heaven**, because the two are already coupled.

### Related Projects
- **ff7gx** (older): https://github.com/dwarfcrank/ff7gx — earlier graphics extender, predecessor concept
- **FF7_OpenGL by Aali** — original DLL replacement that FFNx evolved from

---

## 4. Memory Addresses & Game State

### Savemap (Save File / In-Memory Game State)
Full documentation: https://wiki.ffrtt.ru/index.php/FF7/Savemap and https://datacrystal.tcrf.net/wiki/Final_Fantasy_VII/Save_map

The "Savemap" is a 4,340-byte region of game state. On the PC version, most of this data is mirrored in RAM at runtime (not only on disk). Key offsets (relative to savemap base):

| Offset | Size | Description |
|--------|------|-------------|
| `0x0018`–`0x001E` | 6 bytes | Lead character current/max HP and MP (preview) |
| `0x002C`–`0x0032` | 6 bytes | Character record: current/max HP and MP |
| `0x0B94` | 1 byte | Current module (1 = field, 3 = world map) |
| `0x0B96` | 2 bytes | Current field map ID |
| `0x0B9A`–`0x0B9C` | 4 bytes | X/Y coordinates on field map (signed) |
| `0x0B9E` | 2 bytes | Triangle/walkmesh ID on field map |
| `0x0BA0` | 2 bytes | Player model direction |
| `0x0BB4`–`0x0BB7` | 4 bytes | Game timer (hours, minutes, seconds, frames) |
| `0x0BB8`–`0x0BBB` | 4 bytes | Countdown timer |
| `0x0BBC` | 2 bytes | Number of battles fought |
| `0x0BC0`–`0x0BC2` | 3 bytes | Menu visibility/locking masks (item, magic, materia, equip, status, etc.) |
| `0x0B7C` | 4 bytes | Gil amount |
| `0x0CEE` | 2 bytes | GP (0–10000) |
| `0x0F5C`–`0x0F63` | 8 bytes | World map position (X, Y, Z + altitude) |
| `0x10D8`–`0x10DB` | 4 bytes | Battle speed, message speed, config settings |
| `0x0BEF+` | variable | Field-specific event flags (story progression) |
| `0x0E0C` | 1 byte | Final battle flag (`0x08` = in final battle) |

**Note**: These are savemap offsets. For live memory scanning, the absolute addresses differ per game version and ASLR. The Qhimm thread at `topic=12914.0` documents absolute addresses for the 1.02 retail build. The Steam 2013 version's absolute addresses require independent scanning.

### Finding Live Runtime Addresses
- Use **Cheat Engine** (https://www.cheatengine.org/) to scan FF7.exe at runtime.
- For the 2026 re-release: FearLess Cheat Engine community at https://fearlessrevolution.com/viewtopic.php?t=38397 has posted tables.
- For the 2013 Steam version: start with the savemap offsets above, then scan for values at known offsets from the savemap base pointer.

---

## 5. Field Script VM

### Documentation
- **Opcode reference**: https://wiki.ffrtt.ru/index.php/FF7/Field/Script/Opcodes
- **Script structure**: https://ff7-mods.github.io/ff7-flat-wiki/FF7/Field/Script.html

### Key Facts
- The field scripting system is a custom bytecode VM with **246 opcodes**.
- Scripts are organized in pointer tables of 64 bytes (32 scripts max per section).
- Scripts run per-entity (player, NPCs, triggers) as cooperative coroutines.

### Opcode Categories Relevant to Accessibility

| Category | Example Opcodes | Accessibility Relevance |
|----------|----------------|------------------------|
| Windowing & Menu | `40 MESSAGE`, `41 MPARA`, `43 MPNAM`, `48 ASK`, `49 MENU` | Dialog display, choice prompts, menu activation |
| Field Models / Position | `75 PXYZI`, `A5 XYZI` | Player and entity coordinates |
| Script Flow | jump, conditional, loop | Detecting when events fire |
| Party & Inventory | item, materia ops | Menu state |
| Camera, Audio, Video | sound, video ops | Synchronization for audio description |

### Tools for Field Script Editing
- **Makou Reactor** (https://github.com/myst6re/makoureactor / SourceForge) — full field editor with script editing, dialog editing, model preview
- **Hades Workshop** — comprehensive PSX/PC editor
- **ff7tk** (https://github.com/sithlord48/ff7tk) — C++ toolkit library used by Black Chocobo and Makou Reactor

---

## 6. File Formats & Modding Tools

### Archive Formats
| Format | Description | Documentation |
|--------|-------------|---------------|
| LGP | Primary archive format, PC-only. Filename-indexed volume. | https://qhimm-modding.fandom.com/wiki/FF7/LGP_format |
| KERNEL.BIN | 27 gzipped sections containing game data (items, materia, equipment stats, texts) | https://ff7-mods.github.io/ff7-flat-wiki/FF7/Kernel/Kernel.bin.html |
| .IRO | 7th Heaven mod archive format (IrosArchive). Used by Braver.7HShim | Ficedula's IrosArchive library |

### Key Tools
| Tool | Purpose | Source |
|------|---------|--------|
| **WallMarket** | KERNEL.BIN editor | https://www.ff7catalog.com/threads/psx-pc-kernel-bin-editor-wallmarket-v1-4-5.5149/ |
| **Makou Reactor** | Field script + dialog editor | https://github.com/myst6re/makoureactor |
| **Black Chocobo** | Save editor | https://github.com/sithlord48/blackchocobo |
| **Elena** | .NET library for reading KERNEL.BIN and LGP files | https://github.com/Shojy/Elena |
| **ff7tk** | C++ toolkit used by modding tools | https://github.com/sithlord48/ff7tk |
| **CrossSlash** | LGP editor (included in Braver solution) | Braver\CrossSlash\ |
| **FFNx** | Graphics driver + mod platform | https://github.com/julianxhokaxhiu/FFNx |
| **7th Heaven** | Mod manager (uses FFNx under the hood) | https://github.com/tsunamods-codes/7th-Heaven |

---

## 7. Accessibility Mods for Other Final Fantasy Games

These projects use directly comparable approaches and are the closest analogues:

### FF6 Pixel Remaster Screen Reader
- **GitHub**: https://github.com/BlindGuyNW/FF6ScreenReader
- **Tech stack**: MelonLoader (mod injection into Unity) + Tolk (screen reader abstraction DLL)
- **Language**: C# (99.6%)
- **Features**: Menu navigation, battle announcements (attacks, damage, XP), field map entities (NPCs, chests, exits), character status
- **Limitation**: Pathfinding can suggest unavailable paths

### FF5 Pixel Remaster Screen Reader
- **GitHub**: https://github.com/bladestorm360/FF5-Screen-Reader
- **Tech stack**: MelonLoader + Tolk (NVDAControllerClient64.dll + tolk.dll)
- **Language**: C# (99.9%)
- **Features**: Menu selections, character stats, battle info, NPC dialogue, location data, inventory
- **Advantage**: Direct plugin-to-game-state access; no memory reverse-engineering needed since MelonLoader runs inside the process with native access to game objects

### FF3 and FF4 Screen Readers
- **FF3**: https://github.com/bladestorm360/FF3-Screen-Reader
- **FF4**: https://github.com/bladestorm360/FF4-Screen-Reader
- Same MelonLoader + Tolk approach as FF5

**Key insight**: All these Pixel Remaster mods work because the Pixel Remasters run on Unity, which MelonLoader supports. FF7 2013 Steam does **not** run on Unity — it uses a custom C++ engine with a custom Direct3D driver (AF3DN.P / FFNx). MelonLoader is not applicable.

### Tolk Library
- Tolk is the common screen reader abstraction layer used by both the FF Pixel Remaster mods AND the Braver.Tolk plugin.
- **GitHub**: https://github.com/ndarilek/tolk (C library, C# wrapper available)
- Supports NVDA, JAWS, SAPI, System Access, Window-Eyes
- The Braver project already uses `DavyKager.Tolk` NuGet package

---

## 8. Reverse Engineering Resources

### IDA / Ghidra Analysis
- FFNx's development involved IDA and Ghidra to locate hook points in FF7.exe. No public IDA database or symbol map file has been found in open repositories.
- The Qhimm community (forums + Discord) is the most likely place to find private RE work.

### Known Hook Points (from FFNx source)
- `ff7_find_externals` in `ff7_data.h` — FFNx's internal function that scans the process to locate all engine symbols dynamically. This file is the definitive reference for how to find any address in the 2013 Steam exe.
- Registry key `DriverPath` / `Graphics` — used by 1998 retail to load the driver; the Steam version uses the proxy DLL mechanism instead.
- `voice_init()` in `src/voice.cpp` — the exact sequence FFNx uses to hook MESSAGE (0x40), ASK (0x48), and battle text. The accessibility DLL replicates this pattern for TTS instead of audio playback.

### FFNx Dynamic Address Discovery Pattern
FFNx resolves addresses by following call chains from known anchor points rather than hardcoding. The pattern used in `ff7_data.h`:
```cpp
// get_relative_call(base, offset):
//   reads the 4-byte relative displacement at (base + offset + 1)
//   returns the absolute target = base + offset + 5 + displacement
//
// get_absolute_value(base, offset):
//   reads the 4-byte absolute address embedded in an instruction
//   at (base + offset + N) where N depends on the instruction type

// To find the opcode dispatch table:
execute_opcode = get_relative_call(0x60BACF, 0x80);   // field_init_event → execute_opcode func
execute_opcode_table = get_absolute_value(execute_opcode, 0x10D);  // absolute ref inside func

// To find dialog state array:
opcode_message_loop_code = get_absolute_value(0x630D50, 0x12);

// To find dialog text pointer array:
current_dialog_string_pointer = get_absolute_value(0x631586, 0x154);  // == 0xCBF578
```

### FFNx Naming Convention
FFNx names functions by their **absolute address in the 1.02 US exe**, e.g.:
- `field_init_event_60BACF` → address `0x60BACF`
- `display_battle_action_text_42782A` → address `0x42782A`
- `world_opcode_message_sub_75EE86` → address `0x75EE86`

The 2013 Steam exe shares the same addresses as the 1.02 US retail build. This naming convention means any `_XXXXXX` suffix in FFNx source is a confirmed absolute address.

### Qhimm Discord
- Qhimm has an active Discord community where reverse engineering discussions happen. The Braver project documentation mentions the "Qhimm Discord" as a community resource.

---

## 9. FFNx Source File Reference

Key source files in the FFNx repository relevant to the accessibility DLL project:

| File | Contents |
|------|---------|
| `src/voice.cpp` | Complete dialog + battle TTS hook implementation. MESSAGE/ASK/battle text hooks. The primary template for our accessibility DLL. |
| `src/voice.h` | Declares `voice_init()` and `ff7_handle_wmode_reset()`. |
| `src/externals_102_us.h` | Hardcoded absolute addresses for the 1.02 US / 2013 Steam exe. `savemap`, `menu_objects`, `build_dialog_window`, and ~200 others. |
| `src/ff7_data.h` | Dynamic address discovery chains. Source of truth for how every runtime address is found. |
| `src/ff7.h` | Structure declarations for `ff7_externals`, `common_externals`, and all game data structures. |
| `src/ff7/field/opcode.h` | Full `FieldOpcode` enum (246 opcodes). Opcode-to-index mapping. `original_opcode_table` declaration. |
| `src/ff7/battle/defs.h` | Battle function declarations: `battle_menu_enter()`, `display_battle_action_text_sub_6D71FA()`, `draw_ui_graphics_objects_wrapper()`. |
| `src/ff7/battle/menu.cpp` | `battle_menu_enter()` and `battle_depth_clear()` implementations. |
| `src/ff7/field/defs.h` | Field initialization and texture loading function declarations. |
| `src/patch.h` | `patch_code_dword()`, `replace_function()`, `replace_call_function()` — the patching primitives FFNx uses to hook game functions. |
| `src/common.h` | `common_externals` structure definition including `execute_opcode_table` pointer. |

---

## 9. Notes on the 2013 vs 2026 Steam Release

The 2013 Steam version (app ID 39140) is the version targeted by 7th Heaven and FFNx. A new re-release appeared on Steam in 2026 (new app ID). FFNx explicitly supports both.

The 2013 version:
- Custom C++/DirectX engine, no middleware framework (unlike Unity-based Pixel Remasters)
- Loads `AF3DN.P` as graphics driver (FFNx replaces this)
- DRM: Steam DRM only (no SecuROM after the 2013 update)
- Save data: `%LOCALAPPDATA%\FINAL FANTASY VII Steam Edition\<SteamID64>\`
