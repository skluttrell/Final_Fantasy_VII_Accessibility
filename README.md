# FF7 Accessibility Mod

A screen reader / TTS accessibility mod for **Final Fantasy VII (2013 Steam Edition)**, built for blind and visually impaired players.

Implemented as a `version.dll` proxy DLL. Drop it into your FF7 install folder alongside your existing mods — no changes to your workflow required.

---

## What It Does

| Feature | Status |
|---------|--------|
| Story dialog spoken aloud (field maps) | ✅ v1 |
| Choice menu text spoken on open | ✅ v1 |
| Per-option TTS as cursor moves in menus | 🔜 v2 |
| Battle action text (attack/spell names) | 🔜 v2 |
| Whose turn announcement in battle | 🔜 v2 |
| Main menu navigation narration | 🔜 v2 |
| World map dialog | 🔜 v2 |
| Name entry screen | 🔜 v2 |

Works with **NVDA**, **JAWS**, and Windows **SAPI** (Narrator / any SAPI voice). Automatically detects which screen reader is running.

---

## Compatibility

- **7th Heaven mods** — fully compatible. The mod adds DLL files to the FF7 folder; it does not replace the executable or conflict with 7th Heaven's mod management.
- **FFNx** (graphics/audio/voice acting mod used by 7th Heaven) — fully compatible. If FFNx has hooked into game functions before us, we chain through FFNx's handlers. Voice acting and TTS fire simultaneously.
- **Voice acting packs** (e.g., Echo-S) — compatible. Use `speak_dialog = false` in the config file if you prefer to hear the voice actors rather than the screen reader reading dialog text. Choice menus, battle, and main menu TTS are controlled separately.
- **Footstep audio mods** — compatible.
- **Other winmm.dll proxies** (e.g., Reunion mod) — fully compatible. We no longer use `winmm.dll`; we use `version.dll` instead, so there is no conflict with other winmm proxies.

---

## Installation

### Requirements

- Final Fantasy VII (2013 Steam Edition, version 1.02 US / the unpatched Steam exe)
- A supported screen reader: NVDA, JAWS, or Windows built-in Narrator/SAPI
- Tolk screen reader library (`Tolk.dll` and its companion DLLs — see below)

### Steps

1. Download the release and extract it.
2. Copy all files into your **FF7 install folder** (the folder containing `FF7.exe`):
   ```
   FF7 install folder/
     version.dll                 ← the accessibility mod
     Tolk.dll                    ← screen reader library
     nvdaControllerClient32.dll  ← NVDA support
     ffvii_accessibility.cfg     ← configuration (edit to your preference)
   ```
3. Launch FF7 normally (via Steam or 7th Heaven). No other steps needed.

To uninstall, delete those files.

### Getting Tolk

Tolk is a free screen reader abstraction library. Download a release from the [Tolk GitHub releases page](https://github.com/ndarilek/tolk/releases) and copy `Tolk.dll` and `nvdaControllerClient32.dll` (32-bit versions) into your FF7 folder.

---

## Configuration

Edit `ffvii_accessibility.cfg` in your FF7 folder with any text editor. Reload by restarting the game.

```ini
# Speak story dialog text (set false if using a voice acting mod and prefer voice over TTS)
speak_dialog = true

# Speak choice menu text when a menu opens (always useful, even with voice acting)
speak_choices = true

# Speak battle action text (reserved for v2)
speak_battle = true

# Speak main menu navigation (reserved for v2)
speak_menus = true

# Whether new speech interrupts (cancels) currently playing speech
# true  = new text starts immediately (good for fast readers)
# false = new text waits for current speech to finish
interrupt = true
```

---

## Building from Source

### Requirements

- CMake 3.16 or newer
- MSVC (Visual Studio 2019 or 2022, or Build Tools) with x86/Win32 target
- Windows SDK

**The DLL must be built as 32-bit (x86).** FF7 2013 Steam is a 32-bit process and cannot load a 64-bit DLL.

```powershell
git clone <this-repo>
cd FFVII-Access/AccessibilityMod

# Configure for 32-bit
cmake -B build -A Win32

# Build Release
cmake --build build --config Release

# Output: build/dist/Release/version.dll
```

Copy `build/dist/Release/version.dll` to your FF7 folder alongside `Tolk.dll` and `ffvii_accessibility.cfg`.

### Build History

- **v1.0 (2026-06-24)**: First compile as `winmm.dll` — 220 KB, 168 exports. Crashed on first test: FFNx's `ff7_find_externals` walked our naked JMP stubs as if they were real winmm code and crashed with Exception 0xc0000005.
- **v1.1 (2026-06-24)**: Switched to `version.dll` proxy — 205 KB, 17 exports. Fixes the FFNx crash. Background thread replaces timeGetTime trigger. Resolved readiness check widened to accept FFNx-patched addresses.

---

## Technical Overview

### How the Proxy Works

FF7 (and FFNx) import `version.dll` for version resource lookups. By placing our DLL in the FF7 folder, Windows loads it instead of the system copy. Our DLL:

1. At load time (`DllMain`): loads the **real** system `version.dll` from `System32` by its full path, capturing all 17 real function pointers. Spawns a background init thread.
2. For all 17 version.dll exports: implements a **naked JMP stub** that redirects to the real system function with zero overhead.
3. The **background thread** (started from `DllMain`, runs after the loader lock releases): waits 200ms, loads config and TTS, then polls every 50ms until FF7's field module is ready, then installs hooks.

**Why not `winmm.dll`**: FFNx's address resolution (`ff7_find_externals`) uses `GetModuleHandle("winmm.dll")` as an anchor, then walks the real winmm code at specific offsets. When we were `winmm.dll`, it got our JMP stubs instead of real code, found unexpected bytes, and crashed. `version.dll` is not used by FFNx for this purpose.

### Hook Mechanism

No MinHook or external hooking library. The FF7 field script VM dispatches opcodes through a `uint32_t[256]` table of function pointers. We overwrite two entries using `VirtualProtect` + direct DWORD write:

```
execute_opcode_table[0x40]  ← our hook_message (was: FFNx handler or FF7 original)
execute_opcode_table[0x48]  ← our hook_ask     (was: FFNx handler or FF7 original)
```

Each hook saves the previous pointer and calls it at the end — forming the chain:

```
our_tts_hook  →  FFNx_voice_hook  →  original_FF7_handler
```

Both voice acting (via FFNx) and TTS (via us) fire on every dialog event. Neither blocks the other.

### Dialog State Machine

The MESSAGE and ASK opcodes are called every game frame while a window is open. A state byte at `opcode_message_loop_code[24 * window_id]` tracks each window's lifecycle. We detect:

- `0 → nonzero` transition: dialog starting — speak the text now
- `14 → 2` or `4 → 8`: page advance — speak the new page text  
- `any → 7`: dialog closing — silence TTS

### Address Discovery

The opcode table address is not hardcoded. At runtime, `FF7Addr::Resolve()` walks two instruction chains from known anchor function addresses (whose values are fixed in the 2013 Steam exe):

```
FIELD_INIT_EVENT (0x60BACF)
  → +0x80  relative CALL  → execute_opcode function
  → +0x10D absolute ref   → execute_opcode_table pointer

OPCODE_MSG_UPDATE_LOOP (0x630D50)
  → +0x12  absolute ref   → opcode_message_loop_code pointer
```

This mirrors the address discovery pattern used by FFNx (`FFNx/src/ff7_data.h`).

### FF7 Text Encoding

FF7 uses a custom 8-bit encoding where `byte + 0x20 = ASCII character`. Special tokens handle character names (0xEA–0xF2), newlines (0xE0), dynamic placeholders, and end-of-string (0xFF). The `FF7Text::Decode()` function translates to `std::wstring` for Tolk output.

---

## Project Structure

```
FFVII-Access/
  AccessibilityMod/
    deps/tolk/
      Tolk.h                  Tolk C API declarations
    src/
      ff7_addresses.h/.cpp    Fixed addresses + runtime Resolve()
      ff7_text.h/.cpp         FF7 encoding → wstring decoder
      config.h/.cpp           ffvii_accessibility.cfg parser
      tts.h/.cpp              Tolk runtime loader + speak/silence API
      hooks.h/.cpp            Opcode table patching (MESSAGE, ASK)
      proxy.h/.cpp            17 naked-JMP stubs + background init thread
      dllmain.cpp             DLL entry point
    version.def               Export names (17 version.dll exports)
    CMakeLists.txt            CMake build (x86 enforced)
    ffvii_accessibility.cfg   Default configuration
  FFNx/                       FFNx source (reference — not modified)
  Braver/                     Braver engine (reference — not active)
  FFVII-Accessibility-Research.md   Technical analysis and address reference
  FFVII-Modding-Resources.md        Modding community resources
```

---

## Research & Reference

Technical details, all known addresses, hook points, v2 plans, and known hurdles with mitigations are documented in [`FFVII-Accessibility-Research.md`](FFVII-Accessibility-Research.md).

The hook architecture is derived from [`FFNx/src/voice.cpp`](FFNx/src/voice.cpp), which implements voice acting for the same hook points. Our TTS mod is a subset of FFNx's voice system.

---

## License

This mod is provided for accessibility purposes. The FF7 game data, FFNx, Tolk, and 7th Heaven are separate projects with their own licenses.
