# FF7 Accessibility Mod

A TTS / screen reader mod for **Final Fantasy VII (2013 Steam Edition)** that reads game text aloud for blind and visually impaired players. Drop the files into your FF7 folder — no other changes to your game or mod setup required.

---

## What It Does

- **Story dialog** is spoken aloud as each dialog box opens and when you advance to the next page
- **Choice menus** are read aloud when they appear, including all available options
- Character names are announced before their dialog ("Cloud: Not interested.")
- Works alongside **7th Heaven**, **FFNx**, voice acting packs, and footstep audio mods with no conflicts

### Current Limitations

Apostrophes and curly quotes come out as spaces in the spoken text ("I'm" becomes "I m"). This is a known issue and will be fixed in a future update.

### Planned for a Future Update

- Per-option TTS as you move the cursor through menus and choices
- Battle action announcements (attacks, spells, whose turn it is)
- Main menu, item, magic, and status screen narration
- World map dialog

---

> **Version compatibility:** This mod uses hardcoded memory addresses discovered against the **2013
> Steam release** of Final Fantasy VII (exe version 1.02 US). Confirmed 2026-07-08: it also works
> unmodified against the **2026 Steam/GOG rerelease** of the original game — that release bundles the
> same underlying engine build, just in a different folder layout (see below). This does **not** cover
> Final Fantasy VII Remake / Rebirth (the separate Unreal Engine action-RPG trilogy) — those are
> unrelated games built on a completely different engine.

## Requirements

- Final Fantasy VII: either the **2013 Steam Edition** or the **2026 Steam/GOG rerelease** (plain
  "FINAL FANTASY VII" on Steam) of the original game, with FFNx installed
- A screen reader: **NVDA** (recommended), **JAWS**, or Windows **Narrator / SAPI**
- The **Tolk** screen reader library (free — download instructions below)

---

## Installation

1. Download the latest release and extract the zip.

2. Copy these four files into the correct folder for your version:
   ```
   version.dll
   Tolk.dll
   nvdaControllerClient32.dll
   ffvii_accessibility.cfg
   ```
   - **2013 Steam Edition**: the folder containing `FF7.exe` (your game install root).
   - **2026 Steam/GOG rerelease**: `ff7\workingdir\`, alongside FFNx and the renamed `ff7_en.exe` —
     **not** the top-level game folder (that's a separate .NET launcher, not the game engine). See
     `FFVII-2026-Project.md` for full 2026 setup steps if you haven't installed FFNx there yet.

3. Launch the game normally — 2013: through Steam or 7th Heaven; 2026: run `ff7_en.exe` directly from
   `ff7\workingdir\` (this bypasses the new launcher, which is expected). Nothing else to configure.

To uninstall, delete those four files.

### Getting Tolk

Tolk is a free library that bridges this mod to your screen reader. Download it from the [Tolk GitHub releases page](https://github.com/ndarilek/tolk/releases). You need the **32-bit** versions of `Tolk.dll` and `nvdaControllerClient32.dll`.

---

## Configuration

Open `ffvii_accessibility.cfg` in Notepad or any text editor. Restart the game after saving changes.

```ini
# Read story dialog aloud
# Set to false if you use a voice acting mod and prefer voice acting over TTS
speak_dialog = true

# Read choice menus aloud when they open
speak_choices = true

# When new text starts, interrupt (cancel) speech currently playing
# true  = new text starts immediately
# false = waits for current speech to finish
interrupt = true
```

---

## Troubleshooting

**Nothing is spoken at all**
- Make sure `Tolk.dll` and `nvdaControllerClient32.dll` are in the same folder as `FF7.exe`.
- Make sure your screen reader (NVDA, JAWS, or Narrator) is running before launching FF7.

**Voice acting plays but TTS is silent**
- Check that `speak_dialog = true` in `ffvii_accessibility.cfg`.

**TTS and voice acting both play at the same time**
- This is expected behavior — both run simultaneously. Set `speak_dialog = false` in the config to hear only the voice actors for story dialog. Choice menus are controlled separately by `speak_choices`.
