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

> **Version compatibility:** This mod targets the **2013 Steam release** of Final Fantasy VII (exe version 1.02 US). It uses hardcoded memory addresses specific to that build and will not work with the 2026 remake or any other version of the game.

## Requirements

- Final Fantasy VII (2013 Steam Edition)
- A screen reader: **NVDA** (recommended), **JAWS**, or Windows **Narrator / SAPI**
- The **Tolk** screen reader library (free — download instructions below)

---

## Installation

1. Download the latest release and extract the zip.

2. Copy these files into your **FF7 install folder** (the folder that contains `FF7.exe`):
   ```
   version.dll
   Tolk.dll
   nvdaControllerClient32.dll
   ffvii_accessibility.cfg
   ```

3. Launch the game normally, either through Steam or 7th Heaven. Nothing else to configure.

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
