# FF7 Accessibility Mod

A TTS / screen reader mod for **Final Fantasy VII (2013 Steam Edition)** that reads game text aloud for blind and visually impaired players. Drop the files into your FF7 folder — no other changes to your game or mod setup required.

---

## What It Does

- **Story dialog** is spoken aloud, paced page-by-page as you advance, with character names announced
  before their lines ("Cloud: Not interested.")
- **Choice menus** are read aloud when they appear, and the highlighted option is re-announced as you
  move the cursor between them
- **Full battle support**: action/attack/spell announcements, a spoken battle menu (command, magic, item,
  and target-selection cursors), whose turn it is, enemy defeat, and the victory/results screens (EXP,
  AP, gil, item drops, level-ups)
- **Field navigation**: a destination browser (Exits / People / Save points / Triggers / Items) you can
  cycle with the keyboard or a controller's right stick, turn-by-turn walking directions computed over
  the field's walkmesh, a proximity chirp near anything interactive, and a tone when you walk into a wall
- **Menus**: title screen, main menu, Config sub-menu, Save/Continue menus (previewed from disk), the
  Item menu, the Order (party reorder) menu, and the Status screen all speak their cursors and content
- **Countdown-timer support** for the game's timed escape sequences: automatic time-remaining
  announcements plus on-demand and freeze hotkeys
- Audio cues (short tones, independent of the TTS narration) for a dialog box waiting on your confirm
  button, a choice menu appearing, and wandering/wall-bump/interaction-range feedback
- Works alongside **7th Heaven**, **FFNx**, voice acting packs, and footstep audio mods with no conflicts

### Current Limitations

- Nested choice trees (a choice that leads straight into another choice) can go silent, including the
  intro text — being investigated.
- A few short "flash text" dialog screens (very brief single-line messages) can be spoken as one block
  instead of one utterance per on-screen page.
- Controller-button icon glyphs embedded in some dialog text (Circle/Triangle/Square/Cross icons) are
  silently skipped rather than announced as words.
- The Item menu's Arrange popup and Key Items pane are not yet narrated.
- World map dialog (as opposed to field dialog) is not yet supported.

See `TODO.txt` in the repo for the full, current list of known issues and their status.

### Planned for a Future Update

- World map dialog narration
- Item menu: Arrange popup and Key Items pane
- Magic/Materia screen narration

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
All settings default to `true` except `speak_enemy_hp_always` and `debug_log`, which default to `false`.

```ini
# Story dialog TTS. Set false if you use a voice acting mod and prefer voice acting over TTS.
speak_dialog = true

# Choice menu TTS, including cursor tracking as you move between options. Recommended true even
# with speak_dialog = false, since voice mods don't typically cover every choice line.
speak_choices = true

# Battle action text (attack/spell/item names as they happen).
speak_battle = true

# The in-battle command/magic/item/target menu cursor, spoken as it moves. Separate from
# speak_battle so you can have quiet menus but spoken actions, or vice versa.
speak_battle_menu = true

# Menu navigation: title screen, main menu + Quit dialog, Config/Sound sub-menus, name entry.
speak_menus = true

# If true, enemy HP is always spoken during targeting, even before you've used Sense on that
# enemy. Default false matches the sighted game, which hides enemy HP until Sense.
speak_enemy_hp_always = false

# The field-navigation destination browser hotkeys (see accessiblity_keys.txt for the full list:
# J/L cycle destinations, Shift+J/L cycle categories, K announces, \ or P gives directions, M
# announces the map name).
pathfinder_keys = true

# Direction style for the pathfinder's directions key: "turns" (turn-by-turn walkmesh route,
# routes around walls/pits) or "line" (straight-line bearing and distance).
direction_style = turns

# Announce "Screen: <name>" whenever you cross to a new field screen (each has its own camera).
announce_map_change = true

# Right analog stick support for the pathfinder browser (XInput controllers).
gamepad_nav = true

# A short chirp when you come within interaction range of something usable (person, chest,
# save point, trigger line).
proximity_tone = true

# Automatic announcements (start, minute marks, final countdown) for the game's timed-escape
# clock. The T (read time) and Shift+T (freeze) hotkeys always work regardless of this setting.
timer_announcements = true

# A short tone when a story dialog box is sitting and waiting for your confirm button press.
dialog_wait_tone = true

# A short double-tone the instant a choice menu appears.
dialog_choice_tone = true

# A short tone while you're pushing against a wall/obstacle on a field map (FF7 has no
# footstep sound, so this is the only feedback that you're stuck rather than walking).
wall_bump_tone = true

# When new text starts, interrupt (cancel) speech currently playing.
# true  = new text starts immediately
# false = waits for current speech to finish
interrupt = true

# Write diagnostic messages to ffvii_accessibility.log (overwritten each session). Turn this on
# when reporting a bug, then send the log file alongside your report.
debug_log = false
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
