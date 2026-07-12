/*
 * config.h -- User configuration for the FF7 accessibility mod.
 *
 * Configuration is read from "ffvii_accessibility.cfg" in the same directory
 * as this DLL (the FF7 install folder). The file uses a simple key=value
 * format with # for comments.
 *
 * If the config file does not exist, all settings use their defaults.
 * Unknown keys are ignored silently to allow forward compatibility.
 */

#pragma once

namespace Config {

// All mod settings are stored in this struct. One global instance is populated
// by Load() and read by all hook functions.
struct Settings {
    // speak_dialog: If true, story dialog text (MESSAGE opcode) is read aloud
    // by the screen reader. Set to false if you have a voice acting mod
    // installed and prefer the voice actors over TTS.
    // Default: true.
    bool speak_dialog = true;

    // speak_choices: If true, choice menu options (ASK opcode) are read aloud
    // as the cursor moves between them. Recommended true even when speak_dialog=false,
    // since choices require acknowledgement and voice mods typically do not
    // cover every choice line.
    // Default: true.
    bool speak_choices = true;

    // speak_battle: If true, battle action text is read aloud (attack names,
    // spell names, item use text). Default: true.
    bool speak_battle = true;

    // speak_menus: If true, menu navigation is announced. Covers the title
    // screen cursor, main menu cursor + Quit dialog, Config sub-menu rows and
    // values, Sound sub-menu cursor and volumes, and the name-entry screen
    // (grid cursor + name readback). Default: true.
    bool speak_menus = true;

    // wall_bump_tone: If true, a short low tone plays while the player pushes
    // against a wall or obstacle on a field map (direction held but the
    // character is not moving). Vanilla FF7 has no footstep sounds, so without
    // this there is no audio cue distinguishing "walking" from "stuck on a
    // wall" — a blind player can walk against a wall indefinitely without
    // knowing. The tone repeats every ~300ms for as long as contact continues.
    // Default: true.
    bool wall_bump_tone = true;

    // interrupt: If true, new TTS output interrupts currently-playing speech.
    // In menus and dialog, this gives faster, more responsive feedback.
    // Set to false if your screen reader handles queuing better than interruption.
    // Default: true.
    bool interrupt = true;

    // debug_log: If true, all [FF7Access] diagnostic messages are written to
    // ffvii_accessibility.log in the FF7 install folder. The log file is
    // overwritten each session so it contains only the most recent run.
    //
    // Enable this when reporting a bug: reproduce the issue, then send the
    // ffvii_accessibility.log file alongside your bug report.
    // Default: false.
    bool debug_log = false;
};

// Load reads ffvii_accessibility.cfg from the DLL's own directory.
// Sets all fields of the global Settings instance.
// Safe to call from DllMain on a background thread.
void Load();

// Get returns a const reference to the active settings.
// Settings are read-only after Load() returns.
const Settings& Get();

} // namespace Config
