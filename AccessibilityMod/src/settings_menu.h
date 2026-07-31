/*
 * settings_menu.h -- The F8 in-game audio-only accessibility menu (v2.30.42).
 *
 * WHAT THIS IS:
 *   A purely auditory settings menu: no graphics, no game-engine
 *   involvement. F8 toggles it; while open, the mod's own FF4-scheme keys
 *   are repurposed to browse and edit every ffvii_accessibility.cfg
 *   setting, spoken through the screen reader. Changes apply IMMEDIATELY
 *   (every consumer in the mod re-reads Config::Get() at its point of
 *   use — audited 2026-07-31) and are saved to the cfg file on every
 *   change, so nothing requires a restart and a crash loses nothing.
 *
 * WHY F8:
 *   accessiblity_keys.txt (the FF1-6 accessibility-mod key scheme this
 *   project keeps parity with) already designates "F8: Open mod menu."
 *   Verified free on this game: the engine's own keyboard map
 *   (ff7input.cfg) contains no DIK_F8 (0x42) binding, FFNx's only hotkey
 *   is devtools on F12 (0x7B), and the game's defaults are numpad-centric.
 *
 * WHY THE MENU KEYS ARE J/L/K/I (not arrows):
 *   The game keeps receiving keyboard input while our menu is open — a
 *   version.dll proxy cannot swallow keys without hooking the engine's
 *   input refresh, and the tutorial-VM research (v2.30.29) showed that
 *   path overwrites the digested-input words every frame (racy to fight
 *   from a polling thread). Arrow keys would therefore walk the player
 *   character around while they browse the menu. J/L/K/I carry NO game
 *   function (proven daily by the pathfinder browser using them in live
 *   fields since v2.14), so browsing the menu is guaranteed side-effect
 *   free. The verbs match the established scheme exactly:
 *     J / L  (or [ / ])      previous / next setting
 *     Shift+J / Shift+L      change the selected setting's value
 *       (or - / =)             (bools toggle; volume steps by 10)
 *     K                      repeat the current setting and value
 *     I                      speak the setting's one-line description
 *                              (same verb as I-for-description in the
 *                              game's config and shop menus)
 *     F8                     close ("Accessibility menu closed.")
 *
 * MODALITY:
 *   While open, the pathfinder browser and the shop/config/equip I-key
 *   description handlers stand down (they poll IsOpen()) so one keypress
 *   never triggers two features. The ONE context where the menu itself
 *   stands down is the naming screen (GAME_MODE 6): J/L/K would type
 *   into the name box, so F8 refuses to open there and the menu
 *   auto-closes if the naming screen appears while it is open.
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace SettingsMenu {

// Start the menu's polling thread. stop_event is proxy.cpp's shared
// manual-reset shutdown event (the same one every other polling thread
// waits on). Returns the thread handle for Proxy::Shutdown() to join,
// or nullptr on failure (the mod runs fine without the menu).
HANDLE Start(HANDLE stop_event);

// True while the menu is open. Polled by FieldNavThread and the I-key
// description handlers in proxy.cpp so their keys go quiet while the
// menu owns them. Lock-free: a single aligned LONG written by the menu
// thread, read by others (x86 word reads/writes are atomic).
bool IsOpen();

} // namespace SettingsMenu
