# FFVII 2026 Rerelease — Accessibility Mod Project Plan

Started 2026-07-08. **CONFIRMED 2026-07-08, same day: the existing 2013 mod works unmodified against
the 2026 rerelease.** This document originally planned for an uncertain "the engine might have changed"
scenario; it's kept below (renumbered, trimmed) for the reasoning trail, but the short version is: this
turned out not to be a porting project. It's the same mod, installed in a different folder.

For the fresh 2026-specific facts this is built on, see section 9 of `FFVII-Modding-Resources.md`. For
the full 2013 implementation history, see `FFVII-Accessibility-Research.md` and the
`project_ffvii_access` / `project_ffvii_2026_access` Claude memory entries.

---

## 1. Confirmed result

Set up FFNx manually in the 2026 release's `ff7/workingdir/` folder (steps below), copied the
**already-compiled, unmodified 2013 `version.dll`** (+ `Tolk.dll`, `nvdaControllerClient32.dll`,
`ffvii_accessibility.cfg`) into that same folder, and ran the renamed `ff7_en.exe` directly. Confirmed
working with **zero code changes**:

- Title screen cursor TTS
- Full field dialog detection pipeline (hook chain, field buffer parsing, dialog-ID pending/speak state
  machine, text decoding) — spoke dialog cleanly
- Main menu cursor TTS
- Config sub-menu TTS ("all menus function as before")

Also confirmed along the way:
- `ff7_en.exe` in the 2026 release is **32-bit** (`PE32 executable (GUI) Intel 80386`) — same as 2013.
- FFNx still uses the filename **`AF3DN.P`** for its driver replacement in the 2026 release.

**Both of the then-open gaps have since been closed on this install** (this paragraph originally read
"not yet tested"): battle action TTS was confirmed working as v2.7 (2026-07-11) and the long-unsolved
battle-menu-cursor problem was cracked and shipped as v2.9 (2026-07-12) — see
`FFVII-Accessibility-Research.md` §8 for those entries and everything since (the mod has continued
active development on this install: battle announcements, field navigation/pathfinding, save/continue
menus, the item menu, and more — §8 is the authoritative version history, TODO.txt the live backlog).

### What this means going forward

- **No separate `AccessibilityMod2026/` source tree is needed.** The existing `AccessibilityMod/`
  source and its compiled `version.dll` work for both the 2013 and 2026 releases as-is.
- The only difference between "installing for 2013" and "installing for 2026" is *where the four mod
  files go* — 2013 Steam root vs. the 2026 release's `ff7/workingdir/` (see install steps below).
- Any future mod work (fixing the TODO items, tackling the battle-menu-cursor problem, new features)
  benefits both releases simultaneously, from one shared codebase.

## 2. Confirmed 2026 install steps

1. Install the game via Steam normally (installs to `...\Final Fantasy VII Steam Edition\`).
2. Download the latest `FFNx-Steam` release from `github.com/julianxhokaxhiu/FFNx/releases` (confirmed
   working: `FFNx-Steam-v1.24.3.0.zip`, current stable — 2026 rerelease support has been in FFNx
   **stable** since v1.24.0, despite some early community guides suggesting Canary was required).
3. Extract the zip into `ff7/workingdir/` (next to the `data` folder already there).
4. Copy `ff7/resources/ff7_1.02/ff7_en` into `ff7/workingdir/`, rename it to `ff7_en.exe`.
5. `mkdir ff7/workingdir/data/kernel`, then copy `ff7/workingdir/data/lang-ja/kernel/window.bin` to
   `ff7/workingdir/data/kernel/windows.bin`.
6. Write `3837340` (no trailing newline) to `ff7/workingdir/steam_appid.txt`.
7. Copy the mod's four files (`version.dll`, `Tolk.dll`, `nvdaControllerClient32.dll`,
   `ffvii_accessibility.cfg`) into `ff7/workingdir/` — **not** the top-level game folder. The top-level
   folder's `FFVII.exe`/`FFVII_LAUNCHER.exe` is a separate .NET/SharpDX QoL launcher (3x speed toggle,
   encounter toggle, etc.), a completely different process from the actual game engine; a native
   `version.dll` proxy sitting there does nothing.
8. Run `ff7/workingdir/ff7_en.exe` directly to play, modded — this bypasses the new launcher entirely.

## 3. Why this was worth checking (original reasoning, still valid as a lesson)

Three sessions were spent trying to find the battle command-menu cursor (Attack/Magic/Item selection)
in the 2013 Steam build's memory: exhaustive per-actor and whole-heap memory scanning, a live
hardware-breakpoint debugger (which reproducibly crashed the game — likely anti-debug behavior in the
Steam wrapper), and a carefully-engineered `GetProcAddress` hook that was proven mechanically correct
via diagnostics but revealed the assumed FFNx injection point (`new_dll_graphics_driver`) is looked up
and never actually called on this build. All three approaches were legitimate and well-executed; none
found the value. Full detail in `project_ffvii_access` memory's "Battle command menu cursor" section.

Rather than escalate to full static disassembly (IDA/Ghidra-level reverse engineering) of a build about
to be superseded anyway, the user redirected effort at the 2026 rerelease — the actively-supported,
currently-purchasable version, free for existing 2013 owners. The research-stage clue that made this
worth trying before assuming a rewrite: FFNx's own version-detection code doesn't distinguish the 2026
rerelease from the 2013 build internally (both resolve to `VERSION_FF7_102_US`), and its changelog
described the 2026-rerelease work as platform/save-path/achievements fixes, not an address-table
rewrite. That clue turned out to be correct.

## 4. Remaining open items

- **Battle action TTS / battle-menu-cursor**: not yet tested on the 2026 install. Expected to behave
  identically to 2013 given everything else has matched exactly, but not directly confirmed.
- **Anti-debug crash parity**: whether the 2013 hardware-breakpoint-crashes-the-game behavior reproduces
  on the 2026 Steam wrapper — untested, and only relevant if the battle-menu-cursor problem is revisited
  with that specific technique. If so, use the same disposable-test-target validation discipline as
  before (see `project_ffvii_access` memory) rather than testing destructively against the real game.
- All the pre-existing 2013 TODO items (`TODO.txt`: controller-button glyphs, splash-screen false
  title announce, quit-dialog prompt text, quit-dialog re-announce, auto-create missing config) apply
  equally to the 2026 install now that it's confirmed to be the same codebase — fixing any of them
  benefits both releases.

## 5. Repo layout

- `AccessibilityMod/` — the one and only mod source, works for both releases unmodified.
- `FFVII-2026-Project.md` — this document.
- `FFVII-Modding-Resources.md` §9 — full 2026 research and install steps.
- `README.md` — update needed: currently claims the mod "will not work with the 2026 remake or any
  other version," which is now confirmed false. Should document both install locations.
