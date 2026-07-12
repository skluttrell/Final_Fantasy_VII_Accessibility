#!/usr/bin/env python3
"""
ff7_name_entry_panel_probe.py — Decode the naming screen's side panel
(Space / Delete / Select / Default) in one guided visit.

WHAT WE KNOW GOING IN (2026-07-12 scan + verify sessions, and the player's
own observation afterwards):
  - Pressing Right on the LAST grid column does not wrap — the cursor jumps
    to the side-panel buttons (player-confirmed by ear/behavior).
  - While the cursor is on the panel, NAME_ENTRY_ROW (0xDD453C) and
    NAME_ENTRY_COL (0xDD4538) keep their last grid values (confirmed live).
  - 0xDD4574 is the prime suspect for the panel cursor: every value ever
    observed is 0-3 (a 4-button panel!), it changed at the exact moments the
    player crossed the grid edge (0->1, later 1->2), and it reset to 0 at
    the Cloud->Barret screen handoff.  The one odd event (3->2 alongside a
    character delete) fits if the player was pressing Confirm ON the
    panel's Delete button at the time.

HOW THIS PROBE LABELS THE BUTTONS WITHOUT SIGHT:
  The name buffer (0xDD45F0) is ground truth for what a Confirm press did:
    - Space   -> a character is ADDED (FF7 byte 0x00)
    - Delete  -> a character is REMOVED
    - Default -> the whole name is REWRITTEN to the character's default
    - Select  -> the screen CLOSES (NAME_ENTRY_ACTIVE 0xDD46FC -> 0)
  So: park on a panel button, press Confirm, watch what happens, note the
  0xDD4574 value at that moment -> that value = that button.  The player
  never needs to see the screen, and Select is saved for last (it ends the
  screen, which is also how the player exits normally).

PROTOCOL (voice-cued; player presses ONLY what each phase asks):
  Phase 1  ENTER PANEL: from the grid, press Right slowly, one press per
           two seconds, until the script says "panel" (it speaks every
           0xDD4574 change; entering the panel should change it).
           About 5 presses max needed from mid-grid.
  Phase 2  WALK THE PANEL: press Down slowly 5 times, then Up 5 times.
           The script speaks each 0xDD4574 value -> reveals the index
           range and whether it wraps.
  Phase 3  LABEL Space/Delete: park on index 0 (script guides: press Up
           until it says "zero"), press Confirm once -> script reports
           what the buffer did.  Then Down once, Confirm once -> reports
           again.  Repeat for the remaining indices EXCEPT the one the
           script has already identified as likely Select — the script
           tells the player which indices are still safe to test.
           (If a Confirm press closes the screen early, the script detects
           ACTIVE going 0 and ends gracefully — no data is lost; whatever
           was learned is in the log.)
  Phase 4  FINISH: player cleans up the name and confirms with Select as
           normal; the script logs the ACTIVE 1->0 transition and which
           0xDD4574 value was current at that moment (= Select's index).

  Every spoken instruction is printed (tee'd log rule), every watched-byte
  change is timestamped, so the timeline reconstructs itself afterwards.

OUTPUT: name_entry_panel_<timestamp>.log next to this script.
"""

import ctypes
import subprocess
import sys
import time
import os
import winsound

PROCESS_NAME = "ff7_en.exe"

ROW_ADDR   = 0x00DD453C   # grid row 0-6 (confirmed; frozen while on panel)
COL_ADDR   = 0x00DD4538   # grid column 0-9 (confirmed; frozen while on panel)
PANEL_ADDR = 0x00DD4574   # SUSPECT: side-panel button index 0-3
BUF_ADDR   = 0x00DD45F0   # name buffer, FF7-encoded, 0xFF-terminated
BUF_CAP    = 12
CHAR_INDEX = 0x00DD46F8   # which character is being named (0=Cloud, 1=Barret)
ACTIVE     = 0x00DD46FC   # 1 while the naming screen is open
GAME_MODE  = 0x00CC0D89   # 6 on the naming screen

# Secondary unresolved bytes from the 2026-07-12 session — logged (not
# spoken) whenever they change, in case one of them is the real panel state
# and 0xDD4574 is something else:
EXTRA_WATCH = {
    0x00DD45E8: "unk_45E8",   # u32: small values / 0xFFFFFFFF, per-screen reset
    0x00DD46F0: "unk_46F0",   # possibly name length at screen open
}

# Whole name-entry block — every byte change logged with a timestamp.
WIN_LO = 0x00DD4400
WIN_HI = 0x00DD4800

k32 = ctypes.windll.kernel32


class Tee:
    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log      = log_file

    def write(self, data):
        self._terminal.write(data)
        self._log.write(data)

    def flush(self):
        self._terminal.flush()
        self._log.flush()

    def __getattr__(self, name):
        return getattr(self._terminal, name)


def speak_wait(text):
    # Spoken text is also printed so it lands in the tee'd log — the whole
    # point of this probe is correlating the logged byte timeline with what
    # the player was asked to do (project rule: all spoken text is logged).
    print(f"[SPOKEN] {text}")
    safe = text.replace("'", "''")
    try:
        subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=90
        )
    except Exception:
        pass


def beep_start():
    winsound.Beep(1200, 120); time.sleep(0.08); winsound.Beep(1200, 120)


def find_pid(exe_name):
    result = subprocess.run(
        ['tasklist', '/FI', f'IMAGENAME eq {exe_name}', '/FO', 'CSV'],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        if exe_name.lower() in line.lower():
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
    return None


def read_bytes(handle, addr, n):
    buf  = ctypes.create_string_buffer(n)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, n, ctypes.byref(read))
    if ok and read.value == n:
        return buf.raw
    return None


def snapshot_window(handle):
    return read_bytes(handle, WIN_LO, WIN_HI - WIN_LO)


def decode_ff7_name(raw):
    out = []
    for b in raw:
        if b == 0xFF:
            break
        c = b + 0x20
        out.append(chr(c) if 0x20 <= c <= 0x7E else "?")
    return "".join(out)


class PanelWatcher:
    """Polls the DD window at 100ms; logs every byte change; speaks the
    events that matter for the protocol (panel byte, buffer edits, screen
    close). All state values are sliced from ONE window snapshot per poll so
    the log and the speech always describe the same instant."""

    def __init__(self, handle, t0):
        self.handle = handle
        self.t0     = t0
        self.win    = snapshot_window(handle)

    def _slice(self, addr, n=1):
        off = addr - WIN_LO
        return self.win[off:off + n]

    def value(self, addr):
        return self._slice(addr)[0]

    def name(self):
        return decode_ff7_name(self._slice(BUF_ADDR, BUF_CAP))

    def poll(self, speak_panel=True, speak_name=True):
        """One 100ms poll. Returns a dict of notable events (or None if the
        window read failed): {'panel': new_val or None,
                              'name_change': (old, new) or None,
                              'closed': bool}"""
        time.sleep(0.10)
        curr = snapshot_window(self.handle)
        if curr is None or self.win is None:
            self.win = curr
            return None

        events = {'panel': None, 'name_change': None, 'closed': False}
        prev = self.win

        # Timestamped log of every changed byte, with known-address labels.
        labels = {ROW_ADDR: "ROW", COL_ADDR: "COL", PANEL_ADDR: "PANEL?",
                  CHAR_INDEX: "CHAR_INDEX", ACTIVE: "ACTIVE"}
        labels.update(EXTRA_WATCH)
        for i in range(len(curr)):
            if curr[i] != prev[i]:
                addr = WIN_LO + i
                tag  = labels.get(addr, "")
                if BUF_ADDR <= addr < BUF_ADDR + BUF_CAP:
                    tag = f"BUF+{addr - BUF_ADDR}"
                print(f"  [{time.time()-self.t0:7.2f}s] 0x{addr:08X}: "
                      f"{prev[i]:3d} -> {curr[i]:3d}  {tag}")

        old_name  = decode_ff7_name(prev[BUF_ADDR-WIN_LO:BUF_ADDR-WIN_LO+BUF_CAP])
        old_panel = prev[PANEL_ADDR - WIN_LO]

        self.win  = curr
        new_name  = self.name()
        new_panel = self.value(PANEL_ADDR)

        if self.value(ACTIVE) == 0:
            events['closed'] = True
        if new_panel != old_panel:
            events['panel'] = new_panel
            if speak_panel:
                speak_wait(f"panel byte {new_panel}")
        if new_name != old_name:
            events['name_change'] = (old_name, new_name)
            if speak_name:
                if len(new_name) == len(old_name) + 1:
                    added = new_name[-1]
                    speak_wait("space added" if added == " "
                               else f"added {added}")
                elif len(new_name) == len(old_name) - 1:
                    speak_wait("character deleted")
                else:
                    speak_wait(f"name is now "
                               f"{' '.join(new_name) if new_name else 'empty'}")
        return events


def timed_watch(watcher, seconds, **kw):
    """Run the watcher for a fixed period, returning early if the naming
    screen closes. Collects panel/name events for the caller."""
    deadline = time.time() + seconds
    seen = {'panel_values': [], 'name_changes': [], 'closed': False}
    while time.time() < deadline:
        ev = watcher.poll(**kw)
        if ev is None:
            continue
        if ev['panel'] is not None:
            seen['panel_values'].append(ev['panel'])
        if ev['name_change'] is not None:
            seen['name_changes'].append(ev['name_change'])
        if ev['closed']:
            seen['closed'] = True
            break
    return seen


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"name_entry_panel_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak_wait("FF7 not found. Get to the naming screen first.")
            print("ERROR: ff7_en.exe not running.")
            return
        handle = k32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not handle:
            speak_wait("Cannot open FF7 process.")
            print("ERROR: OpenProcess failed.")
            return

        gm = read_bytes(handle, GAME_MODE, 1)
        print(f"GAME_MODE = {gm[0] if gm else '?'} (expect 6 on naming screen)")

        t0 = time.time()
        w  = PanelWatcher(handle, t0)
        print(f"start: row={w.value(ROW_ADDR)} col={w.value(COL_ADDR)} "
              f"panel?={w.value(PANEL_ADDR)} name='{w.name()}' "
              f"active={w.value(ACTIVE)}")

        # ---- Phase 1: enter the panel --------------------------------------
        speak_wait(
            "Panel probe. Phase 1. From the letter grid, press Right slowly, "
            "about one press every two seconds, until I say a panel number. "
            "Start at the double beep."
        )
        beep_start()
        seen = timed_watch(w, 25)
        if seen['closed']:
            speak_wait("The screen closed early. Stopping; the log has "
                       "everything so far.")
            return
        if not seen['panel_values']:
            speak_wait(
                "I did not see the panel byte change. Phase 2 will continue "
                "anyway, in case the panel is tracked somewhere else. All "
                "byte changes are being logged regardless."
            )

        # ---- Phase 2: walk the panel up and down ---------------------------
        speak_wait(
            "Phase 2. You should be on the side panel now. Press Down five "
            "times, slowly, then Up five times. I will speak each panel "
            "number I see. Start at the double beep."
        )
        beep_start()
        seen2 = timed_watch(w, 30)
        if seen2['closed']:
            speak_wait("The screen closed early. Stopping; log saved.")
            return

        # ---- Phase 3: label buttons via Confirm ----------------------------
        # Space adds a character, Delete removes one, Default rewrites the
        # name; only Select closes the screen. We ask for Confirm presses on
        # the two lowest panel indices reachable, then Default's signature
        # (wholesale rewrite) or Select (screen close) reveals the rest.
        speak_wait(
            "Phase 3, labeling. Press Up several times to reach the top of "
            "the panel. Then press Confirm once, wait two seconds, press "
            "Down once, press Confirm once, and continue that pattern, "
            "Down then Confirm, until you run out of buttons or the screen "
            "closes. I will describe what each press did. If the screen "
            "closes, that button was Select, and we are done. Start at the "
            "double beep."
        )
        beep_start()
        # Track (panel_value -> observed effect) pairs live.
        effects  = {}
        deadline = time.time() + 60
        last_panel = w.value(PANEL_ADDR)
        while time.time() < deadline:
            ev = w.poll()
            if ev is None:
                continue
            if ev['panel'] is not None:
                last_panel = ev['panel']
            if ev['name_change'] is not None:
                old, new = ev['name_change']
                if len(new) == len(old) + 1:
                    effect = "SPACE" if new[-1] == " " else f"ADD '{new[-1]}'"
                elif len(new) == len(old) - 1:
                    effect = "DELETE"
                else:
                    effect = f"REWRITE -> '{new}'"
                effects[last_panel] = effect
                print(f"  [LABEL] panel={last_panel} -> {effect}")
            if ev['closed']:
                effects[last_panel] = "SELECT (closed screen)"
                print(f"  [LABEL] panel={last_panel} -> SELECT (screen closed)")
                break

        # ---- Report ---------------------------------------------------------
        print("\n" + "=" * 60)
        print("  PANEL BUTTON MAP (0xDD4574 value -> observed effect)")
        print("=" * 60)
        if effects:
            for val in sorted(effects):
                print(f"  {val}: {effects[val]}")
        else:
            print("  (no Confirm effects captured — see raw timeline above)")

        summary = ". ".join(f"panel {v}: {e}" for v, e in sorted(effects.items()))
        speak_wait(f"Probe done. {summary if summary else 'No labels captured.'} "
                   "Finish the naming screen normally whenever you like. "
                   "Everything is in the log.")
        print(f"\nLog saved to: {log_path}")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
