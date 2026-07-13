#!/usr/bin/env python3
"""
ff7_battle_menu_cursor_live_verify.py -- LIVE verification of the battle
command-menu cursor addresses found by static disassembly (2026-07-12).

WHAT WAS FOUND (see ff7_battle_menu_static.py + the two disasm scripts,
logs battle_menu_static_20260712_*.log / battle_menu_*_disasm_*.log)
-----------------------------------------------------------------------
The battle menu is a widget state machine, exactly as the PSX decomp
predicted. All addresses below came off the exe ON DISK by following
FFNx's own resolution chains (three independent cross-checks passed:
0x6DB0EE, 0x6E6291, 0xDC3C98 all matched FFNx's embedded names):

  BATTLE_MENU_STATE  u16 0x0091EF9C   current widget: 0=waiting/ATB,
                                      1=command menu, 2/3=Defend/Change(?),
                                      5/6/7=action lists, 19(0x13)=targeting,
                                      26/27=Cait slots/Tifa slots, ...
  BATTLE_MENU_PREV   u16 0x0091EF98   previous state (written on transitions)
  ACTIVE_SLOT        u8  0x00DC3C7C   party slot (0-2) whose menu is open
  MENU_BUSY          u32 0x00DC35AC   1 = transition in progress

  Per-slot widget block at 0xDC20A0 + slot*0x700, widget stride 0x38:
    COMMAND widget 0xDC20A0:  +0 = column (u32, LEFT/RIGHT, wraps mod
                              number-of-columns), +4 = row (u32, UP/DOWN,
                              wraps mod 4 -- the grid is COLUMN-MAJOR,
                              4 rows per column like the on-screen layout)
    STATE-5 list   0xDC20D8:  +0 + +4 + +0x14(scroll) = selected index
                              into global 6-byte entries at 0x9AC354
                              (u16 id, 0xFFFF empty; id -> 0xDC3C78 on
                              Confirm = FFNx issued_action_id. This is
                              the MAGIC-shaped list.)
    STATE-6 list   0xDC2110:  same cursor math; entries at
                              0xDBA5A0 + slot*0x440 (per-actor)
    STATE-7 list   0xDC2148:  same; entries at 0xDBA760 + slot*0x440

  Per-slot command table at 0xDBA4E4 + slot*0x440, 6-byte entries,
  entry index = row + column*4:
    u8[+0] = command id (0xFF = empty cell, cursor skips it)
    u8[+1] = action type (drives the Confirm jump table)
    u8[+2] = action id for direct-dispatch commands
  Column count = u8[0xDBA4B9 + slot*0x440].

  Confirm flow writes: cmd id -> 0xDC3C70, entry+1 -> 0xDC3C74,
  action id -> u16 0xDC3C84 / 0xDC3C78, list index -> u16 0xDC3C54,
  then targeting: type u8 0xDC3C90, index u8 0xDC3C94, and the live
  target pointer actor = u8 0xDC3C98 (FFNx targeting_actor_id_DC3C98).

WHAT THIS SCRIPT DOES
---------------------
Attaches to the running game and polls all of the above at 40ms. On
change it beeps (so the blind player gets immediate confirmation that
navigation is being tracked) and logs a timestamped decoded line. While
the COMMAND MENU is open it also SPEAKS the command name under the
cursor via SAPI -- if the static analysis is right, this is the first
time the battle menu has ever talked. Speech is fired asynchronously;
at human navigation speed the slight lag is acceptable for a verify.

PLAYER PROTOCOL (spoken at start)
---------------------------------
  1. Get into a battle (any random encounter).
  2. When the command menu opens (double beep + first spoken command),
     press Down repeatedly, pausing ~1s between presses -- the script
     should speak each command in the column in order.
  3. Press Up back to the top. Press Right/Left if this character has
     a second command column.
  4. Open Magic (or the first list command), move Down a few rows,
     then Cancel. Open Item, same, Cancel.
  5. Select Attack, move the target cursor Left/Right across enemies,
     then either finish or flee the battle.

OUTPUT: teed to battle_menu_live_<timestamp>.log next to this script.
"""

import ctypes
import os
import subprocess
import sys
import time
import winsound

PROCESS_NAME = "ff7_en.exe"

# ---- statically resolved addresses (2026-07-12) ---------------------------
GAME_MODE          = 0x00CC0D89   # u8: 2 = battle (live-confirmed enum)
BATTLE_MENU_STATE  = 0x0091EF9C   # u16
BATTLE_MENU_PREV   = 0x0091EF98   # u16
ACTIVE_SLOT        = 0x00DC3C7C   # u8 party slot 0-2
MENU_BUSY          = 0x00DC35AC   # u32

WIDGET_BASE        = 0x00DC20A0   # + slot*0x700; widgets every 0x38
WIDGET_SLOT_STRIDE = 0x700
W_CMD, W_S5, W_S6, W_S7 = 0x00, 0x38, 0x70, 0xA8   # widget offsets in block

CHAR_BLOCK         = 0x00DBA498   # + slot*0x440 per-actor battle char data
CHAR_SLOT_STRIDE   = 0x440
CMD_TABLE_OFF      = 0x4C         # 0xDBA4E4: 6-byte entries, row + col*4
CMD_NCOLS_OFF      = 0x21         # 0xDBA4B9: number of command columns
LIST5_BASE         = 0x009AC354   # global 6-byte entries (magic-shaped list)
LIST6_OFF          = 0x108        # 0xDBA5A0 + slot*0x440
LIST7_OFF          = 0x2C8        # 0xDBA760 + slot*0x440

ISSUED_CMD         = 0x00DC3C70   # u8  (FFNx issued_command_id)
ISSUED_ACTION      = 0x00DC3C78   # u16 (FFNx issued_action_id)
TARGET_TYPE        = 0x00DC3C90   # u8  (FFNx issued_action_target_type)
TARGET_INDEX       = 0x00DC3C94   # u8  (FFNx issued_action_target_index)
TARGETING_ACTOR    = 0x00DC3C98   # u8  (FFNx targeting_actor_id_DC3C98)

# Kernel command ids -> names (standard US kernel order). Unknown ids are
# spoken as "command N" -- if one shows up in the log we learn something.
COMMAND_NAMES = {
    0x00: "Attack",   0x01: "Magic",    0x02: "Summon",  0x03: "Item",
    0x04: "Steal",    0x05: "Sense",    0x06: "Coin",    0x07: "Throw",
    0x08: "Morph",    0x09: "Deathblow",0x0A: "Manipulate", 0x0B: "Mime",
    0x0C: "Enemy Skill", 0x0D: "Mug",
    0x12: "Defend",   0x13: "Change row",
    0x14: "Limit",
    0x17: "W-Magic",  0x18: "W-Summon", 0x19: "W-Item",
    0x1A: "Slash-All",0x1B: "2x-Cut",   0x1C: "Flash",   0x1D: "4x-Cut",
}

STATE_NAMES = {
    0: "waiting/ATB", 1: "COMMAND MENU", 2: "defend?", 3: "change-row?",
    4: "state4-list", 5: "list A (magic?)", 6: "list B", 7: "list C (item?)",
    9: "state9", 11: "state11", 19: "TARGETING",
    0x14: "state20-eskill?", 0x18: "limit A", 0x1A: "limit B",
    0x1B: "limit C", 26: "cait slots", 27: "tifa slots", 28: "state28",
}

POLL_INTERVAL = 0.04
DURATION      = 240        # seconds of monitoring once battle menu first seen

k32 = ctypes.windll.kernel32


class Tee:
    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log      = log_file
    def write(self, data):
        self._terminal.write(data)
        self._log.write(data)
        self._log.flush()
    def flush(self):
        self._terminal.flush()
        self._log.flush()
    def __getattr__(self, name):
        return getattr(self._terminal, name)


def speak_wait(text):
    print(f"[SPOKEN] {text}")
    safe = text.replace("'", "''")
    try:
        subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=90)
    except Exception:
        pass


def speak_async(text):
    """Fire-and-forget speech for live cursor feedback. Each call is its own
    SAPI voice so a new announcement simply overlaps/succeeds the previous
    one -- good enough for a verify run (the real mod will use Tolk)."""
    print(f"[SPOKEN-ASYNC] {text}")
    safe = text.replace("'", "''")
    try:
        subprocess.Popen(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception:
        pass


def find_pid(exe_name):
    result = subprocess.run(
        ['tasklist', '/FI', f'IMAGENAME eq {exe_name}', '/FO', 'CSV'],
        capture_output=True, text=True)
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
    return buf.raw if (ok and read.value == n) else None


def read_u8(handle, addr):
    raw = read_bytes(handle, addr, 1)
    return raw[0] if raw else None


def read_u16(handle, addr):
    raw = read_bytes(handle, addr, 2)
    return int.from_bytes(raw, 'little') if raw else None


def read_u32(handle, addr):
    raw = read_bytes(handle, addr, 4)
    return int.from_bytes(raw, 'little') if raw else None


def cmd_name(cid):
    if cid is None:
        return "unreadable"
    if cid == 0xFF:
        return "empty"
    return COMMAND_NAMES.get(cid, f"command {cid}")


def read_widget(handle, slot, woff):
    """Return (h, v, scroll) cursor components of one widget."""
    base = WIDGET_BASE + slot * WIDGET_SLOT_STRIDE + woff
    return (read_u32(handle, base),
            read_u32(handle, base + 4),
            read_u32(handle, base + 0x14))


def read_command_under_cursor(handle, slot):
    """Command id at the command-widget cursor: entry (row + col*4)."""
    col, row, _ = read_widget(handle, slot, W_CMD)
    if col is None or row is None or col > 8 or row > 8:
        return None, col, row
    entry = (CHAR_BLOCK + slot * CHAR_SLOT_STRIDE + CMD_TABLE_OFF
             + (row + col * 4) * 6)
    return read_u8(handle, entry), col, row


def read_list_selection(handle, slot, state):
    """(index, entry id) for the active list widget in states 5/6/7."""
    woff  = {5: W_S5, 6: W_S6, 7: W_S7}[state]
    h, v, scroll = read_widget(handle, slot, woff)
    if None in (h, v, scroll):
        return None, None
    idx = h + v + scroll
    if idx > 0x200:                      # sanity: lists are small
        return idx, None
    if state == 5:
        entry = LIST5_BASE + idx * 6
    elif state == 6:
        entry = CHAR_BLOCK + slot * CHAR_SLOT_STRIDE + LIST6_OFF + idx * 6
    else:
        entry = CHAR_BLOCK + slot * CHAR_SLOT_STRIDE + LIST7_OFF + idx * 6
    return idx, read_u16(handle, entry)


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_path    = os.path.join(
        script_dir, f"battle_menu_live_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak_wait("FF7 not found. Start the game first.")
            return
        handle = k32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not handle:
            speak_wait("Cannot open FF7 process.")
            return
        print(f"Attached to {PROCESS_NAME} pid {pid}")

        speak_wait(
            "Battle menu cursor verification. Get into any battle. "
            "When you hear the double beep and a spoken command name, the "
            "command menu is being tracked. Press Down slowly through all "
            "commands, then Up. Try Right and Left. Then open Magic, move "
            "down a few rows, cancel. Open Item if you have it, move, "
            "cancel. Finally choose Attack and move the target cursor "
            "between enemies. You have four minutes once the menu opens.")

        # Wait for battle + command menu (state 1) to appear.
        print("Waiting for battle command menu (GAME_MODE==2 and "
              "BATTLE_MENU_STATE==1)...")
        t_wait = time.time()
        while True:
            mode  = read_u8(handle, GAME_MODE)
            state = read_u16(handle, BATTLE_MENU_STATE)
            if mode == 2 and state == 1:
                break
            if time.time() - t_wait > 600:
                speak_wait("Timed out waiting for a battle. Exiting.")
                return
            time.sleep(0.1)

        beeped_in = False
        t0 = time.time()

        last = {}
        def changed(key, value):
            """Track-and-report: returns True the first time a key takes a
            new value."""
            if last.get(key) != value:
                last[key] = value
                return True
            return False

        print(f"[{0:7.2f}s] battle menu detected -- monitoring")
        winsound.Beep(1200, 100); winsound.Beep(1200, 100)

        while time.time() - t0 < DURATION:
            ts    = time.time() - t0
            mode  = read_u8(handle, GAME_MODE)
            state = read_u16(handle, BATTLE_MENU_STATE)
            slot  = read_u8(handle, ACTIVE_SLOT)
            busy  = read_u32(handle, MENU_BUSY)

            if mode != 2:
                if changed('mode', mode):
                    print(f"[{ts:7.2f}s] GAME_MODE={mode} (battle left?)")
                time.sleep(POLL_INTERVAL)
                continue

            if changed('state', state):
                name = STATE_NAMES.get(state, f"state {state}")
                print(f"[{ts:7.2f}s] MENU_STATE -> {state} ({name})  "
                      f"slot={slot} busy={busy}")
                winsound.Beep(700, 40)

            if changed('slot', slot):
                print(f"[{ts:7.2f}s] ACTIVE_SLOT -> {slot}")

            if slot is not None and slot <= 2:
                # -- command menu cursor --------------------------------
                cid, col, row = read_command_under_cursor(handle, slot)
                if changed('cmd_cursor', (slot, col, row)):
                    nm = cmd_name(cid)
                    print(f"[{ts:7.2f}s] CMD cursor col={col} row={row} "
                          f"id={cid if cid is not None else '?'} -> {nm}")
                    if state == 1:
                        winsound.Beep(1500, 30)
                        speak_async(nm)

                # -- list cursor (only meaningful in 5/6/7) --------------
                if state in (5, 6, 7):
                    idx, eid = read_list_selection(handle, slot, state)
                    if changed('list_sel', (state, idx)):
                        print(f"[{ts:7.2f}s] LIST state={state} index={idx} "
                              f"entry_id={eid if eid is not None else '?'}"
                              + (" (0xFFFF empty)" if eid == 0xFFFF else ""))
                        winsound.Beep(1000, 30)
                        if eid is not None and eid != 0xFFFF:
                            speak_async(f"row {idx}, id {eid}")

            # -- confirm/targeting flow ---------------------------------
            for key, addr, rd in (
                    ('issued_cmd', ISSUED_CMD, read_u8),
                    ('issued_action', ISSUED_ACTION, read_u16),
                    ('target_type', TARGET_TYPE, read_u8),
                    ('target_index', TARGET_INDEX, read_u8),
                    ('targeting_actor', TARGETING_ACTOR, read_u8)):
                v = rd(handle, addr)
                if changed(key, v):
                    print(f"[{ts:7.2f}s] {key.upper()} -> {v}")
                    if key == 'targeting_actor' and state == 19:
                        winsound.Beep(900, 30)
                        speak_async(f"target {v}")

            time.sleep(POLL_INTERVAL)

        winsound.Beep(600, 100); winsound.Beep(600, 100); winsound.Beep(600, 100)
        speak_wait("Verification window over. Log saved.")
        print("\nDone. Review the log against what you actually pressed.")
        print(f"Log: {log_path}")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    main()
