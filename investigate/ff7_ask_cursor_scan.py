#!/usr/bin/env python3
"""
ff7_ask_cursor_scan.py -- Find the ASK choice menu's current-option byte
(2026-07-19; player: choice menus read only the first option and don't
track the cursor as you move).

STATIC found (ff7_ask_cursor_static.py): the ASK update loop 0x6310A1
keys off a per-window struct at 0xCFF5D3 + window_id*0x30 (state byte at
+0x11 = 0xCFF5E4). The current SELECTED OPTION lives in that struct too,
but its offset wasn't obvious statically — so watch the struct live while
you move the choice cursor up and down.

METHOD: two press-and-revert rounds (Down then Up), intersected — the
option byte goes +1 on Down and back on Up, both rounds. Scans the full
field window region first (0xCFF5D3..0xCFF700 across all 8 window slots)
plus a wide fallback, and prints each candidate with its window slot +
offset so it drops straight into ff7_addresses.h.

HOW TO RUN (all spoken):
  1. Get a dialog with a MULTI-OPTION choice on screen (e.g. a shop's
     yes/no is only 2 — better: any 3+ option choice), cursor on the
     TOP option.
  2. Run this and follow the voice prompts. Read-only.
"""
import ctypes, subprocess, sys, time, os

PROCESS_NAME = "ff7_en.exe"
BSS_MIN, BSS_MAX = 0x00400000, 0x00DE0000
WIN_BASE, WIN_STRIDE, WIN_N = 0xCFF5D3, 0x30, 8

k32 = ctypes.windll.kernel32
PROCESS_VM_READ, PROCESS_VM_QUERY = 0x0010, 0x0400


class Tee:
    def __init__(self, t, f): self._t, self._f = t, f
    def write(self, d): self._t.write(d); self._f.write(d)
    def flush(self): self._t.flush(); self._f.flush()
    def __getattr__(self, n): return getattr(self._t, n)


def speak(text, wait=False):
    safe = text.replace("'", "''")
    try:
        p = subprocess.Popen(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
        if wait: p.wait(timeout=30)
    except Exception:
        pass


def find_pid():
    out = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {PROCESS_NAME}',
                          '/FO', 'CSV'], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if PROCESS_NAME.lower() in line.lower():
            try: return int(line.strip('"').split('","')[1])
            except (IndexError, ValueError): pass
    return None


def read_bss(h):
    size = BSS_MAX - BSS_MIN
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(BSS_MIN), buf, size,
                             ctypes.byref(got)) and got.value == size:
        return bytes(buf)
    return None


def sdiff(a, b):
    d = b - a
    return d - 256 if d > 127 else d + 256 if d < -128 else d


def win_label(va):
    for w in range(WIN_N):
        b = WIN_BASE + w * WIN_STRIDE
        if b <= va < b + WIN_STRIDE:
            return f" [window {w} +0x{va-b:X}]"
    return ""


def main():
    d = os.path.dirname(os.path.abspath(__file__))
    lp = os.path.join(d, f"ask_cursor_scan_{time.strftime('%Y%m%d_%H%M%S')}.log")
    lf = open(lp, 'w', encoding='utf-8')
    real = sys.stdout
    sys.stdout = Tee(real, lf)
    h = None
    try:
        print(f"Output saving to: {lp}\n")
        speak("Choice cursor scan. Get a dialog with a multi option choice "
              "on screen, cursor on the top option. Then press Enter here.",
              wait=True)
        input("  Press Enter with a choice menu open, cursor on top ...")
        pid = find_pid()
        if pid is None:
            speak("F F 7 not running."); print("ERROR: not running"); return
        h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_QUERY, False, pid)
        print(f"PID: {pid}")
        speak("Connected. Switch to the game. Ten seconds.", wait=True)
        time.sleep(10)

        inter = None
        for rnd in (1, 2):
            print(f"\n-- round {rnd} --")
            base = read_bss(h)
            speak("Press Down once to move to the next option, then hold "
                  "still.", wait=True)
            time.sleep(2.5)
            down = read_bss(h)
            speak("Press Up once to go back, then hold still.", wait=True)
            time.sleep(2.5)
            up = read_bss(h)
            if not (base and down and up):
                print("  read failed"); speak("Read failed."); return
            cands = set()
            for i in range(len(base)):
                if sdiff(base[i], down[i]) == 1 and up[i] == base[i] and \
                        down[i] != up[i]:
                    cands.add(BSS_MIN + i)
            print(f"  round {rnd}: {len(cands)} candidates")
            inter = cands if inter is None else (inter & cands)

        cands = sorted(inter)
        print(f"\nINTERSECTED candidates: {len(cands)}")
        for va in cands[:40]:
            print(f"  0x{va:08X}{win_label(va)}")
        # Prefer any inside the window-struct region.
        inwin = [va for va in cands
                 if WIN_BASE <= va < WIN_BASE + WIN_N * WIN_STRIDE]
        if inwin:
            print(f"\n==> IN WINDOW STRUCT: " +
                  ", ".join(f"0x{v:X}{win_label(v)}" for v in inwin))
            speak(f"Found {len(inwin)} candidate in the window struct. "
                  "See the log.")
        elif cands:
            speak(f"Found {len(cands)} candidate outside the window struct. "
                  "See the log.")
        else:
            speak("No candidate. The choice may have only two options, or "
                  "the cursor wrapped. Try a choice with three or more "
                  "options.")
        print("\nNEXT: wire the option byte (window struct offset) as "
              "ASKMENU_OPTION into ff7_addresses.h; hook_ask announces the "
              "option line on change.")
    except KeyboardInterrupt:
        speak("Stopped.")
    finally:
        if h: k32.CloseHandle(h)
        sys.stdout = real
        lf.close()
        print(f"\nLog: {lp}")


if __name__ == '__main__':
    main()
