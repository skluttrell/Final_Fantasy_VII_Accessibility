#!/usr/bin/env python3
"""
ff7_title_investigate_fast.py — In-process snapshot approach for the FF7 title cursor.

WHY THIS EXISTS:
  The polling script (ff7_title_investigate.py) found no changes in 6 targeted
  regions, confirming the cursor is elsewhere in the ~80MB of writable memory
  that we haven't covered. Polling all of that memory every 200ms would take
  ~60 seconds per cycle — far too slow. This script instead snapshots and diffs
  entirely inside the game process in JavaScript, which takes < 1 second.

CRITICAL DESIGN NOTE — ArrayBuffer copies:
  Memory.readByteArray() in some Frida versions returns an ArrayBuffer whose
  backing store is a live pointer into native process memory. Accessing it
  later reads the CURRENT value, not the snapshot value. .slice(0) was
  supposed to force a copy but proved unreliable. Instead we use the explicit:
    var buf = new ArrayBuffer(size);
    new Uint8Array(buf).set(new Uint8Array(raw));
  This allocates a fresh V8-managed ArrayBuffer and copies bytes via set().
  After set() completes, buf is guaranteed independent of native memory.

CRITICAL DESIGN NOTE — FF7 focus/freeze:
  FF7 2013 Steam freezes its game loop when its window loses focus. Any memory
  snapshot taken while the terminal window is active will show 0 changes (the
  game made no progress). ALL snapshots in this script therefore run AFTER the
  user has switched focus to FF7. The user is never required to interact with
  the terminal again after the initial Enter press.

USAGE:
  1. Start FF7, reach the title screen (CONTINUE / NEW GAME), cursor on CONTINUE.
  2. Run this script. Press Enter in the terminal when ready.
  3. After pressing Enter: switch to FF7 immediately. You have 5 seconds.
  4. Thereafter, follow audio cues only (SAPI speech + beeps). Do NOT switch
     back to the terminal — keep FF7 focused throughout.
  5. On first triple-beep: press Up or Down ONCE (move to NEW GAME).
  6. On second triple-beep: press Up or Down ONCE (move back to CONTINUE).
  7. Results are spoken and saved to the log file.

Frida RPC naming rule: exports_sync lowercases method names before JS lookup.
All JS export names and Python call names must be fully lowercase.
"""

import frida
import sys
import time
import os
import subprocess
import winsound

PROCESS_NAME    = "ff7_en.exe"
FOCUS_WAIT_SEC  = 5     # seconds after Enter for user to switch to FF7
MOVE_WINDOW_SEC = 2.0   # seconds between triple-beep and snapshot

# ---------------------------------------------------------------------------
# Audio helpers
# ---------------------------------------------------------------------------

def speak_wait(text):
    """Speak 'text' via Windows SAPI and block until speech finishes.

    Works regardless of which window has focus. SAPI routes through the
    configured audio device so the user hears it even while FF7 is foreground.
    """
    safe = text.replace("'", "''")
    try:
        subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=60
        )
    except Exception:
        pass


def beep_tick():
    """Short low tick — once per second during countdowns."""
    winsound.Beep(500, 80)


def beep_move():
    """Three quick high beeps: 'move cursor NOW'."""
    for _ in range(3):
        winsound.Beep(1200, 80)
        time.sleep(0.06)


def beep_snap():
    """Rising two-tone: snapshot just taken."""
    winsound.Beep(700, 120)
    winsound.Beep(1100, 200)


def beep_done():
    """Three ascending tones: investigation complete."""
    winsound.Beep(600,  150)
    winsound.Beep(900,  150)
    winsound.Beep(1200, 300)


def countdown_ticks(seconds):
    """Tick-beep a countdown for 'seconds' seconds."""
    for i in range(seconds, 0, -1):
        print(f"  {i}...", flush=True)
        beep_tick()
        time.sleep(0.92)


# ---------------------------------------------------------------------------
# Tee: Mirror all print() output to both terminal and log file.
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Frida JS agent.
#
# ArrayBuffer copy technique:
#   new ArrayBuffer(size) allocates in V8's managed JS heap.
#   new Uint8Array(buf).set(new Uint8Array(raw)) reads bytes from raw at
#   the time .set() is called (the moment of snapshot) and writes them into
#   buf's V8-managed backing store. After .set() returns, buf is completely
#   independent of native process memory — even if raw is a live view, the
#   values already got copied into buf and buf reads from its own storage.
#
# All export names are fully lowercase (exports_sync lowercases before lookup).
# ---------------------------------------------------------------------------

JS_CODE = r"""
'use strict';

var snaps = { s1: null, s2: null, s3: null };

// Direct block-probe approach: bypass Process.enumerateRanges entirely.
// enumerateRanges was returning 0 results due to a Frida version issue on
// this platform. Instead, we walk every BLOCK_SIZE bytes from SCAN_START to
// SCAN_END and try to read each block. Non-mapped / guard pages throw and
// are silently skipped; readable pages are stored. Windows VirtualAlloc
// granularity is 64KB so aligned 64KB reads rarely straddle region boundaries.
var SCAN_START = 0x400000;
var SCAN_END   = 0x20000000;  // 512 MB — covers FF7 BSS (0x9-0xDE range) and heap
var BLOCK_SIZE = 65536;       // 64 KB per block

function takeSnap(tag) {
    var entries = [];
    var total   = 0;

    for (var addr = SCAN_START; addr < SCAN_END; addr += BLOCK_SIZE) {
        try {
            var raw = Memory.readByteArray(ptr(addr), BLOCK_SIZE);
            if (raw === null) continue;
            // Explicit copy into a V8-managed ArrayBuffer.
            // new Uint8Array(buf).set(new Uint8Array(raw)) reads the bytes from
            // raw at the moment .set() executes and writes them into buf, which
            // lives in V8's managed heap. After .set() returns, buf is completely
            // independent of any live native memory pointer — guaranteed copy.
            var buf = new ArrayBuffer(BLOCK_SIZE);
            new Uint8Array(buf).set(new Uint8Array(raw));
            entries.push([ptr(addr).toString(), BLOCK_SIZE, buf]);
            total += BLOCK_SIZE;
        } catch(e) {
            // Non-mapped, non-readable, or guard page — skip.
        }
    }
    snaps[tag] = entries;
    return [entries.length, total];
}

function compareSnaps(tag_a, tag_b, max_results) {
    var sa = snaps[tag_a];
    var sb = snaps[tag_b];
    if (!sa || !sb) return [];

    var bmap = {};
    for (var i = 0; i < sb.length; i++) {
        bmap[sb[i][0]] = sb[i][2];
    }

    var changed = [];
    outer:
    for (var i = 0; i < sa.length; i++) {
        var base  = sa[i][0];
        var buf_a = sa[i][2];
        var buf_b = bmap[base];
        if (!buf_b) continue;

        var arr_a = new Uint8Array(buf_a);
        var arr_b = new Uint8Array(buf_b);
        var bptr  = ptr(base);

        for (var j = 0; j < arr_a.length; j++) {
            if (arr_a[j] !== arr_b[j]) {
                changed.push([bptr.add(j).toString(), arr_a[j], arr_b[j]]);
                if (changed.length >= max_results) break outer;
            }
        }
    }
    return changed;
}

rpc.exports = {
    takesnap1: function() { return takeSnap('s1'); },
    takesnap2: function() { return takeSnap('s2'); },
    takesnap3: function() { return takeSnap('s3'); },
    compare12: function(max) { return compareSnaps('s1', 's2', max || 50000); },
    compare23: function(max) { return compareSnaps('s2', 's3', max || 50000); },
    clearsnapshots: function() { snaps = { s1: null, s2: null, s3: null }; },
};
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"title_fast_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    session = None
    try:
        print(f"Output saving to: {log_path}")
        print()

        print(f"Attaching to {PROCESS_NAME}...")
        try:
            session = frida.attach(PROCESS_NAME)
        except frida.ProcessNotFoundError:
            speak_wait("Error: F F 7 not found. Start the game first.")
            print(f"ERROR: {PROCESS_NAME} not found.")
            sys.exit(1)

        frida_script = session.create_script(JS_CODE)
        frida_script.load()
        print("Attached.")
        print()

        # Initial prompt while terminal still has focus.
        speak_wait(
            "Attached to F F 7. "
            "Make sure you are on the title screen with the cursor on Continue. "
            "When ready, press Enter in the terminal. "
            "After pressing Enter, immediately switch focus to F F 7 and stay there. "
            "Do not switch back to the terminal for the rest of the investigation."
        )
        input("Press ENTER when on title screen (cursor on CONTINUE), then switch to FF7...")
        print()

        # Give the user time to switch focus to FF7.
        # FF7 2013 Steam freezes its game loop when its window loses focus, so
        # ALL subsequent snapshots must be taken with FF7 as the active window.
        speak_wait(
            f"Switching to F F 7 in {FOCUS_WAIT_SEC} seconds. "
            "Switch now and keep F F 7 focused."
        )
        countdown_ticks(FOCUS_WAIT_SEC)
        print()

        # ── Sanity check (FF7 now has focus, game is running) ─────────────────
        # Take two rapid snapshots 300ms apart. A running FF7 title screen changes
        # thousands of bytes per frame (audio position, frame counter, etc.). If 0
        # bytes differ here, something is genuinely wrong with the snapshotting.
        # NOTE: The previous sanity-check failure was because it ran while the
        # TERMINAL had focus and FF7 was frozen. It now runs after the switch.
        print("Sanity check (FF7 should be in focus now)...")
        n_s1, kb_s1 = frida_script.exports_sync.takesnap1()
        time.sleep(0.3)
        n_s2, kb_s2 = frida_script.exports_sync.takesnap2()
        sanity = frida_script.exports_sync.compare12(10)
        print(f"  Snap1: {n_s1} ranges, {kb_s1//1024} KB")
        print(f"  Snap2: {n_s2} ranges, {kb_s2//1024} KB")
        print(f"  Changes in 300ms: {len(sanity)}")

        if n_s1 == 0:
            speak_wait(
                "Error: Frida found zero memory ranges to scan. "
                "The investigation cannot proceed. Check that FF7 is still running."
            )
            print()
            print("FATAL: enumerateRanges returned 0 ranges. FF7 may have crashed.")
            print(f"Log saved to: {log_path}")
            return

        if len(sanity) == 0:
            speak_wait(
                "Warning: sanity check found zero changes between two snapshots "
                "of a running game. F F 7 may still be frozen, or the ArrayBuffer "
                "copy is still not working. Proceeding anyway — results may be zero."
            )
            print("  WARNING: 0 changes in 300ms. FF7 may still be out of focus,")
            print("  or the explicit ArrayBuffer copy is not working on this build.")
            print("  Continuing — if cursor investigation also finds 0, the issue")
            print("  is the ArrayBuffer copy. Report Frida version: pip show frida")
        else:
            speak_wait(f"Sanity check passed: {len(sanity)} changes detected.")
            print(f"  Sanity check PASSED.")
        print()

        # ── Snapshot 1: CONTINUE ──────────────────────────────────────────────
        # FF7 has focus. Cursor should be on Continue.
        speak_wait("Snapshotting Continue position. Do not move the cursor. Wait.")
        print("Snapshot 1 (Continue)...")
        t0 = time.time()
        n1, kb1 = frida_script.exports_sync.takesnap1()
        elapsed = time.time() - t0
        print(f"  Done in {elapsed:.2f}s — {n1} ranges, {kb1//1024} KB")
        print()

        # ── Move to NEW GAME ──────────────────────────────────────────────────
        speak_wait(
            "Ready. On my mark, press Up or Down ONCE to move to New Game. "
            f"You have {MOVE_WINDOW_SEC:.0f} seconds after the beeps. Move on the beeps."
        )
        beep_move()
        time.sleep(MOVE_WINDOW_SEC)

        # ── Snapshot 2: NEW GAME ──────────────────────────────────────────────
        beep_snap()
        print("Snapshot 2 (New Game)...")
        t0 = time.time()
        n2, kb2 = frida_script.exports_sync.takesnap2()
        elapsed = time.time() - t0
        print(f"  Done in {elapsed:.2f}s — {n2} ranges, {kb2//1024} KB")

        print("Diffing Continue → New Game...")
        fwd = frida_script.exports_sync.compare12(50000)
        print(f"  {len(fwd)} byte(s) changed.")
        print()

        if len(fwd) == 0:
            speak_wait(
                "No bytes changed between snapshots. "
                "Either the cursor did not move, or FF7 was still frozen. "
                "If the sanity check also found 0 changes, the issue is "
                "Frida's ArrayBuffer copy. Run pip show frida and report the version."
            )
            print("No changes detected. Check:")
            print("  1. Did FF7 have focus during the cursor move?")
            print("  2. Did the sanity check above also show 0 changes?")
            print("     If yes → Frida ArrayBuffer copy bug. Run: pip show frida")
            print("  3. Is MOVE_WINDOW_SEC large enough? Increase it at top of file.")
            print(f"\nLog saved to: {log_path}")
            return

        # ── Move back to CONTINUE ─────────────────────────────────────────────
        speak_wait(
            f"{len(fwd)} bytes changed. Good. "
            "Now move the cursor BACK to Continue on the beeps."
        )
        beep_move()
        time.sleep(MOVE_WINDOW_SEC)

        # ── Snapshot 3: CONTINUE again ────────────────────────────────────────
        beep_snap()
        print("Snapshot 3 (Continue again)...")
        t0 = time.time()
        n3, kb3 = frida_script.exports_sync.takesnap3()
        elapsed = time.time() - t0
        print(f"  Done in {elapsed:.2f}s — {n3} ranges, {kb3//1024} KB")

        print("Diffing New Game → Continue...")
        back = frida_script.exports_sync.compare23(50000)
        print(f"  {len(back)} byte(s) changed.")
        print()

        # ── Filter: changed both ways AND reverted to exact original ──────────
        fwd_map  = {row[0]: (row[1], row[2]) for row in fwd}
        back_map = {row[0]: (row[1], row[2]) for row in back}

        candidates = []
        for addr, (cont_val, ng_val) in sorted(fwd_map.items()):
            if addr not in back_map:
                continue
            _ng, cont2 = back_map[addr]
            if cont2 == cont_val:
                candidates.append((int(addr, 16), cont_val, ng_val))

        n = len(candidates)
        print(f"=== FINAL CANDIDATES: {n} address(es) ===")
        print("(Changed Continue→NewGame AND reverted NewGame→Continue)")
        print()

        if n == 0:
            speak_wait(
                "No candidates survived the revert filter. "
                "Showing bytes that changed in both directions."
            )
            both = sorted(set(fwd_map.keys()) & set(back_map.keys()))
            print(f"Both-direction changes (revert not clean): {len(both)}")
            for addr in both[:30]:
                cont, ng   = fwd_map[addr]
                ng2, cont2 = back_map[addr]
                print(f"  0x{int(addr,16):08X}  "
                      f"cont={cont}  ng={ng}  final={cont2}")
            if len(both) > 30:
                print(f"  ... and {len(both)-30} more")

        elif n > 50:
            speak_wait(
                f"{n} candidates — too many. Background timers matched the pattern. "
                "Showing only small-value candidates (values 0 to 4)."
            )
            print(f"WARNING: {n} candidates — likely includes background timer noise.")
            small = [(a, c, g) for a, c, g in candidates if c <= 4 and g <= 4]
            print(f"Small-value candidates (both values ≤ 4): {len(small)}")
            print()
            for addr, cont_val, ng_val in small[:50]:
                print(f"  0x{addr:08X}  Continue={cont_val}  NewGame={ng_val}")

        else:
            speak_wait(
                f"{n} candidate{'s' if n != 1 else ''} found. "
                "Check the log file. The cursor byte has small values like 0 and 1."
            )
            for addr, cont_val, ng_val in candidates:
                note = " <-- LIKELY CURSOR" if cont_val <= 4 and ng_val <= 4 else ""
                print(f"  0x{addr:08X}  Continue={cont_val} (0x{cont_val:02X})"
                      f"  NewGame={ng_val} (0x{ng_val:02X}){note}")

        print()
        print("=== IDENTIFICATION GUIDE ===")
        print("Title cursor byte:")
        print("  - Value 0 on one option and 1 (or small nonzero) on the other")
        print("  - Address in 0x900000–0xDEFFFF (game data/BSS segment)")
        print("  - Surrounded by near-zero values in a hex dump")
        print()
        print("If > 50 candidates: run immediately after title screen finishes loading")
        print("  so fewer animation counters are cycling.")
        print("If 0 candidates: try moving the cursor MORE times to get cleaner revert.")
        print(f"\nLog saved to: {log_path}")
        beep_done()
        speak_wait("Investigation complete. Check the log file.")

    finally:
        if session:
            try:
                frida_script.exports_sync.clearsnapshots()
            except Exception:
                pass
            session.detach()
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    main()
