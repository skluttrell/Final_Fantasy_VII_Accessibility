#!/usr/bin/env python3
"""
ff7_battle_menu_cursor_hwbp.py -- Hardware write-watchpoint debugger, replacing
Cheat Engine's "find out what writes to this address" (CE would not launch on
this machine: "This app won't run on your PC").

WHY (2026-07-07): Two full-heap ReadProcessMemory delta-scans (see
ff7_battle_menu_cursor_fullscan.py and ff7_battle_menu_cursor_edge_scan.py)
both failed -- the process has millions of bytes of background memory churn
per second (audio, particles, allocator activity) even at idle, and
thousands of addresses react to ANY input event, not specifically to cursor
movement. Byte-diffing cannot separate signal from this much noise.

This script instead attaches AS A DEBUGGER to the running FF7 process (the
same underlying Windows Debug API that Cheat Engine, x64dbg, WinDbg etc. use)
and arms a genuine CPU hardware write-watchpoint (via the DR0/DR7 debug
registers) on TARGET_ADDR -- one of the known "event pulse" addresses
(0x009ADE30) that fires on ANY d-pad press. When ANY instruction in the game
writes to that byte, the CPU itself traps -- no polling, no noise, no missed
events. We log the exact instruction address that did the write; from there
a disassembly listing (next step, not in this script) can reveal the nearby
code that also updates the real persisted cursor index.

*** SAFETY -- READ BEFORE RUNNING ***
This is the first script this investigation has used that attaches as a
live debugger to the running game (all previous scripts only ever *read*
memory via a normal process handle). Attaching a debugger sets real CPU
debug registers on the game's threads. If this script crashes or is killed
WITHOUT running its cleanup, those debug registers stay armed with no
debugger left to catch the trap -- the next time the game writes to
TARGET_ADDR (very likely almost immediately, since it fires on every d-pad
press), Windows would deliver an unhandled exception and the GAME WOULD
CRASH. There is no save-corruption or lasting-harm risk (mid-battle state
isn't persisted) -- worst case is restarting FF7 -- but to make that
practically not happen, cleanup runs from FOUR independent triggers:
  1. Normal completion (end of the `with DebuggerSession(...)` block)
  2. Any exception inside the block (try/finally)
  3. atexit (covers os._exit-style abnormal termination paths)
  4. SIGINT/SIGTERM handlers (covers Ctrl+C or an external kill)
DebugSetProcessKillOnExit(FALSE) is also set immediately after attaching, so
if this script's process is killed outright (cleanup can't run at all), the
GAME IS NOT KILLED ALONG WITH IT -- worst case then is the game running with
a stale breakpoint until it writes to that byte, matching the risk above.

SAFETY for the player: only Up/Down are used. Do NOT press Right (=Confirm).

*** MITIGATION AFTER FIRST CRASH (2026-07-08) ***
The first real run against FF7 crashed the game (silent exit, no dialog) a
few events after attaching. The log showed 71 CREATE_THREAD_DEBUG_EVENTs
fired in a rapid retroactive backlog (Windows reports one for every thread
that already existed at attach time, not 71 new threads), and the previous
version armed the hardware breakpoint on EVERY one of them synchronously,
inside the WaitForDebugEvent/ContinueDebugEvent loop -- during which the
ENTIRE target process is frozen (Windows debug semantics stop all threads,
not just the reporting one, until ContinueDebugEvent is called). Best
working theory: something time-sensitive (likely audio buffer servicing,
given how audio-heavy this engine's background activity was in the earlier
heap scans) has a watchdog that doesn't tolerate a stall that long, hit a
timeout, and the game shut itself down.

Mitigation, three phases instead of one:
  1. FAST-DRAIN: process the initial backlog doing the absolute minimum
     work per event (no breakpoint arming at all) to get through the freeze
     window as fast as possible.
  2. ARM: once drained (no new event within a short window), arm the
     breakpoint on ONLY the main thread (most likely place for menu/UI
     code), via SuspendThread/SetContext/ResumeThread OUTSIDE the debug
     event loop -- a brief, isolated single-thread pause instead of an
     all-threads freeze.
  3. WATCH: resume the normal event loop, now doing minimal work per event
     (no further breakpoint arming), watching only for hits on that one
     thread.
This trades coverage (if the real write happens on a non-main thread, this
run will find nothing rather than crash) for safety.

PROCEDURE (self-cued, no chat round-trip):
  1. Speaks instructions.
  2. Attaches, fast-drains the initial backlog, arms ONLY the main thread.
  3. Beeps once per requested press; you press Down once per beep.
  4. Logs each hit (thread id + instruction address) to the log file.
  5. Cleans up and detaches after MAX_HITS hits or MAX_TOTAL_SECONDS,
     whichever comes first.
"""
import atexit
import ctypes
from ctypes import wintypes
import signal
import subprocess
import sys
import os
import time
import winsound

PROCESS_NAME = "ff7_en.exe"
TARGET_ADDR = 0x009ADE30   # known event-pulse address; fires on ANY d-pad press

MAX_HITS = 8
MAX_TOTAL_SECONDS = 45
WAIT_TIMEOUT_MS = 1500
DRAIN_QUIET_MS = 250     # phase 1 ends after this long with no new event
DRAIN_MAX_SECONDS = 5    # hard cap on phase 1 even if events keep streaming

CONTEXT_i386 = 0x00010000
CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x00000010

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_BREAKPOINT = 0x80000003
# On a WOW64 (32-bit-under-64-bit) target, the debug-trap exception for a
# hardware breakpoint is reported to a 64-bit debugger under this WOW64-
# specific status code instead of plain EXCEPTION_SINGLE_STEP (confirmed via
# _hwbp_selftest2_realhit.py against a genuine x86 test target: two hits
# fired and were reported as 0x4000001E, not 0x80000004).
STATUS_WX86_SINGLE_STEP = 0x4000001E
STATUS_WX86_BREAKPOINT = 0x4000001F

# DR7: L0=1 (bit0), LE/GE compat bits (8,9), RW0=01 write (bits16-17), LEN0=00 1-byte (bits18-19)
DR7_WRITE_WATCH_1BYTE = (1 << 0) | (1 << 8) | (1 << 9) | (0b01 << 16) | (0b00 << 18)

SE_DEBUG_NAME = "SeDebugPrivilege"
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x0002

DEBUG_EVENT_BUF_SIZE = 256

k32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32


class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ("ControlWord", ctypes.c_uint32),
        ("StatusWord", ctypes.c_uint32),
        ("TagWord", ctypes.c_uint32),
        ("ErrorOffset", ctypes.c_uint32),
        ("ErrorSelector", ctypes.c_uint32),
        ("DataOffset", ctypes.c_uint32),
        ("DataSelector", ctypes.c_uint32),
        ("RegisterArea", ctypes.c_uint8 * 80),
        ("Cr0NpxState", ctypes.c_uint32),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint32),
        ("Dr1", ctypes.c_uint32),
        ("Dr2", ctypes.c_uint32),
        ("Dr3", ctypes.c_uint32),
        ("Dr6", ctypes.c_uint32),
        ("Dr7", ctypes.c_uint32),
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
        ("SegGs", ctypes.c_uint32),
        ("SegFs", ctypes.c_uint32),
        ("SegEs", ctypes.c_uint32),
        ("SegDs", ctypes.c_uint32),
        ("Edi", ctypes.c_uint32),
        ("Esi", ctypes.c_uint32),
        ("Ebx", ctypes.c_uint32),
        ("Edx", ctypes.c_uint32),
        ("Ecx", ctypes.c_uint32),
        ("Eax", ctypes.c_uint32),
        ("Ebp", ctypes.c_uint32),
        ("Eip", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint32),
        ("EFlags", ctypes.c_uint32),
        ("Esp", ctypes.c_uint32),
        ("SegSs", ctypes.c_uint32),
        ("ExtendedRegisters", ctypes.c_uint8 * 512),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", ctypes.c_long)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


k32.Wow64GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(WOW64_CONTEXT)]
k32.Wow64GetThreadContext.restype = ctypes.c_int
k32.Wow64SetThreadContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(WOW64_CONTEXT)]
k32.Wow64SetThreadContext.restype = ctypes.c_int
k32.DebugActiveProcess.argtypes = [wintypes.DWORD]
k32.DebugActiveProcess.restype = ctypes.c_int
k32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
k32.DebugActiveProcessStop.restype = ctypes.c_int
k32.DebugSetProcessKillOnExit.argtypes = [ctypes.c_int]
k32.DebugSetProcessKillOnExit.restype = ctypes.c_int
k32.WaitForDebugEvent.argtypes = [ctypes.c_void_p, wintypes.DWORD]
k32.WaitForDebugEvent.restype = ctypes.c_int
k32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
k32.ContinueDebugEvent.restype = ctypes.c_int
k32.SuspendThread.argtypes = [ctypes.c_void_p]
k32.SuspendThread.restype = wintypes.DWORD
k32.ResumeThread.argtypes = [ctypes.c_void_p]
k32.ResumeThread.restype = wintypes.DWORD


class Tee:
    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log = log_file

    def write(self, data):
        self._terminal.write(data)
        self._log.write(data)

    def flush(self):
        self._terminal.flush()
        self._log.flush()

    def __getattr__(self, name):
        return getattr(self._terminal, name)


def speak(text):
    safe = text.replace("'", "''")
    try:
        subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=90)
    except Exception:
        pass


def beep(freq=1000, ms=100):
    winsound.Beep(freq, ms)


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


def enable_debug_privilege():
    hToken = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(k32.GetCurrentProcess(),
                                      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                      ctypes.byref(hToken)):
        return False
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        return bool(advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None))
    finally:
        k32.CloseHandle(hToken)


def read_u32(buf, off):
    return int.from_bytes(bytes(buf[off:off + 4]), 'little')


def read_ptr(buf, off):
    return int.from_bytes(bytes(buf[off:off + 8]), 'little')


def wait_for_debug_event(timeout_ms):
    buf = (ctypes.c_uint8 * DEBUG_EVENT_BUF_SIZE)()
    ok = k32.WaitForDebugEvent(ctypes.byref(buf), timeout_ms)
    if not ok:
        return None
    code = read_u32(buf, 0)
    epid = read_u32(buf, 4)
    etid = read_u32(buf, 8)
    return code, epid, etid, buf


def arm_breakpoint(hThread, addr):
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
    if not k32.Wow64GetThreadContext(hThread, ctypes.byref(ctx)):
        print(f"  WARN: Wow64GetThreadContext failed (err={k32.GetLastError()})")
        return False
    ctx.Dr0 = addr
    ctx.Dr7 = DR7_WRITE_WATCH_1BYTE
    if not k32.Wow64SetThreadContext(hThread, ctypes.byref(ctx)):
        print(f"  WARN: Wow64SetThreadContext failed (err={k32.GetLastError()})")
        return False
    return True


def clear_breakpoint(hThread):
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
    if k32.Wow64GetThreadContext(hThread, ctypes.byref(ctx)):
        ctx.Dr0 = 0
        ctx.Dr7 = 0
        k32.Wow64SetThreadContext(hThread, ctypes.byref(ctx))


class DebuggerSession:
    """Attaches on __enter__, guarantees breakpoint-clear + detach on the way
    out via __exit__, atexit, and signal handlers -- whichever fires first."""

    def __init__(self, pid):
        self.pid = pid
        self.attached = False
        self.threads = {}   # tid -> hThread
        self._cleaned = False
        atexit.register(self.cleanup)
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._signal_handler)
            except Exception:
                pass

    def _signal_handler(self, signum, frame):
        self.cleanup()
        sys.exit(1)

    def __enter__(self):
        enable_debug_privilege()
        if not k32.DebugActiveProcess(self.pid):
            raise OSError(f"DebugActiveProcess failed, err={k32.GetLastError()}")
        self.attached = True
        k32.DebugSetProcessKillOnExit(0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False

    def cleanup(self):
        if self._cleaned:
            return
        self._cleaned = True
        for tid, hThread in list(self.threads.items()):
            clear_breakpoint(hThread)
        if self.attached:
            k32.DebugActiveProcessStop(self.pid)
            self.attached = False


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(script_dir, f"battle_menu_hwbp_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    try:
        print(f"Output saving to: {log_path}\n")

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak("FF7 not found. Start the game and get into a battle first.")
            print("ERROR: ff7_en.exe not running.")
            return
        print(f"PID: {pid}")
        print(f"Target address: 0x{TARGET_ADDR:08X}")

        hits = []

        with DebuggerSession(pid) as dbg:
            print("Attached as debugger. Kill-on-exit disabled.")

            # ── Phase 1: fast-drain the initial retroactive backlog ────────
            # Absolute minimum work per event -- no breakpoint arming here --
            # to get through the process-wide freeze window as fast as
            # possible. Ends once no new event arrives within DRAIN_QUIET_MS.
            print("Phase 1: fast-draining initial backlog...")
            main_tid = None
            drain_start = time.time()
            seen_threads = 0
            process_exited_early = False

            while (time.time() - drain_start) < DRAIN_MAX_SECONDS:
                ev = wait_for_debug_event(DRAIN_QUIET_MS)
                if ev is None:
                    break  # quiet gap -> backlog drained
                code, epid, etid, buf = ev
                continue_status = DBG_CONTINUE

                if code == CREATE_PROCESS_DEBUG_EVENT:
                    hThread = read_ptr(buf, 32)
                    hFile = read_ptr(buf, 16)
                    dbg.threads[etid] = hThread
                    main_tid = etid
                    if hFile:
                        k32.CloseHandle(hFile)
                    seen_threads += 1
                elif code == CREATE_THREAD_DEBUG_EVENT:
                    hThread = read_ptr(buf, 16)
                    dbg.threads[etid] = hThread
                    seen_threads += 1
                elif code == EXIT_THREAD_DEBUG_EVENT:
                    dbg.threads.pop(etid, None)
                elif code == LOAD_DLL_DEBUG_EVENT:
                    hFile = read_ptr(buf, 16)
                    if hFile:
                        k32.CloseHandle(hFile)
                elif code == EXCEPTION_DEBUG_EVENT:
                    exc_code = read_u32(buf, 16)
                    if exc_code not in (EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT):
                        continue_status = DBG_EXCEPTION_NOT_HANDLED
                elif code == EXIT_PROCESS_DEBUG_EVENT:
                    process_exited_early = True
                    k32.ContinueDebugEvent(epid, etid, continue_status)
                    break

                k32.ContinueDebugEvent(epid, etid, continue_status)

            print(f"Phase 1 done: {seen_threads} threads seen, main_tid={main_tid}")

            if process_exited_early:
                print("ERROR: process exited during backlog drain.")
                speak("FF7 exited during setup. Stopping.")
            elif main_tid is None:
                print("ERROR: never saw CREATE_PROCESS_DEBUG_EVENT, cannot identify main thread.")
                speak("Could not identify the main thread. Stopping.")
            else:
                # ── Phase 2: arm ONLY the main thread, outside the debug loop ──
                hMainThread = dbg.threads[main_tid]
                k32.SuspendThread(hMainThread)
                try:
                    armed = arm_breakpoint(hMainThread, TARGET_ADDR)
                finally:
                    k32.ResumeThread(hMainThread)
                print(f"Phase 2: armed main thread only = {armed}")

                if not armed:
                    speak("Failed to arm the breakpoint. Stopping.")
                else:
                    speak(
                        "Debugger attached, main thread armed. Command window should be open, "
                        "only Up and Down, do not press Right. I will beep once per round -- "
                        "press Down once per beep."
                    )

                    # ── Phase 3: watch loop -- minimal work per event ──────
                    start = time.time()
                    while (time.time() - start) < MAX_TOTAL_SECONDS and len(hits) < MAX_HITS:
                        ev = wait_for_debug_event(WAIT_TIMEOUT_MS)
                        if ev is None:
                            continue
                        code, epid, etid, buf = ev
                        continue_status = DBG_CONTINUE

                        if code == CREATE_THREAD_DEBUG_EVENT:
                            hThread = read_ptr(buf, 16)
                            dbg.threads[etid] = hThread  # tracked for cleanup only, not armed
                        elif code == EXIT_THREAD_DEBUG_EVENT:
                            dbg.threads.pop(etid, None)
                        elif code == LOAD_DLL_DEBUG_EVENT:
                            hFile = read_ptr(buf, 16)
                            if hFile:
                                k32.CloseHandle(hFile)
                        elif code == EXCEPTION_DEBUG_EVENT:
                            exc_code = read_u32(buf, 16)
                            exc_addr = read_ptr(buf, 32)
                            if exc_code in (EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP):
                                hits.append((etid, exc_addr))
                                print(f"[HIT #{len(hits)}] tid={etid} instr_addr=0x{exc_addr:08X}")
                                beep(1600, 80)
                            elif exc_code in (EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT):
                                print(f"[BREAKPOINT] code=0x{exc_code:08X} (continuing)")
                            else:
                                print(f"[EXCEPTION] code=0x{exc_code:08X} (not ours, passing through)")
                                continue_status = DBG_EXCEPTION_NOT_HANDLED
                        elif code == EXIT_PROCESS_DEBUG_EVENT:
                            print("[EXIT_PROCESS] target process exited.")
                            k32.ContinueDebugEvent(epid, etid, continue_status)
                            break

                        k32.ContinueDebugEvent(epid, etid, continue_status)

                    beep(1100, 300); time.sleep(0.3); beep(1100, 300)
                    print(f"\nDone. Total hits: {len(hits)}")

        # dbg.__exit__ has already cleared breakpoints and detached by here
        speak("Scan complete, debugger detached cleanly. You may act normally now.")

        print("\n" + "=" * 60)
        print("  RESULTS")
        print("=" * 60)
        print(f"\n  {'#':3}  {'ThreadID':>9}  {'InstrAddr':10}")
        print(f"  {'-'*3}  {'-'*9}  {'-'*10}")
        for i, (tid, addr) in enumerate(hits, 1):
            print(f"  {i:3d}  {tid:9d}  0x{addr:08X}")

        print(f"\nLog saved to: {log_path}")

    finally:
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
