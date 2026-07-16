/*
 * gamepad.cpp -- Right-analog-stick pathfinder input (v2.21).
 *
 * See gamepad.h for the action map and the evidence that the right stick
 * and R3 are free of any native game function. This file is about the HOW:
 *
 * DYNAMIC XINPUT LOADING (LoadLibrary, not an import):
 *   This module lives inside version.dll, a proxy DLL that Windows resolves
 *   during process import snapshotting — the most fragile moment of process
 *   startup. Adding a static xinput import there would make controller
 *   support a LOAD-TIME dependency of the whole mod: any machine where the
 *   DLL is missing or blocked would lose ALL accessibility features, not
 *   just the stick. Loading lazily from the poll thread instead means a
 *   missing/broken XInput degrades to exactly one thing: the stick does
 *   nothing. xinput9_1_0.dll is chosen over xinput1_4/1_3 because it ships
 *   with every Windows since Vista — no DirectX-redist dependency.
 *
 * DISCONNECTED-SLOT BACKOFF (the one real efficiency trap):
 *   XInputGetState on an EMPTY slot is documented/measured to be far
 *   slower than on a connected one (it re-enumerates devices, up to the
 *   millisecond range on some stacks). Naively scanning 4 empty slots
 *   every 50ms poll could burn more CPU than the rest of the nav thread
 *   combined. So: remember the connected slot and poll only it; when
 *   nothing is connected, rescan all 4 slots at most once every 3 seconds.
 *   Result: pad connected = one cheap call per tick; no pad = idle.
 *
 * HYSTERESIS ON THE STICK (engage 60%, release 40%):
 *   A flick is an edge, like a keypress. With a single threshold, holding
 *   the stick right AT the threshold would rattle across it (hand tremor,
 *   spring noise) and fire a machine-gun of category/destination steps.
 *   The two-level scheme makes the boundary sticky: you must deflect past
 *   60% to fire, and return under 40% before the same direction can fire
 *   again. No auto-repeat, deliberately — the keyboard side is pure edges
 *   too (GetAsyncKeyState transitions), so parity holds: one flick, one
 *   step; hold-to-scroll exists in neither input path.
 *
 * DOMINANT-AXIS 4-WAY DECODE:
 *   The browser needs up/down/left/right, but a thumb never moves on one
 *   axis only. The larger |axis| wins, so a sloppy up-and-slightly-right
 *   flick is just "up". Rolling the stick from one direction to another
 *   without re-centering fires the new direction the moment the old one
 *   drops below its release threshold and the new axis is past engage —
 *   which lets a user sweep "category down, then entity right" in one
 *   motion without a mandatory stop at center.
 */

#include "gamepad.h"
#include "log.h"     // controller connect/disconnect diagnostics

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <Xinput.h>

#include <cstdio>    // _snprintf_s for the slot-number log line
#include <cstdlib>   // abs
#include <cstdint>   // uint8_t (Dir4's storage type)

namespace GamepadNav {

namespace {

// ---- lazy XInput binding ---------------------------------------------------

typedef DWORD (WINAPI* XInputGetState_t)(DWORD, XINPUT_STATE*);

XInputGetState_t g_XInputGetState = nullptr;
bool             g_init_attempted = false;

// Resolve XInputGetState once. Failure is permanent for the session (there
// is no scenario where xinput9_1_0.dll appears later) and leaves the module
// as a no-op.
bool EnsureXInput()
{
    if (!g_init_attempted) {
        g_init_attempted = true;
        // The HMODULE is intentionally never freed: the poll thread uses the
        // function pointer for the life of the process.
        if (HMODULE h = LoadLibraryW(L"xinput9_1_0.dll"))
            g_XInputGetState = reinterpret_cast<XInputGetState_t>(
                GetProcAddress(h, "XInputGetState"));
        // Failure is worth one log line (it means gamepad_nav can never
        // work this session); success is silent — the interesting event on
        // the success path is the controller CONNECTING, logged in ReadPad.
        if (!g_XInputGetState)
            Log::Write("[FF7Access] GAMEPAD xinput9_1_0.dll unavailable - "
                       "right-stick navigation disabled");
    }
    return g_XInputGetState != nullptr;
}

// ---- controller-slot tracking ----------------------------------------------

int       g_slot = -1;              // connected slot, -1 = none known
ULONGLONG g_next_scan_tick = 0;     // earliest allowed empty-slot rescan
constexpr ULONGLONG RESCAN_MS = 3000;

// ---- per-tick input state (edge detection) ----------------------------------

enum Dir4 : uint8_t { DIR_NONE, DIR_UP, DIR_DOWN, DIR_LEFT, DIR_RIGHT };

Dir4 g_dir     = DIR_NONE;   // direction currently held past threshold
bool g_r3_down = false;      // R3 click held

// Thresholds on the raw signed 16-bit axis range (32767 = full deflection).
constexpr int ENGAGE_RAW  = 19660;   // ~60% — must exceed to fire
constexpr int RELEASE_RAW = 13107;   // ~40% — must drop under to re-arm

// Fetch the current pad state, handling slot memory and rescan backoff.
// Returns false when no controller is available this tick.
bool ReadPad(XINPUT_STATE* st)
{
    if (!EnsureXInput())
        return false;

    if (g_slot >= 0) {
        if (g_XInputGetState(g_slot, st) == ERROR_SUCCESS)
            return true;
        // Just unplugged: forget the slot and start the rescan clock so we
        // don't hammer the (now slow) empty slot on the very next tick.
        Log::Write("[FF7Access] GAMEPAD controller disconnected");
        g_slot = -1;
        g_next_scan_tick = GetTickCount64() + RESCAN_MS;
        return false;
    }

    const ULONGLONG now = GetTickCount64();
    if (now < g_next_scan_tick)
        return false;
    g_next_scan_tick = now + RESCAN_MS;

    for (DWORD i = 0; i < XUSER_MAX_COUNT; ++i) {
        if (g_XInputGetState(i, st) == ERROR_SUCCESS) {
            g_slot = static_cast<int>(i);
            char msg[80];
            _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                        "[FF7Access] GAMEPAD controller connected (slot %lu) "
                        "- right-stick navigation active", i);
            Log::Write(msg);
            return true;
        }
    }
    return false;
}

} // anonymous namespace

void Reset()
{
    g_dir     = DIR_NONE;
    g_r3_down = false;
}

Actions Poll(bool active)
{
    Actions out = {};

    XINPUT_STATE st = {};
    if (!ReadPad(&st)) {
        // No controller: park the held-state at "released". A pad plugged
        // in later starts from a clean baseline, and a pad yanked out
        // mid-hold cannot leave a phantom held direction behind.
        Reset();
        return out;
    }

    const SHORT rx = st.Gamepad.sThumbRX;
    const SHORT ry = st.Gamepad.sThumbRY;   // XInput: positive Y = stick up

    // Keep the held direction while its own axis component stays past the
    // RELEASE threshold — direction changes and jitter both have to break
    // the hold first (hysteresis, see header comment).
    bool still_held = false;
    switch (g_dir) {
        case DIR_UP:    still_held = ry >=  RELEASE_RAW; break;
        case DIR_DOWN:  still_held = ry <= -RELEASE_RAW; break;
        case DIR_LEFT:  still_held = rx <= -RELEASE_RAW; break;
        case DIR_RIGHT: still_held = rx >=  RELEASE_RAW; break;
        case DIR_NONE:  break;
    }

    Dir4 dir = g_dir;
    if (!still_held) {
        // Re-arm: dominant axis past ENGAGE wins; ties go to vertical
        // (arbitrary but stable — a perfect 45° hold picks one action
        // instead of alternating).
        const int ax = std::abs(rx), ay = std::abs(ry);
        if (ay >= ax && ay >= ENGAGE_RAW)
            dir = (ry > 0) ? DIR_UP : DIR_DOWN;
        else if (ax > ay && ax >= ENGAGE_RAW)
            dir = (rx > 0) ? DIR_RIGHT : DIR_LEFT;
        else
            dir = DIR_NONE;
    }

    const bool dir_edge = active && dir != g_dir && dir != DIR_NONE;
    g_dir = dir;

    const bool r3 = (st.Gamepad.wButtons & XINPUT_GAMEPAD_RIGHT_THUMB) != 0;
    const bool r3_edge = active && r3 && !g_r3_down;
    g_r3_down = r3;

    if (dir_edge) {
        switch (dir) {
            case DIR_UP:    out.prev_cat  = true; break;
            case DIR_DOWN:  out.next_cat  = true; break;
            case DIR_LEFT:  out.prev_dest = true; break;
            case DIR_RIGHT: out.next_dest = true; break;
            case DIR_NONE:  break;
        }
    }
    out.directions = r3_edge;

    return out;
}

} // namespace GamepadNav
