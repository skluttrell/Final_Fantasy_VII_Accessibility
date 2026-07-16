/*
 * gamepad.h -- Right-analog-stick pathfinder input (v2.21).
 *
 * Supplements the keyboard pathfinder hotkeys (FieldNavThread in proxy.cpp)
 * with the right analog stick and stick-click (R3) of an XInput controller:
 *
 *   stick up    -> previous destination category   (like Shift+J / -)
 *   stick down  -> next destination category       (like Shift+L / =)
 *   stick left  -> previous destination            (like J / [)
 *   stick right -> next destination                (like L / ])
 *   R3 click    -> directions to the selection     (like \ / P)
 *
 * These are ALTERNATE TRIGGERS for existing browser actions, not new
 * functions — the key-parity rule (accessiblity_keys.txt) stays intact
 * because the destination-browser model is unchanged.
 *
 * WHY THE RIGHT STICK IS SAFE TO TAKE (verified 2026-07-15):
 *   - The vanilla FF7 engine has no analog support at all; analog input is
 *     a feature FFNx retrofits. FFNx reads the right stick ONLY in its
 *     camera code (ff7_use_analogue_controls), which is gated behind
 *     enable_analogue_controls — false by default and in our install.
 *   - The R3 CLICK is forwarded by FFNx to the game as gamepad button 12,
 *     but ff7input.cfg's joystick table only ever binds buttons 1-10
 *     (codes 0xEB-0xF4; verified in the live cfg AND the factory default),
 *     so the game ignores it. FFNx's own hardcoded R3 use (camera reset)
 *     sits behind the same disabled analog flag.
 *   - We only ever READ the pad via XInputGetState — a stateless, shared
 *     query. Nothing is captured, filtered, or injected, so no native
 *     control can be blocked by this module even in principle.
 *   - L3 is NOT free (FFNx toggles its "shortcut mode" on L3
 *     unconditionally — gamehacks.cpp) and must never be used here.
 */

#pragma once

namespace GamepadNav {

// Edge-detected pathfinder actions for one poll tick. At most one field is
// true per tick in practice (one stick direction + the click are physically
// possible together; the caller ORs these into its keyboard booleans, whose
// decode order resolves any overlap the same way it does for the keys).
struct Actions {
    bool prev_cat;      // stick up
    bool next_cat;      // stick down
    bool prev_dest;     // stick left
    bool next_dest;     // stick right
    bool directions;    // R3 click

    bool Any() const {
        return prev_cat || next_cat || prev_dest || next_dest || directions;
    }
};

// Poll the controller once. Call once per FieldNavThread tick (50ms).
//
// `active` mirrors the keyboard's focus gate: when false, the pad state is
// still tracked (so re-focusing cannot manufacture a stale edge from input
// that happened while unfocused) but all reported edges are suppressed.
//
// Cheap by construction: with a controller connected this is one
// XInputGetState call (~tens of microseconds); with none it is a 4-slot
// scan at most once every 3 seconds (see gamepad.cpp for why polling empty
// XInput slots every tick would be the one real efficiency trap).
Actions Poll(bool active);

// Forget held state (stick centered, R3 released). Called by the same
// early-out gates that memset the keyboard's was_down[] (pathfinder
// disabled, or not in normal field control) so both input paths resume
// from an identical "nothing held" baseline.
void Reset();

} // namespace GamepadNav
