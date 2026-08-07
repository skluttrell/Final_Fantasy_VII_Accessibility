/*
 * proxy.cpp -- version.dll proxy: 17 runtime stubs + background hook installer.
 *
 * WHY RUNTIME STUBS (not .def forwarding):
 *   .def forwarding "funcname = VERSION.funcname" requires VERSION.lib at link
 *   time, which makes the linker look for "VERSION" to verify the target.
 *   When our DLL IS named "version.dll", the OS resolves "VERSION" to us,
 *   creating an infinite forwarding loop. Runtime stubs bypass this entirely:
 *   we load the real System32 version.dll by its full absolute path and
 *   resolve each export directly via GetProcAddress.
 *
 * STUB MECHANISM (x86):
 *   Every forwarded function is a naked JMP through a stored function pointer:
 *
 *     __declspec(naked) void Foo() { __asm { jmp [fp_Foo] } }
 *
 *   MSVC generates:  FF 25 [&fp_Foo]  (indirect JMP through memory)
 *
 *   This works for both __stdcall (callee cleans stack with RET N) and __cdecl
 *   (caller cleans): the real function's prologue, body, and epilogue execute
 *   exactly as if our stub never existed.
 *
 * WHY #define VER_H BEFORE INCLUDES:
 *   windows.h unconditionally includes winver.h, which declares all 17 version
 *   API functions (GetFileVersionInfoA, VerQueryValueA, etc.). Our MAKE_STUB
 *   macro re-declares these as naked extern "C" functions with no parameters.
 *   MSVC C2733 fires when two extern "C" declarations of the same name have
 *   incompatible signatures, even across definition/declaration order.
 *
 *   winver.h uses #ifndef VER_H as its include guard (line 15). By defining
 *   VER_H before any include, winver.h's body is skipped for this translation
 *   unit. We need none of winver.h's declarations here â€” we never call these
 *   functions directly, only forward to them. All other windows.h content
 *   (HMODULE, GetSystemDirectoryA, CreateThread, etc.) is unaffected.
 *
 * BACKGROUND THREADS:
 *   Proxy::Init() spawns InitThread (a one-shot thread) that:
 *
 *     1. Sleep(200ms) â€” loader lock released, FFNx init safe.
 *     2. Config::Load() â€” parse ffvii_accessibility.cfg (no DLL loading).
 *     3. TTS::Init()   â€” LoadLibrary("Tolk.dll"); safe past the 200ms mark.
 *     4. Spawn TitleCursorThread â€” persistent thread for title screen cursor
 *        TTS. Must start before step 5 because the title screen appears before
 *        the field module loads (which is what Install() waits for).
 *     5. Loop: Hooks::Install() every 50ms until FF7's field module is ready
 *        AND FFNx's voice_init() has patched the opcode table.
 *     6. Exit.
 *
 *   All six polling threads (title, main menu, config, battle, wall-bump,
 *   name-entry) run until Proxy::Shutdown() signals g_cursor_stop_event (a
 *   shared manual-reset event). Each thread uses
 *   WaitForSingleObject(g_cursor_stop_event, <poll ms>) as its sleep; one
 *   SetEvent() wakes all of them within one poll interval on clean unload.
 *
 *   The 50ms poll is invisible to the player: FF7 takes several seconds to
 *   reach the first field map. Hooks::Install() is idempotent and fast
 *   (two VirtualProtect + DWORD writes) so repeated calls before success
 *   cause no side effects.
 *
 * VERSION.DLL EXPORTS (17, from dumpbin /exports C:\Windows\SysWOW64\version.dll):
 *   VerLanguageNameA and VerLanguageNameW are forwarded by the system
 *   version.dll to KERNEL32. GetProcAddress follows the forward chain
 *   automatically and returns the kernel32 function address, so our stubs
 *   redirect correctly without any special handling.
 */

// Suppress winver.h declarations BEFORE any include processes windows.h.
// See file-level comment above for the full explanation.
#define VER_H

#include "proxy.h"
#include "hooks.h"
#include "ff7_addresses.h"
#include "ff7_text.h"
#include "tts.h"
#include "config.h"
#include "log.h"
#include "tones.h"   // waveOut tone playback (v2.30.41) â€” replaces Beep()
#include "settings_menu.h" // F8 in-game audio-only settings menu (v2.30.42)
#include "gamepad.h" // right-analog-stick pathfinder input (v2.21)
#include "ff7_field_names.h" // generated maplist: field id -> internal name (v2.25)
#include "ff7_field_captions.h" // generated MPNAM harvest: field id -> friendly
                                // caption for UNVISITED places (v2.30.86)
#include "ff7_line_trigger_catalog.h" // generated: what each LINE trigger DOES
#include "ff7_field_graph.h"          // generated: gateway edges (journeys, v2.30.65)
#include "ff7_prop_catalog.h" // generated: talk-scripted model entities
                              // (device whitelist for MC_PROP, v2.30.45)
                                      // (exit/climb/OK/scene, v2.30.23)
#include <string>
#include <fstream>   // visited-places cache file IO (v2.25)
#include <cstring>   // memchr/memcmp/memcpy in the kernel2 section scanner
#include <cmath>     // atan2f/sqrtf/fmodf in the field pathfinder (v2.14)
#include <cwctype>   // iswdigit in the dev-label translator (v2.20)
#include <vector>    // walkmesh snapshot + A* state (v2.22 turn-by-turn)
#include <cfloat>    // FLT_MAX as the A* "unvisited" cost (v2.22)
#include <set>       // battle scene-message dedup by buffer_idx (v2.36)
#include <algorithm> // std::sort for the Places nearest-first list (v2.30.65)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlobj.h>   // SHGetFolderPathA - the 2013 Steam save location
                       // lives under (possibly OneDrive-redirected) Documents

// ---------------------------------------------------------------------------
// Complete export list for version.dll.
// Derived from: dumpbin /exports C:\Windows\SysWOW64\version.dll
// ---------------------------------------------------------------------------
#define VERSION_FORWARD_FUNCS(X) \
    X(GetFileVersionInfoA)       \
    X(GetFileVersionInfoByHandle)\
    X(GetFileVersionInfoExA)     \
    X(GetFileVersionInfoExW)     \
    X(GetFileVersionInfoSizeA)   \
    X(GetFileVersionInfoSizeExA) \
    X(GetFileVersionInfoSizeExW) \
    X(GetFileVersionInfoSizeW)   \
    X(GetFileVersionInfoW)       \
    X(VerFindFileA)              \
    X(VerFindFileW)              \
    X(VerInstallFileA)           \
    X(VerInstallFileW)           \
    X(VerLanguageNameA)          \
    X(VerLanguageNameW)          \
    X(VerQueryValueA)            \
    X(VerQueryValueW)

// ---------------------------------------------------------------------------
// Pass 1: One void* function pointer per forwarded function.
// Starts as nullptr; filled by GetProcAddress in Proxy::Init().
// ---------------------------------------------------------------------------
#define DECLARE_FP(name) static void* fp_##name = nullptr;
VERSION_FORWARD_FUNCS(DECLARE_FP)
#undef DECLARE_FP

// ---------------------------------------------------------------------------
// Pass 2: Naked stub bodies â€” one per forwarded function.
//
// Each generates FF 25 [&fp_name] (JMP DWORD PTR [abs_addr]).
// The call passes control to the real function with the exact same stack
// layout as a direct call. No prologue or epilogue needed.
//
// These work without parameter lists because we never touch the stack â€”
// the real function handles its own calling convention cleanup.
// ---------------------------------------------------------------------------
#define MAKE_STUB(name) \
    extern "C" void __declspec(naked) name() { __asm { jmp [fp_##name] } }
VERSION_FORWARD_FUNCS(MAKE_STUB)
#undef MAKE_STUB

// Shared manual-reset stop event for ALL polling threads (title, main menu,
// config, battle, wall-bump, name-entry). Each blocks on
// WaitForSingleObject(g_cursor_stop_event, <its poll ms>); one SetEvent() in
// Proxy::Shutdown() wakes all of them simultaneously.
// Written in InitThread before any CreateThread call; read in Shutdown().
// No lock needed: Shutdown() runs after InitThread exits (happens-before on
// the global state the game loop observes when the threads are live).
static HANDLE g_cursor_stop_event = nullptr;
static HANDLE g_title_thread      = nullptr;
static HANDLE g_menu_thread       = nullptr;
static HANDLE g_config_thread     = nullptr;
static HANDLE g_savemenu_thread   = nullptr;
static HANDLE g_itemmenu_thread   = nullptr;
static HANDLE g_ordermenu_thread  = nullptr;
static HANDLE g_statusmenu_thread = nullptr;
static HANDLE g_shopmenu_thread   = nullptr;
static HANDLE g_materiamenu_thread = nullptr;
static HANDLE g_equipmenu_thread  = nullptr;
static HANDLE g_limitmenu_thread  = nullptr;
static HANDLE g_magicmenu_thread  = nullptr;   // v2.30.48
static HANDLE g_gilkey_thread     = nullptr;
static HANDLE g_tutorial_thread   = nullptr;
static HANDLE g_timer_thread      = nullptr;
static HANDLE g_victory_thread    = nullptr;
static HANDLE g_battle_thread     = nullptr;
static HANDLE g_battlemsg_thread  = nullptr;

// v2.30.75: POSITIVE victory/menu discrimination. The post-battle VICTORY
// screens set MENU_OPEN=1 with every main-menu byte stale (the v2.8.3
// observation), which v2.35.1 countered with two cross-thread heuristics:
// a g_victory_active flag set by VictoryThread, plus a g_last_battle_tick
// 4-second battle-recency window. The 2026-08-03 menu_handoff_monitor log
// (one full battleâ†’victoryâ†’menu play-through, 30ms sampling) replaced
// both with the engine's own signal and proved the heuristics were holed:
//   - GAME_MODE (0xCC0D89) stays 2 (battle) through the ENTIRE victory
//     sequence while MENU_OPEN=1, and reads 9 for the whole real main-
//     menu family (rising ~0.5-1.2s BEFORE MENU_OPEN, dropping together
//     with it on close). Title and game-over prompts raise MENU_OPEN
//     with GAME_MODE=0. So:
//       MENU_OPEN==1 && GAME_MODE==2  =  the victory results window
//       MENU_OPEN==1 && GAME_MODE==9  =  the real main-menu family
//     No timing assumptions anywhere in the handoff.
//   - The old heuristics failed three ways: the tick was stamped only
//     while speak_battle was enabled (speak_battle=false left the menus
//     with no victory defense at all); a real menu open within 4s of
//     battle teardown was wrongly suppressed (log 12:01:00, open ~1.7s
//     after teardown, open-announce swallowed); and a slow battleâ†’
//     results transition (>4s) would have missed the whole window.
// Every menu-family thread now gates on GAME_MODE==GAME_MODE_MAIN_MENU
// and VictoryThread owns MENU_OPEN==1 && GAME_MODE==2 outright.
static HANDLE g_battlemenu_thread = nullptr;
static HANDLE g_wallbump_thread   = nullptr;
static HANDLE g_dialogtone_thread = nullptr;
static HANDLE g_fieldnav_thread   = nullptr;
static HANDLE g_settingsmenu_thread = nullptr;   // F8 menu (v2.30.42)
static HANDLE g_nameentry_thread  = nullptr;
static HANDLE g_gameover_thread   = nullptr;

// ---------------------------------------------------------------------------
// v2.30.37: game-over "title context" latch.
//
// THE PROBLEM (play report 2026-07-27, Screenshots/game_over/ + session log
// 10:02-10:03): after a party wipe the engine shows the GAME OVER film reel
// and then returns to the title screen's NEW GAME / Continue prompt â€” but it
// NEVER clears the field state. FIELD_ID stays at the dead field (145 in the
// log) through the reel, the prompt, and the save-select screen. Every
// "which world am I in" test in this file assumed FIELD_ID==0 means title
// and FIELD_ID!=0 means gameplay, so the whole title path inverted:
//   - TitleCursorThread (gate: FIELD_ID==0) stayed SILENT on the prompt;
//   - MenuCursorThread (gate: FIELD_ID!=0) saw the prompt's MENU_OPEN=1 and
//     spoke the STALE quit cursor ("Yes") and menu row ("Item") over a
//     screen that actually says NEW GAME / Continue;
//   - SaveMenuThread's LOAD mode (gate: FIELD_ID==0) would have been silent
//     had the player continued into the save grid.
// A blind player heard "Cloud is down", then 40s of silence, then "Yes...
// Item" â€” with no way to know the run had ended.
//
// THE SIGNAL: GAME_MODE (0xCC0D89) blips to 26 for ~60ms at the battleâ†’
// game-over handoff (the only positive in-memory evidence; the reel itself
// reads as frozen field play â€” see GAME_MODE_GAMEOVER in ff7_addresses.h).
// GameOverWatchThread polls at 30ms, latches here, and speaks "Game over."
//
// LATCH SEMANTICS: nonzero = "the field state is a corpse; we are in the
// title sequence even though FIELD_ID says otherwise". Consumers:
//   - TitleCursorThread treats the latch as title context (with an extra
//     MENU_OPEN==1 requirement so the reel's stale cursor byte stays quiet);
//   - every main-menu-family thread stands down (the v2.30.32 rule: stale
//     main-menu bytes must never narrate a foreign screen);
//   - SaveMenuThread's LOAD mode accepts the latch as title context;
//   - the wall-bump and field-navigation threads stand down (the frozen
//     field passes all their byte gates);
//   - the G key treats the game as not loaded (the dead run's gil is gone).
//
// CLEARING: the observed reload sequence is reel (MENU_OPEN=0) â†’ prompt
// (MENU_OPEN=1, held through save-select â€” boot log 09:57:12â†’09:57:36) â†’
// load commit (MENU_OPENâ†’0, field alive). So: once MENU_OPEN=1 has been
// seen while latched, the next MENU_OPEN==0 clears the latch. Safety net:
// FIELD_ID changing to a DIFFERENT nonzero value also clears (a new field
// definitely loaded; covers any path that skips the prompt).
//
// Plain aligned 32-bit stores/loads; benign racing (x86 atomicity).
// ---------------------------------------------------------------------------
static volatile LONG g_game_over_latch = 0;

// True while the post-game-over title sequence owns the screen. See the
// latch comment above for what every consumer must do about it.
static bool GameOverTitleContext()
{
    return g_game_over_latch != 0;
}

// ---------------------------------------------------------------------------
// Sound sub-menu volume cache.
//
// Written by HookDotemuRegSetValueExA (called on FF7's thread when the player
// presses Left/Right in the Sound sub-menu); read by ConfigMenuThread to
// include the volume in Up/Down cursor-navigation announcements.
//
// 0xFF = not yet seen from a live slider press.  When unknown, ConfigMenuThread
// omits the volume from the navigation announce (just "Music volume" / "FX
// volume") so TTS never speaks a stale or fabricated number.
//
// uint8_t reads/writes are atomically word-teared on x86, so no lock is
// needed for this best-effort UI-hint purpose.  volatile prevents the compiler
// from caching the value in a register across the two threads.
// ---------------------------------------------------------------------------
static volatile uint8_t g_sound_music_vol = 0xFF;
static volatile uint8_t g_sound_fx_vol    = 0xFF;

// IAT hook plumbing for AF3DN.P:dotemuRegSetValueExA.
// g_iat_dotemu_entry is saved so Proxy::Shutdown() can restore the original
// pointer without re-walking the import table.
typedef LONG (WINAPI *RegSetExA_fn)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
static RegSetExA_fn      g_orig_dotemu_regset = nullptr;
static IMAGE_THUNK_DATA* g_iat_dotemu_entry   = nullptr;

// ---------------------------------------------------------------------------
// dotemuRegSetValueExA IAT hook â€” Sound sub-menu Left/Right value TTS.
//
// FF7 (2013 Steam) calls AF3DN.P:dotemuRegSetValueExA instead of the real
// Win32 RegSetValueExA for all registry writes (AF3DN.P is the DotEmu/FFNx
// proxy that intercepts these calls).  FF7 imports this function statically,
// so its IAT entry can be patched to reroute through our handler.
//
// WHEN IT SPEAKS:
//   Only when MENU_OPEN is set AND CONFIG_ROW==1 (the Sound row in the Config
//   sub-menu is active).  This is the case when the player is inside the Sound
//   sub-menu pressing Left/Right.  All other registry writes (startup, save,
//   etc.) have MENU_OPEN=0 or CONFIG_ROWâ‰ 1 and are forwarded silently.
//
// VALUE CACHING:
//   Updates g_sound_music_vol / g_sound_fx_vol on every matching call so
//   ConfigMenuThread can include the volume in Up/Down cursor announces.
//
// REGISTRY KEY NAMES:
//   "MusicVolume" â€” music volume slider (byte 0=silence, 127=maximum)
//   "SFXVolume"   â€” FX volume slider    (same scale)
//   Exact names from the classic FF7 registry layout under
//   HKLM\SOFTWARE\Square Soft, Inc\Final Fantasy VII\1.00\.
// ---------------------------------------------------------------------------
static LONG WINAPI HookDotemuRegSetValueExA(
    HKEY        hKey,
    LPCSTR      lpValueName,
    DWORD       Reserved,
    DWORD       dwType,
    const BYTE* lpData,
    DWORD       cbData)
{
    if (lpValueName && lpData && cbData >= 1 && Config::Get().speak_menus) {
        const uint8_t menu_open  =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        const uint8_t config_row =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_ROW);

        if (menu_open && config_row == 1) {
            const uint8_t vol = lpData[0];
            const bool is_music = (strcmp(lpValueName, "MusicVolume") == 0);
            const bool is_fx    = (!is_music && strcmp(lpValueName, "SFXVolume") == 0);

            if (is_music || is_fx) {
                if (is_music) g_sound_music_vol = vol;
                else          g_sound_fx_vol    = vol;

                wchar_t buf[16];
                _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%u", vol);

                char dbg[80];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] SOUND %s vol=%u",
                    is_music ? "Music" : "FX", vol);
                Log::Write(dbg);
                TTS::Speak(buf, /*interrupt=*/true);
            }
        }
    }
    return g_orig_dotemu_regset(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

// ---------------------------------------------------------------------------
// SetupSoundIATHook â€” patch FF7's IAT to intercept dotemuRegSetValueExA.
//
// Walks the IMAGE_IMPORT_DESCRIPTOR table of ff7_en.exe, locates the
// AF3DN.P section, then finds the IAT slot for dotemuRegSetValueExA and
// replaces its function pointer with HookDotemuRegSetValueExA.
//
// Saves the original pointer in g_orig_dotemu_regset and the IAT entry
// address in g_iat_dotemu_entry so Proxy::Shutdown() can restore it.
//
// Called once from InitThread after TTS::Init() (Log and TTS must be ready
// because the hook itself calls both).  Must run after DllMain returns (no
// loader lock) but before the player can enter the Sound sub-menu.
// ---------------------------------------------------------------------------
static void SetupSoundIATHook()
{
    HMODULE exe = GetModuleHandleA("ff7_en.exe");
    if (!exe) {
        Log::Write("[FF7Access] IAT hook: ff7_en.exe module not found");
        return;
    }

    const BYTE* base = reinterpret_cast<const BYTE*>(exe);
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const IMAGE_NT_HEADERS* nt  =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY& dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) {
        Log::Write("[FF7Access] IAT hook: import directory not found");
        return;
    }

    const IMAGE_IMPORT_DESCRIPTOR* desc =
        reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);

    for (; desc->Name; ++desc) {
        const char* dll_name =
            reinterpret_cast<const char*>(base + desc->Name);
        if (_stricmp(dll_name, "AF3DN.P") != 0) continue;

        // Some PE tools (packers, bound-import writers) zero OriginalFirstThunk
        // and keep only FirstThunk (the IAT).  Without the INT we cannot match
        // by name â€” FirstThunk holds runtime addresses, not IMAGE_IMPORT_BY_NAME
        // pointers.  Bail out cleanly rather than walking the MZ header.
        if (!desc->OriginalFirstThunk) {
            Log::Write("[FF7Access] IAT hook: AF3DN.P has no INT "
                       "(OriginalFirstThunk==0), cannot match by name");
            return;
        }

        const IMAGE_THUNK_DATA* orig =
            reinterpret_cast<const IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA* thunk =
            reinterpret_cast<IMAGE_THUNK_DATA*>(const_cast<BYTE*>(base) + desc->FirstThunk);

        for (; orig->u1.AddressOfData; ++orig, ++thunk) {
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;

            const IMAGE_IMPORT_BY_NAME* by_name =
                reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                    base + orig->u1.AddressOfData);
            if (strcmp(reinterpret_cast<const char*>(by_name->Name),
                       "dotemuRegSetValueExA") != 0) continue;

            g_orig_dotemu_regset = reinterpret_cast<RegSetExA_fn>(thunk->u1.Function);
            g_iat_dotemu_entry   = thunk;

            DWORD old_protect;
            if (!VirtualProtect(thunk, sizeof(ULONG_PTR), PAGE_READWRITE, &old_protect)) {
                Log::Write("[FF7Access] IAT hook: VirtualProtect failed, skipping patch");
                g_orig_dotemu_regset = nullptr;
                g_iat_dotemu_entry   = nullptr;
                return;
            }
            thunk->u1.Function = reinterpret_cast<ULONG_PTR>(HookDotemuRegSetValueExA);
            VirtualProtect(thunk, sizeof(ULONG_PTR), old_protect, &old_protect);

            Log::Write("[FF7Access] IAT hook: dotemuRegSetValueExA patched");
            return;
        }

        // Found AF3DN.P in the import table but dotemuRegSetValueExA was not
        // in its name list.  Either it is imported by ordinal (unlikely) or
        // the function name differs between FFNx versions.
        Log::Write("[FF7Access] IAT hook: AF3DN.P found but dotemuRegSetValueExA not listed");
        return;
    }

    Log::Write("[FF7Access] IAT hook: AF3DN.P not in ff7_en.exe import table");
}

// ---------------------------------------------------------------------------
// Title screen cursor polling thread.
//
// Polls FF7Addr::TITLE_CURSOR (0x00DD6F24) and speaks "Continue" (value=1)
// or "New Game" (value=0) whenever the byte changes to a valid cursor value.
// Uses WaitForSingleObject(g_cursor_stop_event, 150) as its sleep so that
// Proxy::Shutdown() can wake and join it within 150ms on clean unload.
//
// WHY A SEPARATE PERSISTENT THREAD:
//   The title screen appears BEFORE the field module loads, so Hooks::Install()
//   has not yet succeeded when the player first sees it. This thread starts
//   immediately after TTS::Init() so the initial title screen is covered,
//   as well as any return (e.g., after a Game Over).
//
// FIELD_ID GATE:
//   FF7Addr::FIELD_ID (0xCC15D0) is non-zero while in a named field map and
//   zero during the title screen, world map, and battle. When non-zero, the
//   player cannot be on the title screen, so we reset the sentinel to 0xFF.
//   This ensures that after field gameplay ends and the title screen re-appears,
//   the first valid cursor position is always announced â€” regardless of what
//   value the BSS byte held during field mode.
//
// last_cursor SENTINEL UPDATE RULE:
//   last_cursor is updated ONLY inside the announce branches (values 0 and 1).
//   Non-0/1 BSS values (from other modules writing into the 0xDD segment) must
//   not advance the sentinel. If they did, a silent field-mode write of 0 or 1
//   could pin last_cursor, silencing the announcement when the title screen
//   later shows the same cursor position.
//
// SPLASH FALSE-ANNOUNCE â€” FIXED v2.30.38 (was "KNOWN LIMITATION"):
//   Windows zero-initializes the 0xDD BSS segment, so TITLE_CURSOR reads 0
//   (= New Game) during the company logo splash with FIELD_ID also 0 â€” the
//   thread used to announce "New Game" ~350ms into the splash and then stay
//   silent when the real title menu appeared (same value, change-check).
//   The old comment claimed "there is no in-process signal that
//   distinguishes splash from title screen" â€” static disasm (2026-07-27)
//   found it: TITLE_STATE (0xDD74E0), the title module's own lifecycle
//   dword, is 1 exactly while the menu is on screen and interactive (full
//   state machine at its declaration in ff7_addresses.h). The thread now
//   announces only at TITLE_STATE==1, which both kills the splash announce
//   AND lands the first announce at the moment the menu fades in â€” with a
//   "Title screen." orientation prefix on every fresh title entry (boot,
//   post-game-over, quit-to-title all re-cycle the state through 0 -> 1).
//
// Gated by Config::Get().speak_menus.
// ---------------------------------------------------------------------------
static DWORD WINAPI TitleCursorThread(LPVOID /*unused*/)
{
    uint8_t last_cursor = 0xFF;  // 0xFF = sentinel; triggers announce on first valid read
    // v2.30.38: last observed TITLE_STATE, logged on change while in title
    // context (debug builds) â€” the state machine is disasm-derived, so its
    // first few launch logs double as the live verification pass.
    int32_t last_tstate = INT32_MIN;

    for (;;) {
        // Sleep 150ms, or wake immediately if Proxy::Shutdown() signals us.
        if (WaitForSingleObject(g_cursor_stop_event, 150) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_menus) {
            last_cursor = 0xFF;
            continue;
        }

        // FIELD_ID is non-zero while in a named field map. When non-zero the
        // player is not on the title screen: reset the sentinel and skip.
        // Safe dereference: 0xCC15D0 is in the statically-allocated game BSS.
        //
        // v2.30.37: EXCEPT after a game over â€” the engine returns to the
        // title prompt with FIELD_ID still STALE at the dead field (play
        // report 2026-07-27: the prompt was completely silent). The latch
        // says "this IS title context despite FIELD_ID".
        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        if (field_id != 0 && !GameOverTitleContext()) {
            last_cursor = 0xFF;
            continue;
        }

        // v2.30.38: the title module's own lifecycle state (0xDD74E0) is the
        // authoritative "menu on screen" test â€” 1 only while the NEW GAME/
        // Continue prompt (or its Continue save-grid subscreen) is displayed
        // and interactive. Anything else means splash/logo movies (0, the
        // BSS boot value â€” the module hasn't run), the backdrop still fading
        // in (0), a choice fading out (2), or the module exited (-1, stale
        // through gameplay). This replaces v2.30.37's MENU_OPEN==1 check in
        // the game-over path (MENU_OPEN was a proxy observed once; this is
        // the disasm-proven source) and finally closes the launch-splash
        // false "New Game" (the old FIELD_ID==0-only gate). Transition log
        // doubles as the live verification of the disasm-derived semantics.
        const int32_t tstate =
            *reinterpret_cast<const volatile int32_t*>(FF7Addr::TITLE_STATE);
        if (tstate != last_tstate) {
            last_tstate = tstate;
            char dbg[64];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] TITLE state=%ld", static_cast<long>(tstate));
            Log::Write(dbg);
        }
        if (tstate != FF7Addr::TITLE_STATE_INTERACTIVE) {
            last_cursor = 0xFF;
            continue;
        }

        // Safe dereference: 0x00DD6F24 is in the statically-allocated game BSS.
        const uint8_t curr =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::TITLE_CURSOR);

        if (curr == last_cursor) continue;

        // v2.30.38 (generalizing v2.30.37's game-over prefix): the FIRST
        // announce of every title session says "Title screen." â€” at boot the
        // menu has just faded in after silent logo movies, after a game over
        // the player last heard "Game over." 40s of film reel ago, and after
        // a quit the context also changed screens. last_cursor is still the
        // 0xFF sentinel exactly at that first valid read, so later cursor
        // moves in the same session stay terse.
        const bool orient = last_cursor == 0xFF;

        // Update last_cursor only for values we announce, so non-0/1 BSS values
        // cannot pin the sentinel and cause a false negative on title re-entry.
        if (curr == 1) {
            last_cursor = curr;
            Log::Write("[FF7Access] TITLE cursor=1 (Continue)");
            TTS::Speak(orient ? L"Title screen. Continue" : L"Continue",
                       /*interrupt=*/true);
        } else if (curr == 0) {
            last_cursor = curr;
            Log::Write("[FF7Access] TITLE cursor=0 (New Game)");
            TTS::Speak(orient ? L"Title screen. New Game" : L"New Game",
                       /*interrupt=*/true);
        }
        // Other values are BSS data from unrelated modules â€” do not announce
        // and do not update last_cursor.
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Game-over watch thread (v2.30.37).
//
// Sets/clears g_game_over_latch (full rationale at its declaration). Runs at
// 30ms â€” faster than every other poll loop in this file â€” because the ONLY
// positive game-over signal is GAME_MODE holding 26 for ~60ms (one observed
// sample; a 30ms poll gives two chances at the observed width, but the true
// minimum width is unknown â€” if a log ever shows a wipe with no "GAMEOVER"
// line, this poll missed the blip and a second trigger is needed).
//
// The thread always runs regardless of speech config: the latch's job is
// mostly SUPPRESSION (keeping stale-menu narration off a title screen), and
// that correctness must not depend on which speech families are enabled.
// Only the "Game over." announcement itself is config-gated (speak_menus â€”
// the same family that owns the title screen narration this latch hands
// off to).
//
// interrupt=false on the announce: a party wipe fires the battle defeat
// announce ("Cloud is down") ~5s before the mode blip in the observed log,
// but TTS may still be speaking it in slower configs â€” queueing preserves
// the causal order (downed â†’ game over) instead of eating the cause.
// ---------------------------------------------------------------------------
static DWORD WINAPI GameOverWatchThread(LPVOID /*unused*/)
{
    // MENU_OPEN==1 seen since the latch set â€” arms the "prompt closed â‡’
    // game is reloading" clear. Reset at every latch set.
    bool prompt_seen = false;
    // FIELD_ID captured at latch time (the dead field). A DIFFERENT nonzero
    // value later means a new field really loaded â€” the safety-net clear.
    int16_t dead_field_id = 0;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 30) == WAIT_OBJECT_0)
            break;

        const uint8_t mode =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE);

        if (g_game_over_latch == 0) {
            if (mode == FF7Addr::GAME_MODE_GAMEOVER) {
                prompt_seen   = false;
                dead_field_id = *reinterpret_cast<const volatile int16_t*>(
                    FF7Addr::FIELD_ID);
                g_game_over_latch = 1;
                char dbg[96];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] GAMEOVER: mode=26 observed (dead field=%d) "
                    "â€” title-context latch set", static_cast<int>(dead_field_id));
                Log::Write(dbg);
                if (Config::Get().speak_menus)
                    TTS::Speak(L"Game over.", /*interrupt=*/false);
            }
            continue;
        }

        // â”€â”€ Latched: watch for the game coming back to life â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        // v2.30.38: TITLE_STATE==1 (the title module's own "menu is up"
        // dword, disasm-proven â€” see ff7_addresses.h) joins MENU_OPEN as a
        // prompt-up signal. MENU_OPEN=1 was observed at the prompt exactly
        // once (10:03:03 log); if some path never raises it, the latch
        // would have deadlocked open. TITLE_STATE is authoritative, and the
        // clear now also requires it to have LEFT 1 (title fading out or
        // exited), so a menu-byte flicker while the prompt is still up
        // cannot clear the latch early.
        const int32_t tstate =
            *reinterpret_cast<const volatile int32_t*>(FF7Addr::TITLE_STATE);

        if (menu_open == 1 || tstate == FF7Addr::TITLE_STATE_INTERACTIVE) {
            if (!prompt_seen) {
                prompt_seen = true;
                Log::Write("[FF7Access] GAMEOVER: title prompt up "
                           "(menu/title-state) â€” latch clears when it ends");
            }
            continue;
        }

        const bool prompt_closed = prompt_seen;  // menu==0 AND tstate!=1 here
        const bool new_field     = field_id != 0 && field_id != dead_field_id;
        if (prompt_closed || new_field) {
            g_game_over_latch = 0;
            prompt_seen       = false;
            Log::Write(prompt_closed
                ? "[FF7Access] GAMEOVER: title menu closed â€” latch cleared "
                  "(game reloading)"
                : "[FF7Access] GAMEOVER: new field id â€” latch cleared "
                  "(safety net)");
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Main-menu cursor polling thread.
//
// Polls FF7Addr::MENU_CURSOR (0x00CC1B42) and announces the highlighted
// main-menu option by name whenever the cursor moves.
//
// CURSOR INDEX â†’ OPTION NAME (v2.31.1, player-corrected 2026-07-18):
//   0=Item  1=Magic  2=Materia  3=Equip  4=Status  5=Order  6=Limit
//   7=Config  8=PHS  9=Save  10=Quit
// The original 2026-07-01 table was built before the player could compare
// rows in game and OMITTED Materia â€” everything from Equip down was one
// row early ("equip, status, order and limit all need to move down 1; the
// selection directly under magic is not available yet" = the grayed
// Materia row). The shift also resolves both old "unlockable, identity
// TBD" slots: 6 is just Limit, 8 is PHS (grayed until the story grants
// it). Config=7 and Save=9 were correct in both tables â€” which is why the
// v2.29 save-mode gate (MENU_CURSOR==9) never misfired.
// Address confirmed via ff7_menu_cursor_poll.py (2026-07-01).
//
// FIELD_ID GATE:
//   The main menu can only be opened from a field map. FIELD_ID (0xCC15D0)
//   is non-zero while in a named field map and zero elsewhere (title screen,
//   world map, battle). When FIELD_ID == 0 the player cannot be in the main
//   menu, so we reset the sentinel and skip. This prevents the thread from
//   reacting to the cursor byte's retained value during non-field game states.
//
// CHANGE-ONLY DETECTION:
//   MENU_CURSOR retains its last value when the menu closes, so we only
//   speak on value-change â€” not on menu-open. The player can press a
//   direction to hear their current position if they re-open at the same row.
//   A "menu is open" flag (to re-announce on open) was not found during
//   investigation; locating it is noted as future work.
//
// UNKNOWN SLOTS 7â€“8:
//   These cursor indices exist but correspond to menu options not yet
//   unlocked in the game (likely PHS and one other). The thread skips them
//   silently and logs a diagnostic. Update kMenuLabels[] when confirmed.
//
// Gated by Config::Get().speak_menus.
// ---------------------------------------------------------------------------
// v2.30.32: TRUE while the menu module is running a top-level screen that
// is NOT the main-menu family â€” name entry (GAME_MODE 6), PHS (7), shop
// (8). All three raise MENU_OPEN while every main-menu byte (MENU_CURSOR,
// the dispatch index, FOCUS_MODE, the save-mode frozen-row signature)
// stays STALE at its last value, so every thread keyed on those bytes
// must stand down or it narrates a menu that is not on screen. Play-
// proven twice: the naming screen's false "Item" (v2.8.3) and the shop's
// false "Save" (2026-07-26 report â€” MENU_CURSOR was parked on row 9 from
// the player's last save, and the shop's MENU_OPEN let the row announce
// talk over the shop greeting).
static bool MenuModuleForeignScreen()
{
    const uint8_t m =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE);
    return m == FF7Addr::GAME_MODE_NAME_ENTRY ||
           m == FF7Addr::GAME_MODE_PHS ||
           m == FF7Addr::GAME_MODE_SHOP;
}

static DWORD WINAPI MenuCursorThread(LPVOID /*unused*/)
{
    // Map cursor index â†’ spoken label. nullptr entries are unlockable options
    // whose names are not yet confirmed; they are logged but not spoken.
    static const wchar_t* const kMenuLabels[] = {
        L"Item",     // 0
        L"Magic",    // 1
        L"Materia",  // 2 â€” grayed until the story grants materia
        L"Equip",    // 3
        L"Status",   // 4
        L"Order",    // 5
        L"Limit",    // 6
        L"Config",   // 7
        L"P H S",    // 8 â€” spaced so TTS spells the letters; grayed until granted
        L"Save",     // 9
        L"Quit",     // 10
    };
    static const uint8_t kMenuMax = 10;   // highest valid main-menu index

    // Quit confirmation dialog: 0=Yes  1=No  (No is the default on open).
    static const wchar_t* const kQuitLabels[] = { L"Yes", L"No" };
    static const uint8_t kQuitMax = 1;

    uint8_t last_cursor      = 0xFF;  // main-menu cursor; 0xFF = none announced
    uint8_t last_menu_open   = 0;
    uint8_t last_quit_cursor = 0xFF;  // quit-dialog cursor; 0xFF = reset, seed
                                      // next valid read silently; 0xFE = saw
                                      // garbage, next valid read speaks
                                      // (dialog init) â€” see v2.30.40 note
    // Counts consecutive polls where MENU_OPEN=1. We require at least 2 before
    // treating MENU_OPEN as a real menu open. This prevents a single stale
    // MENU_OPEN=1 poll (the title-screen overlay briefly persisting into the
    // first field-load poll) from triggering the re-announce logic and
    // announcing "Item" (MENU_CURSOR BSS default = 0) before the player has
    // done anything.
    uint8_t menu_open_streak = 0;
    // v2.30.68: menu-OPEN cursor settle gate. The menu module briefly
    // writes row 0 during init before restoring the remembered row --
    // the 2026-08-02 log shows "cursor=0 (Item)" then "cursor=10 (Quit)"
    // 0.8s apart on one open with no input (player report: wrong
    // selections spoken after a battle). The open announce now waits for
    // the byte to hold still for 2 consecutive polls (~100ms, inaudible)
    // before speaking; navigation announces afterwards are unchanged.
    uint8_t menu_open_settle = 0;    // >0 = settling; counts down on match
    uint8_t menu_settle_prev = 0xFF;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 150) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_menus) {
            last_cursor      = 0xFF;
            last_menu_open   = 0;
            last_quit_cursor = 0xFF;
            menu_open_streak = 0;
            continue;
        }

        // FIELD_ID is non-zero only in named field maps. It is 0 on the title
        // screen, world map, and during battle. MENU_OPEN is set by the title
        // screen overlay too, so without this gate MenuCursorThread would
        // announce "Item" (MENU_CURSOR BSS default = 0) on the title screen.
        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        if (field_id == 0) {
            last_cursor      = 0xFF;
            last_menu_open   = 0;
            last_quit_cursor = 0xFF;
            menu_open_streak = 0;
            continue;
        }

        // The NAMING SCREEN also sets MENU_OPEN=1 while FIELD_ID stays
        // non-zero (player-reported 2026-07-12: a false "Item" announce â€”
        // MENU_CURSOR's stale value â€” talked over NameEntryThread's own
        // screen-open announcement). v2.30.32 widened the same stand-down
        // to the shop and PHS screens after the shop's false "Save"
        // (MenuModuleForeignScreen â€” the exclusion list stays narrow and
        // live-evidenced rather than requiring GAME_MODE==9, because
        // other MENU_OPEN contexts haven't been mode-sampled).
        if (MenuModuleForeignScreen()) {
            last_cursor      = 0xFF;
            last_menu_open   = 0;
            last_quit_cursor = 0xFF;
            menu_open_streak = 0;
            continue;
        }

        // v2.30.37: post-game-over title sequence. FIELD_ID is STALE nonzero
        // (so the gate above let us through) and the title prompt raises
        // MENU_OPEN=1 â€” exactly the combination that made this thread speak
        // the stale quit cursor ("Yes") and menu row ("Item") over the
        // NEW GAME / Continue prompt (2026-07-27 log, 10:03:03). Same
        // stale-bytes situation as a foreign menu screen: stand down.
        if (GameOverTitleContext()) {
            last_cursor      = 0xFF;
            last_menu_open   = 0;
            last_quit_cursor = 0xFF;
            menu_open_streak = 0;
            continue;
        }

        // â”€â”€ Main menu â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);

        if (menu_open == 0) {
            // v2.30.27: the menu closing ends any running tutorial â€”
            // clear the flag and cut whatever narration is still queued
            // (the player has moved on; finishing the lesson into the
            // field would talk over gameplay).
            // v2.30.36: only a genuine open->closed EDGE counts
            // (last_menu_open != 0 â€” set at the bottom of the open path,
            // so it is nonzero here exactly when the previous poll saw
            // the menu open). TUTOR fires on the FIELD side a beat
            // before the menu module opens â€” the request gap the latch
            // comment in hooks.cpp explicitly says it must cover â€” and
            // this branch also runs during that gap: the old
            // level-triggered clear killed the suppression before the
            // menu ever opened (cursor-sweep chatter over the lesson)
            // and cut in-flight speech with a spurious Silence().
            if (Hooks::TutorialActive() && last_menu_open != 0) {
                Hooks::ClearTutorialActive();
                TTS::Silence();
                Log::Write("[FF7Access] TUTOR: menu closed, tutorial "
                           "narration cut, announcements resume.");
            }
            last_cursor      = 0xFF;
            last_menu_open   = 0;
            last_quit_cursor = 0xFF;
            menu_open_streak = 0;
            continue;
        }

        // Require MENU_OPEN=1 for 2 consecutive polls before treating this as
        // a real menu open. A stale title-screen or post-battle MENU_OPEN=1
        // clears after one poll, so it never reaches streak >= 2.
        menu_open_streak++;
        if (menu_open_streak < 2) continue;

        // On the 0â†’1 transition of MENU_OPEN, arm the settle gate
        // (v2.30.68) instead of the old immediate last_cursor=0xFF: the
        // open announce fires once the cursor byte has held still for 2
        // consecutive polls, so the module's transient init row (0) can
        // never speak ahead of the remembered row.
        // This fires on the 2nd consecutive poll of MENU_OPEN=1, when
        // last_menu_open is still 0 from the previous menu-close reset.
        if (last_menu_open == 0) {
            menu_open_settle = 1;
            menu_settle_prev = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::MENU_CURSOR);
        }
        last_menu_open = menu_open;

        // v2.30.75: MENU_OPEN=1 alone does not mean "the main menu" â€” the
        // victory results screens raise it while GAME_MODE stays 2, and
        // the title/game-over prompts raise it with GAME_MODE 0 (2026-08-03
        // handoff log). Only GAME_MODE==9 is the main-menu family; anything
        // else with the menu byte up is a foreign overlay whose stale
        // main-menu bytes must not narrate (this replaces the v2.35.1
        // g_victory_active flag + 4-second battle-recency window â€” see the
        // header comment at the old globals' site). Seed silently so
        // nothing stale fires when the real menu opens later.
        if (*reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE) !=
                FF7Addr::GAME_MODE_MAIN_MENU) {
            last_cursor = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::MENU_CURSOR);
            last_quit_cursor = 0xFF;
            continue;
        }

        // v2.30.27: a menu TUTORIAL is running â€” the script drives the
        // cursor, and hook_tutor has already queued the lesson text.
        // Track state silently (so nothing stale fires when the
        // tutorial ends) but announce nothing over the narration.
        if (Hooks::TutorialActive()) {
            last_cursor = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::MENU_CURSOR);
            last_quit_cursor = 0xFF;
            continue;
        }

        // â”€â”€ Quit confirmation cursor (runs in parallel, no priority block) â”€â”€
        // QUIT_CURSOR tracks Yes (0) / No (1) while the Quit dialog is visible.
        // We intentionally do NOT gate this on a QUIT_OPEN flag: the initial
        // candidate (0x00DC0FB1) did not reliably return to 0 when the dialog
        // was dismissed with No, which caused the main menu to stop announcing.
        // Tracking QUIT_CURSOR in parallel here â€” without any continue â€” keeps
        // the main menu cursor logic running at all times.
        //
        // v2.30.40: the byte is STALE between quit dialogs, and every reset
        // above re-arms last_quit_cursor to 0xFF â€” so the first poll of a
        // fresh menu open treated the leftover value as a player move and
        // spoke "Yes" over the menu-open announce whenever the stale byte
        // happened to be <= kQuitMax (2026-07-27 12:17 launch log: "QUIT
        // cursor=0 (Yes)" at the same instant as "MENU cursor=0 (Item)";
        // the same stale speak the game-over prompt heard pre-v2.30.37).
        // Fix = the v2.30.13 baseline-suppression pattern, with two sentinel
        // states so the REAL dialog-open announce survives:
        //   0xFF  "just reset"      -> first valid read is the pre-open
        //                             stale byte: seed silently.
        //   0xFE  "saw out-of-range" -> the byte was garbage while we
        //                             watched; a garbage->valid transition
        //                             is the quit dialog WRITING its initial
        //                             cursor â€” that one must speak (it was
        //                             the old else-branch's behavior too).
        // Yes<->No moves inside a live dialog are plain valid->valid
        // changes and speak exactly as before.
        const uint8_t qcurr =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::QUIT_CURSOR);
        if (qcurr != last_quit_cursor) {
            if (qcurr <= kQuitMax) {
                const bool seed = (last_quit_cursor == 0xFF);
                last_quit_cursor = qcurr;
                char qdbg[80];
                _snprintf_s(qdbg, sizeof(qdbg), _TRUNCATE,
                    "[FF7Access] QUIT cursor=%u (%ls)%s", qcurr,
                    kQuitLabels[qcurr], seed ? " seeded" : "");
                Log::Write(qdbg);
                if (!seed)
                    TTS::Speak(kQuitLabels[qcurr], /*interrupt=*/true);
            } else {
                last_quit_cursor = 0xFE;
            }
        }

        // â”€â”€ Main menu cursor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        const uint8_t curr =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_CURSOR);

        // v2.30.68 settle gate: silent until the byte repeats across two
        // polls, then release with last_cursor=0xFF so the stable row
        // announces exactly once (the normal open announce, just ~100ms
        // later than before).
        if (menu_open_settle > 0) {
            if (curr == menu_settle_prev) {
                if (--menu_open_settle == 0)
                    last_cursor = 0xFF;
            } else {
                menu_settle_prev = curr;
                menu_open_settle = 1;
            }
            if (menu_open_settle > 0)
                continue;
        }

        if (curr == last_cursor) continue;

        if (curr > kMenuMax) {
            last_cursor = 0xFF;
            continue;
        }

        last_cursor = curr;

        const wchar_t* label = kMenuLabels[curr];
        if (!label) {
            char dbg[80];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] MENU cursor=%u (unlockable slot, no label)", curr);
            Log::Write(dbg);
            continue;
        }

        // v2.30.78: mirror the game's OWN activation test, both halves.
        // The confirm path (disasm 0x6CA4AB..0x6CA4E7) refuses a row
        // unless its MENU_VISIBLE_ROWS bit is SET and its
        // MENU_DISABLED_ROWS bit is CLEAR, in that order, before the row
        // jump table.  v2.32 read only the disabled mask â€” but the
        // early-game Materia/PHS story lock lives in the VISIBLE mask
        // (savemap+0xBC0 = 0x02FB pre-hideout, locking mask all-zero),
        // so Materia never spoke ", not available" (user report
        // 2026-08-04).  Reading the engine's two dispatch words â€” not
        // re-deriving from the savemap â€” keeps parity by construction:
        // the Quit force-bit, the Quit never-locks bit, and the
        // savemap+0xE13 Item/Limit script fold are already applied by
        // the game's per-frame mask build at 0x6CA38C.
        const uint16_t visible_rows =
            *reinterpret_cast<const volatile uint16_t*>(FF7Addr::MENU_VISIBLE_ROWS);
        const uint16_t disabled_rows =
            *reinterpret_cast<const volatile uint16_t*>(FF7Addr::MENU_DISABLED_ROWS);
        const bool row_disabled = ((disabled_rows >> curr) & 1u) != 0 ||
                                  ((visible_rows  >> curr) & 1u) == 0;

        wchar_t line[64];
        _snwprintf_s(line, _countof(line), _TRUNCATE, L"%ls%ls",
                     label, row_disabled ? L", not available" : L"");
        char dbg[112];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] MENU cursor=%u (%ls)%s vis=%04X dis=%04X",
            curr, label, row_disabled ? " disabled" : "",
            visible_rows, disabled_rows);
        Log::Write(dbg);
        TTS::Speak(line, /*interrupt=*/true);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Config sub-menu cursor polling thread.
//
// Polls FF7Addr::CONFIG_ROW (0x00DC10F0) and announces the highlighted Config
// row by name whenever the cursor moves.
//
// CONFIG_ROW values (confirmed 2026-07-02 via isolate scan + verify):
//   0=Window color  1=Sound         2=Controller  3=Cursor
//   4=ATB           5=Battle speed  6=Battle msg  7=Field msg
//   8=Camera angle  9=Magic order
//
// GATE â€” CONFIG_OPEN PROXY:
//   No dedicated "config sub-menu open" flag was found.  All symmetric-toggle
//   candidates from ff7_config_menu_scan.py Phase C fired on any main-menu
//   open event, identical to the existing MENU_OPEN (0x00DC12DC).  We gate
//   on MENU_CURSOR == 7 (the Config row in the main menu) as a proxy:
//     - In the config sub-menu: MENU_CURSOR is frozen at 7 and CONFIG_ROW
//       changes with Up/Down presses.  Thread tracks and announces.
//     - On the Config row of the main menu (before pressing Confirm): MENU_CURSOR
//       is also 7 but Up/Down moves the MAIN MENU cursor, not CONFIG_ROW.
//       CONFIG_ROW doesn't change â†’ thread is active but stays silent. âœ“
//     - On any other main-menu row: MENU_CURSOR â‰  7 â†’ thread skips. âœ“
//
// FALSE-ANNOUNCE PREVENTION (no 0xFF sentinel):
//   last_row is initialized to 0 (matching the BSS default of CONFIG_ROW) and
//   is NEVER reset to 0xFF.  Keeping last_row persistent across menu opens
//   prevents a false announce when MENU_CURSOR passes through 7 during main-
//   menu navigation: CONFIG_ROW retains its last config-session value, which
//   always equals last_row (since last_row only updates when we announce), so
//   they are always in sync when the player has not entered the sub-menu.
//
//   The one accepted limitation: if the player last visited config ending on
//   row 0 (Window color), re-entering config will not announce the initial
//   row because CONFIG_ROW resets to 0 = last_row.  The player can press
//   Up or Down once to hear their position.  See TODO.txt (re-announce entry).
//
// Gated by Config::Get().speak_menus.
// ---------------------------------------------------------------------------
static DWORD WINAPI ConfigMenuThread(LPVOID /*unused*/)
{
    static const wchar_t* const kConfigRowLabels[] = {
        L"Window color",    // 0
        L"Sound",           // 1
        L"Controller",      // 2
        L"Cursor",          // 3
        L"ATB",             // 4
        L"Battle speed",    // 5
        L"Battle message",  // 6
        L"Field message",   // 7
        L"Camera angle",    // 8
        L"Magic order",     // 9
    };
    static const uint8_t kConfigRowMax = 9;

    // Initialized to 0 (= Window color, same as the BSS value of CONFIG_ROW).
    // Never reset to 0xFF â€” see "FALSE-ANNOUNCE PREVENTION" note above.
    uint8_t  last_row   = 0;
    // Last-announced extracted setting value for the current row. 0xFFFF = none
    // announced yet (also used as the sentinel for rows with no value address).
    // Reset to 0xFFFF whenever last_row changes so the new row's value is read
    // and announced immediately.
    uint16_t last_value = 0xFFFF;
    // Sound sub-menu cursor (SOUND_CURSOR 0x00DC108C): 0=Music, 1=FX, 0xFF=not observed.
    // Reset to 0xFF when CONFIG_ROW leaves row 1 so the first read on re-entry
    // is always silent (prevents spurious announce if the byte retained its last
    // value while the Sound sub-menu was closed).
    uint8_t  last_sound_cursor = 0xFF;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 150) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_menus) continue;

        // v2.30.32: MENU_CURSOR is stale on the menu module's foreign
        // screens (shop/PHS/name entry) â€” the ==7 Config-row proxy below
        // would trust it (see MenuModuleForeignScreen). v2.30.37: same for
        // the post-game-over title sequence (stale MENU_CURSOR + MENU_OPEN=1
        // + stale nonzero FIELD_ID pass every gate below).
        if (MenuModuleForeignScreen() || GameOverTitleContext()) continue;

        // Field must be active â€” config sub-menu only reachable from a field map.
        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        if (field_id == 0) continue;

        // Main menu (and therefore config sub-menu) requires MENU_OPEN.
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        if (menu_open == 0) continue;

        // v2.30.75: the config sub-menu only exists under the main-menu
        // module (GAME_MODE==9). The victory screens raise MENU_OPEN with
        // MENU_CURSOR stale â€” possibly at 7 â€” while GAME_MODE stays 2;
        // the row/value-sync invariant below happened to keep this thread
        // quiet there, but the stand-down should be positive, not lucky
        // (2026-08-03 handoff log).
        if (*reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE) !=
                FF7Addr::GAME_MODE_MAIN_MENU)
            continue;

        // Proxy gate for config sub-menu: MENU_CURSOR must be 7 (Config row).
        const uint8_t menu_cursor =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_CURSOR);
        if (menu_cursor != 7) continue;

        const uint8_t curr =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_ROW);

        if (curr > kConfigRowMax) continue;

        const bool row_changed = (curr != last_row);
        if (row_changed) {
            last_row   = curr;
            last_value = 0xFFFF;  // reset so the new row's value is announced
        }

        // Extract the display value for this row.
        // new_value = 0xFFFF means no value tracking (rows 0, 1, 2).
        // val_str holds the human-readable form for TTS.
        uint16_t new_value = 0xFFFF;
        wchar_t  val_str[32] = {};
        switch (curr) {
        case 3: {
            // Cursor: bit 4 of CONFIG_PACKED_CURSOR_ATB (0=Initial, 1=Memory)
            const uint8_t packed =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_PACKED_CURSOR_ATB);
            new_value = (packed >> 4) & 1;
            _snwprintf_s(val_str, _countof(val_str), _TRUNCATE,
                         L"%ls", new_value ? L"Memory" : L"Initial");
            break;
        }
        case 4: {
            // ATB: bits 7:6 of CONFIG_PACKED_CURSOR_ATB (0=Active, 1=Recommended, 2=Wait)
            static const wchar_t* const kATB[] = { L"Active", L"Recommended", L"Wait" };
            const uint8_t packed =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_PACKED_CURSOR_ATB);
            new_value = (packed >> 6) & 3;
            _snwprintf_s(val_str, _countof(val_str), _TRUNCATE,
                         L"%ls", new_value < 3 ? kATB[new_value] : L"unknown");
            break;
        }
        case 5: {
            // Battle speed: raw byte 0â€“255 (0=Fast, 255=Slow)
            new_value = *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_SPEED_BATTLE);
            _snwprintf_s(val_str, _countof(val_str), _TRUNCATE, L"%u", new_value);
            break;
        }
        case 6: {
            // Battle message: raw byte 0â€“255 (0=Fast, 255=Slow)
            new_value = *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_SPEED_MSG);
            _snwprintf_s(val_str, _countof(val_str), _TRUNCATE, L"%u", new_value);
            break;
        }
        case 7: {
            // Field message: raw byte 0â€“255 (0=Fast, 255=Slow)
            new_value = *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_SPEED_FIELD_MSG);
            _snwprintf_s(val_str, _countof(val_str), _TRUNCATE, L"%u", new_value);
            break;
        }
        case 8: {
            // Camera angle: bit 0 of CONFIG_PACKED_CAMERA_MAGIC (0=Auto, 1=Fixed)
            const uint8_t packed =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_PACKED_CAMERA_MAGIC);
            new_value = packed & 1;
            _snwprintf_s(val_str, _countof(val_str), _TRUNCATE,
                         L"%ls", new_value ? L"Fixed" : L"Auto");
            break;
        }
        case 9: {
            // Magic order: bits 4:2 of CONFIG_PACKED_CAMERA_MAGIC (0â€“5 â†’ No.1â€“No.6)
            const uint8_t packed =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_PACKED_CAMERA_MAGIC);
            new_value = (packed >> 2) & 7;
            _snwprintf_s(val_str, _countof(val_str), _TRUNCATE, L"No. %u", new_value + 1u);
            break;
        }
        default:
            break;  // rows 0, 1, 2: new_value stays 0xFFFF, val_str stays empty
        }

        // â”€â”€ Sound sub-menu cursor (Up/Down between Music and FX sliders) â”€â”€â”€â”€â”€
        // Runs independently of the row-value check below so a cursor navigation
        // that leaves CONFIG_ROW unchanged is still caught.
        //
        // Guards:
        //   first_obs (last_sound_cursor==0xFF): silently establishes baseline
        //     on the first poll after entering CONFIG_ROW==1, preventing a false
        //     announce caused by the retained cursor byte from a prior session.
        //   sc > 1: out-of-range â€” ignore; do not update sentinel so the next
        //     in-range value triggers an announce.
        //
        // Volume inclusion: if the IAT hook has seen a slider change this session,
        //   g_sound_{music,fx}_vol hold the last-spoken value and we append it.
        //   If 0xFF (never seen), we announce the slider name only.
        if (curr == 1) {
            const uint8_t sc =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::SOUND_CURSOR);
            if (sc != last_sound_cursor && sc <= 1) {
                const bool first_obs = (last_sound_cursor == 0xFF);
                last_sound_cursor = sc;
                if (!first_obs) {
                    const wchar_t* slider_label =
                        (sc == 0) ? L"Music volume" : L"FX volume";
                    const uint8_t  cached_vol =
                        (sc == 0) ? static_cast<uint8_t>(g_sound_music_vol)
                                  : static_cast<uint8_t>(g_sound_fx_vol);
                    wchar_t sannounce[64] = {};
                    if (cached_vol != 0xFF) {
                        _snwprintf_s(sannounce, _countof(sannounce), _TRUNCATE,
                                     L"%ls, %u", slider_label,
                                     static_cast<unsigned>(cached_vol));
                    } else {
                        _snwprintf_s(sannounce, _countof(sannounce), _TRUNCATE,
                                     L"%ls", slider_label);
                    }
                    char sdbg[80];
                    _snprintf_s(sdbg, sizeof(sdbg), _TRUNCATE,
                        "[FF7Access] SOUND cursor=%u (%ls)", sc, sannounce);
                    Log::Write(sdbg);
                    TTS::Speak(sannounce, /*interrupt=*/true);
                }
            }
        } else {
            // Not on Sound row: reset so re-entry first-observation is silent.
            last_sound_cursor = 0xFF;
        }

        // Nothing changed: same row and same extracted value (or no value tracking).
        if (!row_changed && new_value == last_value) continue;
        last_value = new_value;

        // Row navigation â†’ "Row name, value" (or just row name for untracked rows).
        // Left/Right within a row â†’ just the value string.
        wchar_t announce[64];
        if (row_changed) {
            if (val_str[0] != L'\0') {
                _snwprintf_s(announce, _countof(announce), _TRUNCATE,
                             L"%ls, %ls", kConfigRowLabels[curr], val_str);
            } else {
                _snwprintf_s(announce, _countof(announce), _TRUNCATE,
                             L"%ls", kConfigRowLabels[curr]);
            }
        } else {
            _snwprintf_s(announce, _countof(announce), _TRUNCATE, L"%ls", val_str);
        }

        char dbg[80];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] CONFIG row=%u (%ls)", curr, announce);
        Log::Write(dbg);
        TTS::Speak(announce, /*interrupt=*/true);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// SAVE / LOAD menu TTS (v2.29, 2026-07-17).
//
// The menu behind main-menu SAVE (at a save point) and the title screen's
// Continue: a 10-file grid ("Save 1".."Save 10"), then a 15-slot list
// inside the chosen file. Same UI, but TWO separate implementations with
// separate state (the shared-module assumption was live-DISPROVED
// 2026-07-17): the save menu's cursors in the DC6Axx menu block
// (ff7_save_menu_scan.py) and the Continue menu's own instance in the
// title block (ff7_continue_menu_scan.py) â€” each grid cursor was
// live-verified by its scan's speak-back pass, and both instances share
// the same +0x3C gridâ†’slot struct spacing. See ff7_addresses.h
// SAVEMENU_* / LOADMENU_*.
//
// The slot PREVIEW data (what the sighted player sees per slot: lead
// character, level, location, play time, gil, party portraits) is read
// from the save FILES themselves, not from game memory: the menu renders
// from saveNN.ff7 on disk, whose layout was derived from the player's own
// save00.ff7 against screenshot ground truth (research doc Â§5 "Save file
// (.ff7) slot-preview layout", ff7_savefile_preview_derive.py). Files are
// re-read on every announce â€” 65 KB a press is nothing, and it means a
// just-written save can never be announced stale.
//
// ANNOUNCE MODEL (change-only, the MenuCursorThread rule): neither menu
// has a known "just opened" flag â€” in save mode the gate (MENU_OPEN=1
// with MENU_CURSOR frozen on the Save row, the Config-submenu signature)
// becomes true while the player is still browsing the main menu, and at
// the title nothing observable distinguishes the Continue grid from the
// plain title screen (continue_menu_verify: every known byte constant).
// So: cursor moves and pane changes announce; entering the slot list
// announces "Game N" plus the slot under the cursor; everything is
// range-guarded â€” any out-of-range value (grid>9, slot>14, phase>1)
// means some other module owns those bytes right now â€” reset and stay
// silent (the TitleCursorThread 0/1-only lesson).
// ---------------------------------------------------------------------------

// One parsed slot preview. name/location hold the SAVED text (renames and
// the game's own caption spelling carry through automatically).
struct SaveSlotPreview {
    bool     used;
    uint8_t  level;
    uint8_t  portraits[3];    // char ids, 0xFF = empty party slot
    wchar_t  name[20];
    wchar_t  location[32];
    uint32_t gil;
    uint32_t seconds;         // total play time
};

// .ff7 layout constants â€” every one verified against the real file
// (research doc Â§5): 9-byte header, 15 slots of 0x10F4, preview at the
// slot head, empty slot = all-zero.
static const size_t kSaveFileHeader  = 9;
static const size_t kSaveSlotStride  = 0x10F4;
static const int    kSaveSlotCount   = 15;
static const size_t kSaveFileSize    = 9 + 15 * 0x10F4;  // 65,109 bytes
static const size_t kSavePreviewLen  = 0x48;             // parsed region

// Decode an FF7-encoded, 0xFF-terminated string field into out (drops
// undecodable bytes, trims trailing spaces). Reuses the dialog decoder's
// per-byte table via FF7Text::DecodeChar.
static void SaveDecodeText(const uint8_t* src, size_t max_bytes,
                           wchar_t* out, size_t out_cap)
{
    size_t n = 0;
    for (size_t i = 0; i < max_bytes && n + 1 < out_cap; ++i) {
        if (src[i] == 0xFF)
            break;
        const wchar_t c = FF7Text::DecodeChar(src[i]);
        if (c != L'\0')
            out[n++] = c;
    }
    while (n > 0 && out[n - 1] == L' ')
        --n;
    out[n] = L'\0';
}

// Read + parse one save file. Grid entry "Save <idx+1>" = save0<idx>.ff7
// in the save\ directory next to the DLL (same own-module-directory
// pattern as Config::Load / PlacesFilePath â€” immune to CWD games).
// Returns false if the file is absent or malformed; out[] is then all
// unused, which speaks as an empty file â€” exactly what the sighted menu
// shows for a file that was never saved to.
// ---------------------------------------------------------------------------
// WHERE THE SAVE FILES LIVE (v2.30.63).
//
// The original reader assumed ONE layout: a save\ folder next to the DLL.
// Right for the 1998 release and the 2026 re-release
// (ff7/workingdir/save/), WRONG for the 2013 Steam release, which keeps
// saves under the user's Documents:
//
//   <Documents>\Square Enix\FINAL FANTASY VII Steam\user_<steamid>\saveNN.ff7
//
// Tester report (2013 + 7th Heaven): every slot read "empty". Reproduced
// locally - that install's game-dir save\ folder EXISTS but is empty,
// while the Documents copy holds the real save00.ff7. The file FORMAT is
// identical (65,109 bytes; parsing that very file with the research-doc
// layout gives "Cloud, level 7, Mako Reactor 1, 376 gil, 25 minutes"),
// so only the path was wrong - no preview re-derivation needed, and 7th
// Heaven turns out not to redirect saves at all.
//
// Documents must come from the SHELL, not %USERPROFILE%\Documents: this
// machine has OneDrive folder redirection, so the literal path does not
// exist. SHGetFolderPath returns the redirected location.
//
// A directory only qualifies if it actually CONTAINS a saveNN.ff7 - that
// is what lets the 2013 install's empty game-dir save\ fall through to
// Documents instead of shadowing it. The winner is cached; if the cached
// directory later has no files (profile switch), it re-resolves.
// ---------------------------------------------------------------------------
static char g_save_dir[MAX_PATH] = {};   // trailing backslash when set

static bool SaveDirHasFiles(const char* dir)
{
    char pat[MAX_PATH];
    _snprintf_s(pat, sizeof(pat), _TRUNCATE, "%ssave*.ff7", dir);
    WIN32_FIND_DATAA fd = {};
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    FindClose(h);
    return true;
}

static bool ResolveSaveDir()
{
    if (g_save_dir[0] && SaveDirHasFiles(g_save_dir))
        return true;
    g_save_dir[0] = '\0';

    // 1. save\ beside the DLL - 1998 / 2026 layouts.
    HMODULE hSelf = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&ResolveSaveDir), &hSelf);
    char base[MAX_PATH] = {};
    GetModuleFileNameA(hSelf, base, MAX_PATH);
    char* sep = strrchr(base, '\\');
    if (sep) *(sep + 1) = '\0';
    char cand[MAX_PATH];
    _snprintf_s(cand, sizeof(cand), _TRUNCATE, "%ssave\\", base);
    if (SaveDirHasFiles(cand)) {
        strcpy_s(g_save_dir, cand);
        Log::Write("[FF7Access] SAVE dir: game folder save\\");
        return true;
    }

    // 2. 2013 Steam profile under (possibly redirected) Documents.
    char docs[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PERSONAL, nullptr,
                                   SHGFP_TYPE_CURRENT, docs))) {
        char pat[MAX_PATH];
        _snprintf_s(pat, sizeof(pat), _TRUNCATE,
                    "%s\\Square Enix\\FINAL FANTASY VII Steam\\user_*", docs);
        WIN32_FIND_DATAA fd = {};
        HANDLE h = FindFirstFileA(pat, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            FILETIME best = {};
            char best_dir[MAX_PATH] = {};
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    continue;
                char dir[MAX_PATH];
                _snprintf_s(dir, sizeof(dir), _TRUNCATE,
                            "%s\\Square Enix\\FINAL FANTASY VII Steam\\%s\\",
                            docs, fd.cFileName);
                if (!SaveDirHasFiles(dir))
                    continue;
                // Multiple Steam accounts each get a user_ folder; take
                // the most recently written - the profile in use.
                if (best_dir[0] == '\0' ||
                    CompareFileTime(&fd.ftLastWriteTime, &best) > 0) {
                    best = fd.ftLastWriteTime;
                    strcpy_s(best_dir, dir);
                }
            } while (FindNextFileA(h, &fd));
            FindClose(h);
            if (best_dir[0]) {
                strcpy_s(g_save_dir, best_dir);
                char dbg[MAX_PATH + 64];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] SAVE dir: 2013 Steam profile '%s'",
                    g_save_dir);
                Log::Write(dbg);
                return true;
            }
        }
    }
    Log::Write("[FF7Access] SAVE dir: none found (slots will read empty)");
    return false;
}

static bool ReadSaveFilePreviews(int file_idx, SaveSlotPreview out[/*15*/])
{
    memset(out, 0, sizeof(SaveSlotPreview) * kSaveSlotCount);

    // v2.30.63: the directory is resolved (and cached) by ResolveSaveDir
    // above - the 2013 Steam release keeps saves in Documents, not in a
    // save\ folder beside the DLL.
    if (!ResolveSaveDir())
        return false;
    char full[MAX_PATH];
    _snprintf_s(full, sizeof(full), _TRUNCATE, "%ssave%02d.ff7",
                g_save_dir, file_idx);

    std::ifstream f(full, std::ios::binary);
    if (!f.is_open())
        return false;
    std::vector<uint8_t> data(kSaveFileSize);
    f.read(reinterpret_cast<char*>(data.data()), kSaveFileSize);
    if (static_cast<size_t>(f.gcount()) != kSaveFileSize)
        return false;                     // truncated/foreign file: distrust

    for (int s = 0; s < kSaveSlotCount; ++s) {
        const uint8_t* p = data.data() + kSaveFileHeader + s * kSaveSlotStride;
        // Empty slot = all-zero (verified: the real file's unused slot 1 is
        // zero through its whole 0x10F4 bytes). Checking just the preview
        // region is sufficient and cheap.
        bool any = false;
        for (size_t i = 0; i < kSavePreviewLen && !any; ++i)
            any = p[i] != 0;
        if (!any)
            continue;
        SaveSlotPreview& sp = out[s];
        sp.used  = true;
        sp.level = p[0x04];
        memcpy(sp.portraits, p + 0x05, 3);
        SaveDecodeText(p + 0x08, 0x10, sp.name, _countof(sp.name));
        sp.gil     = *reinterpret_cast<const uint32_t*>(p + 0x20);
        sp.seconds = *reinterpret_cast<const uint32_t*>(p + 0x24);
        SaveDecodeText(p + 0x28, 0x1C, sp.location, _countof(sp.location));
    }
    return true;
}

// "1 hour 5 minutes" / "21 minutes" â€” the menu's HH:MM, made speakable.
static void SaveTimeSpeakable(uint32_t seconds, wchar_t* out, size_t cap)
{
    const uint32_t h = seconds / 3600;
    const uint32_t m = (seconds / 60) % 60;
    if (h > 0)
        _snwprintf_s(out, cap, _TRUNCATE, L"%u hour%ls %u minute%ls",
                     h, h == 1 ? L"" : L"s", m, m == 1 ? L"" : L"s");
    else
        _snwprintf_s(out, cap, _TRUNCATE, L"%u minute%ls",
                     m, m == 1 ? L"" : L"s");
}

// Spoken line for one slot: "Slot 2: Cloud, level 7, No.1 Reactor,
// 21 minutes, 376 gil, with Barret" â€” the whole sighted preview minus
// HP/MP (menu-identity noise). Non-lead party from the portrait ids via
// the DEFAULT names (the lead's name is the saved text; the others'
// renames are not in the preview block â€” default names are the honest
// best available).
static void SaveSlotLine(int slot_idx, const SaveSlotPreview& sp,
                         wchar_t* out, size_t cap)
{
    if (!sp.used) {
        _snwprintf_s(out, cap, _TRUNCATE, L"Slot %d, empty", slot_idx + 1);
        return;
    }
    wchar_t tbuf[32];
    SaveTimeSpeakable(sp.seconds, tbuf, _countof(tbuf));
    _snwprintf_s(out, cap, _TRUNCATE, L"Slot %d: %ls, level %u, %ls, %ls, %u gil",
                 slot_idx + 1, sp.name, sp.level, sp.location, tbuf, sp.gil);
    int companions = 0;                   // portraits[0] is the lead
    for (int i = 1; i < 3; ++i) {
        const wchar_t* nm = sp.portraits[i] == 0xFF
            ? nullptr : FF7Text::DefaultCharName(sp.portraits[i]);
        if (!nm)
            continue;                     // party-slot hole: keep joiners right
        wchar_t part[40];
        _snwprintf_s(part, _countof(part), _TRUNCATE, L"%ls %ls",
                     companions == 0 ? L", with" : L" and", nm);
        wcsncat_s(out, cap, part, _TRUNCATE);
        ++companions;
    }
}

// Spoken line for one file-grid entry: "Save 1, 3 saves" / "Save 2, empty".
static void SaveGridLine(int file_idx, wchar_t* out, size_t cap)
{
    SaveSlotPreview slots[15];
    ReadSaveFilePreviews(file_idx, slots);
    int used = 0;
    for (int s = 0; s < kSaveSlotCount; ++s)
        used += slots[s].used ? 1 : 0;
    if (used == 0)
        _snwprintf_s(out, cap, _TRUNCATE, L"Save %d, empty", file_idx + 1);
    else
        _snwprintf_s(out, cap, _TRUNCATE, L"Save %d, %d save%ls",
                     file_idx + 1, used, used == 1 ? L"" : L"s");
}

static DWORD WINAPI SaveMenuThread(LPVOID /*unused*/)
{
    uint8_t last_phase = 0xFF;   // 0xFF = unseeded (gate was closed)
    uint8_t last_grid  = 0xFF;
    uint8_t last_slot  = 0xFF;
    bool    in_confirm = false;  // Yes/No dialog open last poll (v2.29.5)
    uint8_t last_yesno = 0xFF;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 150) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_menus) {
            last_phase = last_grid = last_slot = 0xFF;
            in_confirm = false;
            last_yesno = 0xFF;
            continue;
        }

        // v2.30.32: the save-mode gate below is "MENU_OPEN + MENU_CURSOR
        // frozen at 9" â€” EXACTLY the stale signature a shop shows when the
        // player's last main-menu visit ended on the Save row (the
        // 2026-07-26 false-"Save" report). Stand down on foreign screens.
        if (MenuModuleForeignScreen()) {
            last_phase = last_grid = last_slot = 0xFF;
            in_confirm = false;
            last_yesno = 0xFF;
            continue;
        }

        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        const uint8_t menu_cursor =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_CURSOR);

        // TWO menu implementations, one speaker (live-proven 2026-07-17:
        // the title Continue menu does NOT share the save menu's state â€”
        // continue_menu_verify log â€” it has its own instance in the TITLE
        // block, found by continue_menu_scan the same day):
        //   SAVE mode â€” in-field menu module, gated by the frozen-row
        //   signature (MENU_OPEN=1, MENU_CURSOR held at 9, FIELD_ID!=0).
        //   LOAD mode â€” title context (FIELD_ID==0).
        // The PANE for BOTH comes from LOADMENU_LIST_PTR (nonzero = the
        // slot list is open; it is the loaded file's heap pointer, and
        // both scans observed it independently â€” nonzero-check only,
        // never deref). The per-menu phase byte 0xDC1210 is DISPROVED:
        // it oscillates in real use, which made v2.29.1 alternate the
        // two pane announcements endlessly (player report).
        //
        // The slot position is ROW (0..2 visible window) + SCROLL
        // (0..12) â€” the "only 3 slots" player report; scroll offsets per
        // ff7_slot_scroll_probe.py (title instance live-confirmed; save
        // instance inferred at the same struct offset +0x10).
        //
        // The FILE position is likewise split (v2.29.3, the "second row
        // counts wrong" player report): GRID_CURSOR is the COLUMN 0..4,
        // the 5Ã—2 grid's row a separate byte at grid+4: 0 = top row
        // (Save 1-5), 1 = bottom row (Save 6-10). File index =
        // rowbyte*5 + column. (v2.29.4: the first reading was inverted â€”
        // the probe's baseline of 1 was the player already PARKED on the
        // bottom row, not the top; their play report of Save 6 spoken on
        // the top row is the decisive observation.)
        // v2.30.37: !GameOverTitleContext() â€” the post-game-over title
        // prompt raises MENU_OPEN with FIELD_ID stale nonzero, and if the
        // player's last main-menu visit parked MENU_CURSOR on the Save row
        // (row 9 â€” exactly the 2026-07-26 shop false-"Save" signature) this
        // gate would select the WRONG menu instance for the Continue grid.
        // v2.30.75: GAME_MODE==9 requirement â€” the victory results screens
        // raise MENU_OPEN with MENU_CURSOR stale (a pre-boss save parks it
        // at row 9, the common case) while GAME_MODE stays 2; this thread
        // previously had NO victory stand-down at all (2026-08-03 handoff
        // log). The LOAD mode below is title context (FIELD_ID==0, mode 0)
        // and deliberately does not take this requirement.
        const bool save_mode =
            menu_open == 1 && menu_cursor == 9 && field_id != 0 &&
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE) ==
                FF7Addr::GAME_MODE_MAIN_MENU &&
            !GameOverTitleContext();

        // v2.29.5: the "Are you sure you want to save?" Yes/No dialog.
        // Widget-state byte 0xDCA028 == 7 while it is open (1 = slot
        // list â€” it is the save menu's little state machine, the SINGLE
        // A/B/A candidate of ff7_save_confirm_scan 2026-07-17); cursor
        // 0xDC6C6C 0=Yes 1=No, speak-back verified. The slot-row byte
        // holds still during the dialog (same scan log), so this block
        // runs FIRST and short-circuits the pane/cursor logic below
        // while the dialog is up. Save mode only â€” the Continue menu
        // loads without a confirm.
        if (save_mode) {
            const uint8_t wstate =
                *reinterpret_cast<const volatile uint8_t*>(
                    FF7Addr::SAVEMENU_WIDGET_STATE);
            const uint8_t yesno =
                *reinterpret_cast<const volatile uint8_t*>(
                    FF7Addr::SAVEMENU_CONFIRM_CURSOR);
            if (wstate == FF7Addr::SAVEMENU_STATE_CONFIRM && yesno <= 1) {
                if (!in_confirm) {
                    // Dialog just opened (cursor starts on Yes).
                    wchar_t line[80];
                    _snwprintf_s(line, _countof(line), _TRUNCATE,
                                 L"Are you sure you want to save? %ls",
                                 yesno ? L"No" : L"Yes");
                    Log::Write("[FF7Access] SAVEMENU confirm open");
                    TTS::Speak(line, /*interrupt=*/true);
                } else if (yesno != last_yesno) {
                    TTS::Speak(yesno ? L"No" : L"Yes", /*interrupt=*/true);
                }
                in_confirm = true;
                last_yesno = yesno;
                continue;
            }
        }
        in_confirm = false;
        last_yesno = 0xFF;

        const uint8_t phase =
            *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::LOADMENU_LIST_PTR) != 0 ? 1 : 0;

        uint8_t col, grow, row, scroll;
        if (save_mode) {
            col = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::SAVEMENU_GRID_CURSOR);
            grow = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::SAVEMENU_GRID_ROW);
            row = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::SAVEMENU_SLOT_CURSOR);
            scroll = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::SAVEMENU_SLOT_SCROLL);
        } else if (field_id == 0 || GameOverTitleContext()) {
            // v2.30.37: GameOverTitleContext â€” the post-game-over Continue
            // grid IS the title-block LOAD instance, but FIELD_ID stays
            // stale nonzero there (the whole point of the latch). Without
            // this the Continue path after a game over browsed silently.
            col = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::LOADMENU_GRID_CURSOR);
            grow = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::LOADMENU_GRID_ROW);
            row = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::LOADMENU_SLOT_CURSOR);
            scroll = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::LOADMENU_SLOT_SCROLL);
        } else {
            last_phase = last_grid = last_slot = 0xFF;
            continue;
        }
        const uint8_t grid = grow * 5 + col;         // file index 0..9
        const uint8_t slot = row + scroll;           // absolute 0..14

        // Out-of-range = these bytes belong to some other module right now
        // (e.g. the plain title screen before Continue is chosen).
        if (col > 4 || grow > 1 || row > 2 || scroll > 12) {
            last_phase = last_grid = last_slot = 0xFF;
            continue;
        }

        // First observation after the gate opens: seed silently. In save
        // mode the gate opens while the player is still on the main menu's
        // Save row â€” announcing then would talk over MenuCursorThread's
        // own "Save".
        if (last_phase == 0xFF) {
            last_phase = phase;
            last_grid  = grid;
            last_slot  = slot;
            continue;
        }

        wchar_t line[192];

        if (phase != last_phase) {
            // Pane change. Into the slot list: name the file and the slot
            // under the cursor (the grid byte HOLDS the selected file
            // while the list is open â€” scan-verified). Back to the grid:
            // re-orient with the grid line.
            if (phase == 1) {
                SaveSlotPreview slots[15];
                ReadSaveFilePreviews(grid, slots);
                wchar_t sline[160];
                SaveSlotLine(slot, slots[slot], sline, _countof(sline));
                _snwprintf_s(line, _countof(line), _TRUNCATE,
                             L"Game %u. %ls", grid + 1u, sline);
            } else {
                SaveGridLine(grid, line, _countof(line));
            }
            last_phase = phase;
            last_grid  = grid;
            last_slot  = slot;
        } else if (phase == 0 && grid != last_grid) {
            SaveGridLine(grid, line, _countof(line));
            last_grid = grid;
        } else if (phase == 1 && slot != last_slot) {
            SaveSlotPreview slots[15];
            ReadSaveFilePreviews(grid, slots);
            SaveSlotLine(slot, slots[slot], line, _countof(line));
            last_slot = slot;
        } else {
            continue;
        }

        char dbg[224];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] SAVEMENU phase=%u grid=%u slot=%u '%ls'",
            phase, grid, slot, line);
        Log::Write(dbg);
        TTS::Speak(line, /*interrupt=*/true);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Battle action polling thread (v2.7: exact action names).
//
// Polls g_active_actor_id and the battle model state arrays to detect battle
// actions, then resolves the EXACT flash-message text ("Ice", "Potion",
// "Machine Gun", "Braver") by replicating the game's own dispatcher â€” see the
// v2.7 resolution notes in ff7_addresses.h (SECTION 1c) for the full data-flow
// derivation (kernel2_consumer_disasm / action_name_final_verify, 2026-07-11).
//
// WHY POLLING (not a function hook):
//   FFNx trampolines display_battle_action_text_42782A (0x42782A) and
//   sub_6D71FA (0x6D71FA).  Hooking those entry points would intercept FFNx,
//   not the game.  Polling reads the same data with no patching.
//
// ACTOR VALIDITY:
//   Party slots 0â€“2; enemy slots 4â€“9.  Slot 3 never appears.
//   g_active_actor_id initialises to 0 at process start and is never reset
//   between battles; commandID==0 is the only reliable "not in battle" gate.
//   The first action of a new battle is announced because actor_id changes;
//   a new battle whose first actor equals the previous battle's last actor
//   misses that one action (accepted).
//
// ANNOUNCE TIMING (why announcements are two-phase):
//   The turn STARTS when g_active_actor_id changes, but the flash-message
//   struct (battle_actor_data 0xDC38E0) is only written ~1â€“2s later, when the
//   flash text actually appears on screen.  Live-verified 2026-07-11:
//   reading it at turn start yields the PREVIOUS action's values.  Also, the
//   struct is NOT rewritten when the new flash content equals the old (e.g.
//   the same enemy attack twice in a row), and never written at all for
//   commands with no flash text (plain Attack).  Therefore:
//     - commands with no flash text (dispatch branch 9) announce a generic
//       label immediately at turn start;
//     - name-bearing commands wait for the struct to CHANGE (flash appeared,
//       resolve new values) or for a 2.5s timeout: on timeout, if the struct's
//       command matches the current action's command the current values are
//       resolved (repeated-flash case â€” values are still correct); otherwise
//       fall back to the generic label.  A stale same-command struct from a
//       DIFFERENT action can theoretically misname one enemy attack; accepted
//       and documented in the research notes.
//
// Gated by Config::Get().speak_battle.
// ---------------------------------------------------------------------------

// Kernel2 text section base pointers, located at runtime.  The decompressed
// kernel2 text lives in ONE heap allocation whose address changes per run;
// each section is a u16 entry-offset table followed by 0xFF-terminated
// FF7-encoded strings (entry N at base + u16[base + N*2]; u16[base] equals
// the offset of entry 0, i.e. the table's own byte size).
//
// âš  LIFETIME (v2.22.1, from the 2026-07-16 play-session log): "scan once,
// cache forever" is TRUE for magic/item/weapon (one resident block, stable
// all session) but FALSE for the COMMAND section â€” it lives in a TRANSIENT
// battle allocation that is freed and reused between battles. The cached
// pointer then decodes reused binary as a "name" that passes every
// structural check in SectionEntryText, and the battle menu spoke garbage
// ("-Ã›+! ' $...") on menu open in the affected battles. Every pointer is
// therefore RE-VALIDATED on each use via ValidatedSection() below; a stale
// pointer is dropped (rate-limited rescan re-finds the live one) and the
// caller falls back to its generic label â€” degraded, never garbage.
struct Kernel2Sections {
    const uint8_t* magic;    // entries: 0-55 spells, 56-71 summons,
                             //          72-95 enemy skills, 128+ limit breaks
    const uint8_t* item;     // entries 0-127 item names
    const uint8_t* weapon;   // entries 0-127 weapon names (thrown weapons)
    const uint8_t* command;  // command names: entry = battle command id - 1
                             // ("Attack","Magic","Summon","Item","Steal",...).
                             // The -1 comes from the menu/battle id space
                             // being 1-based (v2.9, live-corrected) while the
                             // kernel command-name table is 0-based.
    // v2.31 (item menu): the menu inventory mixes equipment ids in with
    // items (id 128+, see SAVEMAP_ITEMS in ff7_addresses.h), and the
    // sighted menu shows a description bar â€” three more sections, same
    // format, same signature discipline (head = entry 0's known English
    // text; a wrong guess finds nothing and callers fall back, never lie).
    const uint8_t* armor;      // entries 0-31 armor names
    const uint8_t* accessory;  // entries 0-31 accessory names
    const uint8_t* item_desc;  // entries 0-127 item descriptions (entry 0 =
                               // Potion's "Restores HP by 100", the exact
                               // items_menu_1.png caption)
    // v2.30.28 (shop menus): materia names/descriptions plus the two gear
    // description sections a weapon shop needs. Section heads ground-truthed
    // from the RUNTIME text file kernel2.bin (LZS-decompressed offline,
    // 2026-07-26 â€” it is the F9-expanded PC text, which is why the heap
    // copies contain plain strings): materia names [0]="MP Plus",
    // [1]="HP Plus"; materia descs [0]="Increases MP capacity"; weapon
    // descs [0]="Initial equipment" (kernel.bin's "Initial equiping" is
    // the PSX-era text â€” the PC runtime uses kernel2's spelling). Armor
    // descriptions have a BLANK entry 0 (single space) so no signature can
    // find them â€” armor rows just get no description, exactly what a
    // sighted player sees (the bar is blank for armor too).
    const uint8_t* magic_desc;    // v2.30.57: entries 0-255 SPELL
                                  // descriptions, index-aligned with
                                  // `magic` above (kernel2 base +0x315 in
                                  // the vanilla file: Cure -> "Restores
                                  // HP", Regen -> "Gradually restores
                                  // HP" — ff7_kernel2_section_enum.py)
    const uint8_t* materia_name;  // entries 0-95 materia names
    const uint8_t* materia_desc;  // entries 0-95 materia descriptions
    const uint8_t* weapon_desc;   // entries 0-127 weapon descriptions
    const uint8_t* accessory_desc;// entries 0-31 accessory descriptions
                                  // (head bytes include the 0xB2/0xB3
                                  // colour codes -> raw-byte signature)
};
static Kernel2Sections g_k2 = { nullptr, nullptr, nullptr, nullptr,
                                nullptr, nullptr, nullptr, nullptr,
                                nullptr, nullptr, nullptr, nullptr };

// Raw-byte section signature for the accessory descriptions: entry 0 is
// "<0xB2>Strength<0xB3> +10" (kernel2.bin ground truth) â€” the colour-code
// bytes cannot be expressed through EncodeSignature's ASCII mapping, so
// this one is spelled out byte-for-byte (text bytes = char - 0x20).
static const uint8_t kAccessoryDescSig[] = {
    0xB2,
    'S'-0x20, 't'-0x20, 'r'-0x20, 'e'-0x20, 'n'-0x20, 'g'-0x20, 't'-0x20, 'h'-0x20,
    0xB3,
    ' '-0x20, '+'-0x20, '1'-0x20, '0'-0x20,
};

// Scan-in-progress guard.  v2.9 added a second thread (BattleMenuThread) that
// can trigger ScanKernel2Sections lazily, so two threads could otherwise scan
// concurrently.  Concurrent scans are HARMLESS for correctness (both compute
// identical section addresses and pointer-sized aligned stores are atomic on
// x86) but each scan walks the whole address space â€” the guard just prevents
// wasted duplicate walks.  A thread that finds the guard taken simply skips;
// its rate-limited retry fires again later.
static volatile LONG g_k2_scan_busy = 0;

// FF7-encode an ASCII signature (byte = char - 0x20; '|' stands for the 0xFF
// string terminator).  Returns encoded length.
static size_t EncodeSignature(const char* ascii, uint8_t* out, size_t cap)
{
    size_t n = 0;
    for (; *ascii && n < cap; ++ascii)
        out[n++] = (*ascii == '|') ? 0xFF : static_cast<uint8_t>(*ascii - 0x20);
    return n;
}

// Defined later in this file (v2.18.2); the kernel2 validator needs it here.
static bool IsReadableSpan(const void* p, size_t len);

// v2.30.77: does this pointer's BODY still look like a kernel2 section?
//
// WHY: the head-signature re-check below closes the "section fully gone"
// window but not the one that actually bit on 2026-08-03 — the scanner's
// first-match address-space walk can latch a TRANSIENT low-address loading
// buffer (both 2026-08-04 logs caught one dying mid-battle: weapon at
// 0FD4F916, command at 0BE69985), and a stale copy whose first bytes
// survive while its body is reused passes the head check and decodes
// reused memory as a name. That is the limit-junk report exactly: Ice and
// Bolt (entries near the head) spoke correctly while Braver at +0x657
// spoke junk, all through one "valid" pointer.
//
// THE INVARIANT: a real section's u16 entry-offset table is monotonically
// non-decreasing with every offset in [table_size, 0x8000] — the format
// packs strings sequentially after the table, and the runtime copy is the
// game's own sequential re-pack of the file section. Verified offline
// against every section the mod scans for, on BOTH installs' kernel2.bin
// (ff7_kernel2_offset_monotonic.py, 2026-08-04; zero-length dummy entries
// make runs of EQUAL offsets, hence non-decreasing, not increasing).
// Randomly reused memory sustaining a hundreds-long monotone in-band run
// is astronomically unlikely, so a body that passes is a body that still
// holds kernel2 text. Cost: one bounded u16 walk (<= 1 KB) per validated
// use — noise next to the announce it guards.
static bool SectionBodyPlausible(const uint8_t* base)
{
    if (!IsReadableSpan(base, 2))
        return false;
    uint16_t tab;
    memcpy(&tab, base, sizeof(tab));
    // Table size = entry 0's offset: even, and inside FindSectionBase's
    // own acceptance range (2..0x800).
    if (tab < 2 || tab > 0x800 || (tab & 1))
        return false;
    if (!IsReadableSpan(base, tab))
        return false;
    uint16_t prev = tab;   // entry 0's offset IS the table size
    for (uint32_t i = 0; i < tab / 2u; ++i) {
        uint16_t off;
        memcpy(&off, base + i * 2, sizeof(off));
        if (off < prev || off > 0x8000)   // out of order or out of band
            return false;
        prev = off;
    }
    return true;
}

// Re-verify a cached kernel2 section pointer before EVERY use (v2.22.1).
//
// WHY: the command-name section is a transient battle allocation (see the
// Kernel2Sections lifetime note) â€” after the game frees and reuses it, the
// cached pointer still "looks like" a section to SectionEntryText's
// structural checks and decodes reused binary as a speakable name. The one
// check garbage cannot pass is the section's own HEAD SIGNATURE: u16[base]
// is the offset of entry 0, and entry 0 must still begin with the exact
// encoded strings FindSectionBase matched ("Attack|Magic|" etc.) â€” the
// identical self-validating rule that located the section in the first
// place, now applied at read time.
//
// On mismatch the slot is NULLED so the callers' rate-limited rescan can
// re-find the live copy; this call returns nullptr and the caller uses its
// generic fallback label. Cost: one ~13-byte encode+memcmp per menu/action
// event â€” noise. Cross-thread: two battle threads may race on *slot; both
// only ever write nullptr here, and aligned pointer stores are atomic on
// x86 (same argument as the scan guard above).
static const uint8_t* ValidatedSectionBytes(const uint8_t** slot,
                                            const uint8_t* sig, size_t sig_len,
                                            const char* debug_label)
{
    const uint8_t* base = *slot;
    if (!base)
        return nullptr;

    bool head_ok = false;
    if (IsReadableSpan(base, 2)) {
        uint16_t first_off;
        memcpy(&first_off, base, sizeof(first_off));
        head_ok = first_off >= 2 && first_off <= 0x800 &&  // FindSectionBase range
             IsReadableSpan(base + first_off, sig_len) &&
             memcmp(base + first_off, sig, sig_len) == 0;
    }
    // v2.30.77: the head alone is not enough — a stale copy whose first
    // bytes survive while the body is reused passed this check and spoke
    // junk (the 2026-08-03 limit-break report; see SectionBodyPlausible).
    const char* why = !head_ok                      ? "head gone"
                    : !SectionBodyPlausible(base)   ? "body implausible"
                    :                                 nullptr;
    if (why) {
        char dbg[128];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] kernel2 section STALE ('%s' %s at %p) â€” "
            "dropped for rescan", debug_label, why, base);
        Log::Write(dbg);
        *slot = nullptr;
        return nullptr;
    }
    return base;
}

// ASCII-signature wrapper â€” the original v2.22.1 entry point; the raw-byte
// core above exists because the accessory-description head embeds colour
// codes (see kAccessoryDescSig).
static const uint8_t* ValidatedSection(const uint8_t** slot,
                                       const char* ascii_sig)
{
    uint8_t sig[24];
    const size_t sig_len = EncodeSignature(ascii_sig, sig, sizeof(sig));
    return ValidatedSectionBytes(slot, sig, sig_len, ascii_sig);
}

// Find a section base inside one memory region: locate the signature (the
// section's first strings), then walk BACKWARD looking for the offset-table
// start: the u16 at the base equals the distance back to the first string.
// This rule self-validates â€” a false positive requires u16[cand] to equal its
// own distance to an accidental signature match, which live scans never hit.
// min_fo/max_fo (v2.30.47): acceptance band on the section's u16[base]
// (= offset of entry 0 = 2 x entry count). The full defaults keep every
// existing caller exactly as before; the RETRANSLATION FALLBACK rungs
// (single-entry signatures like "Cure|") pass tight bands measured from
// vanilla kernel2.bin (ff7_kernel2_sig_ranges.py, 2026-08-01: magic =
// 256 entries/0x200, command = 24 entries/0x30) so a stray matching
// word elsewhere in game text cannot masquerade as the section â€” entry
// COUNT is fixed by the kernel format; text mods only change the words.
static const uint8_t* FindSectionBase(const uint8_t* region, size_t size,
                                      const uint8_t* sig, size_t sig_len,
                                      uint16_t min_fo = 2,
                                      uint16_t max_fo = 0x800)
{
    if (size < sig_len)
        return nullptr;
    const uint8_t* end = region + size - sig_len;
    for (const uint8_t* p = region; p <= end; ++p) {
        p = static_cast<const uint8_t*>(memchr(p, sig[0], end - p + 1));
        if (!p)
            return nullptr;
        if (memcmp(p, sig, sig_len) != 0)
            continue;
        const size_t max_back = static_cast<size_t>(p - region);
        for (uint32_t back = 2; back <= 0x800 && back <= max_back; back += 2) {
            const uint8_t* cand = p - back;
            uint16_t first_off;
            memcpy(&first_off, cand, sizeof(first_off));
            if (first_off == back) {
                // v2.30.77: also require a plausible BODY. The offline
                // dry-run (ff7_kernel2_offset_monotonic.py) caught the
                // failure mode this closes: an "Attack|" hit in ordinary
                // text can backwalk to a coincidental u16-equals-distance
                // word, whose "offset table" is just string bytes — the
                // monotone walk rejects it and the sweep moves on to the
                // real section. Same guard also refuses a transient copy
                // whose body is already reused at scan time.
                if (first_off >= min_fo && first_off <= max_fo &&
                    SectionBodyPlausible(cand))
                    return cand;
                break;   // self-validating base found but wrong shape:
                         // this match is some OTHER table's entry â€” move
                         // to the next signature match, don't keep
                         // walking back past a valid table start.
            }
        }
    }
    return nullptr;
}

// v2.30.43: lifetime count of regions skipped because they vanished
// mid-sweep (see FindSectionBaseSafe). Appended to the scan log line so a
// bug-report log shows how hostile the install's heap churn is.
static volatile LONG g_k2_scan_avs = 0;

// v2.30.43: fruitless-scan backoff. A modded install (retranslated text)
// can leave trigger sections permanently unfindable, and the menu-thread
// call sites retry every 3 SECONDS â€” that was a full address-space sweep
// of live heap every 3s, forever, on exactly the installs (7th Heaven)
// with the most allocation churn. Consecutive fruitless scans now back
// the internal cadence off exponentially; ANY progress resets it, so a
// healthy install (where scans succeed and the triggers go quiet) never
// engages the backoff at all.
static volatile ULONGLONG g_k2_backoff_until    = 0;
static LONG               g_k2_fruitless_streak = 0;

// Wrap one region sweep in SEH (v2.30.43). ROOT CAUSE of the 2026-07-31
// tester crash (scorpion boss, Echo-S via 7th Heaven, low-memory VM):
// VirtualQuery snapshots a region, then FindSectionBase sweeps it with
// memchr/memcmp for MILLISECONDS while the game's own threads keep
// allocating and freeing â€” a region freed or decommitted mid-sweep is an
// access violation inside the CRT (FFNx dump: BattleMenuThread ->
// ScanKernel2Sections -> CRT, 13s into the boss load â€” peak churn from
// battle assets + streaming voice audio). The check-then-read race is
// unfixable by more checking (any recheck has the same window); catching
// the fault and skipping the region is the correct tool for sweeping
// memory this thread does not own. Skipped regions are rescanned by the
// next retry, so nothing is permanently missed.
//
// Separate noinline function because MSVC forbids __try in a function
// requiring C++ unwinding (C2712) â€” this one holds no C++ objects.
// Filter passes only ACCESS_VIOLATION; anything else propagates (a real
// bug elsewhere must stay loud, not get eaten by a scanner guard).
static __declspec(noinline) const uint8_t* FindSectionBaseSafe(
    const uint8_t* region, size_t size, const uint8_t* sig, size_t sig_len,
    uint16_t min_fo = 2, uint16_t max_fo = 0x800)
{
    __try {
        return FindSectionBase(region, size, sig, sig_len, min_fo, max_fo);
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
        InterlockedIncrement(&g_k2_scan_avs);
        return nullptr;
    }
}

// v2.30.47: which signature actually FOUND the magic/command section.
// Under 7th Heaven text mods the vanilla heads fail ("Cure|Cure2|" â‰ 
// Cure/Cura/Curaga naming â€” 2026-08-01 log: every section resolved
// EXCEPT magic and command on the Echo-S install, so the battle magic
// list spoke bare "row N"), and the scan falls back to a single-entry
// signature banded by the section's fixed entry count. ValidatedSection
// re-checks the section head at every read, so it must test the SAME
// bytes that matched â€” these pointers feed it. Written only under the
// scan's busy guard; readers get old-or-new (both valid literals).
static const char* volatile g_k2_magic_sig   = "Cure|Cure2|";
static const char* volatile g_k2_command_sig = "Attack|Magic|";

// Scan this process's committed private read-write memory for the kernel2
// text sections.  Runs from our own polling thread INSIDE the game process,
// so all reads are direct pointer reads.  Called lazily on the first battle
// action and retried (rate-limited) while any section is missing â€” kernel2
// is decompressed during startup and stays resident for the process lifetime,
// so one successful scan is permanent. (Exception: the COMMAND section is a
// transient battle allocation, re-found at each battle start â€” that is why
// the battle threads pass urgent=true: their scans must not be deferred by
// the fruitless-scan backoff armed by field-menu retries. urgent skips only
// the backoff; the callers' own 3s/60s rate limits still apply.)
//
// ENGLISH-ONLY: the signatures are the English section heads.  On a non-
// English kernel2 the scan finds nothing and every action falls back to the
// v2.5 generic labels â€” degraded, never wrong (and the backoff keeps those
// futile sweeps rare).
static void ScanKernel2Sections(bool urgent = false)
{
    if (!urgent && GetTickCount64() < g_k2_backoff_until)
        return;

    // Skip if another thread is mid-scan (see g_k2_scan_busy comment).
    if (InterlockedCompareExchange(&g_k2_scan_busy, 1, 0) != 0)
        return;

    // Count found sections before/after: "progress" resets the backoff.
    const auto count_found = []() {
        int n = 0;
        n += g_k2.magic != nullptr;          n += g_k2.item != nullptr;
        n += g_k2.weapon != nullptr;         n += g_k2.command != nullptr;
        n += g_k2.armor != nullptr;          n += g_k2.accessory != nullptr;
        n += g_k2.item_desc != nullptr;      n += g_k2.materia_name != nullptr;
        n += g_k2.materia_desc != nullptr;   n += g_k2.weapon_desc != nullptr;
        n += g_k2.accessory_desc != nullptr; n += g_k2.magic_desc != nullptr;
        return n;
    };
    const int found_before = count_found();

    uint8_t sig_magic[24], sig_item[24], sig_weapon[24], sig_command[24];
    uint8_t sig_armor[24], sig_access[24], sig_idesc[24];
    uint8_t sig_mname[24], sig_mdesc[24], sig_wdesc[24];
    const size_t len_magic  = EncodeSignature("Cure|Cure2|",        sig_magic,  sizeof(sig_magic));
    const size_t len_item   = EncodeSignature("Potion|Hi-Potion|",  sig_item,   sizeof(sig_item));
    const size_t len_weapon = EncodeSignature("Buster Sword|",      sig_weapon, sizeof(sig_weapon));
    // Command-name section head: entries 0,1,... are "Attack","Magic",...
    // stored back-to-back like every other kernel2 text section.
    const size_t len_command = EncodeSignature("Attack|Magic|",     sig_command, sizeof(sig_command));
    // v2.30.47: retranslation fallbacks. 7th Heaven text mods rename the
    // spell tiers (Cure/Cura/Curaga), killing the two-entry heads while
    // every other section still matches (2026-08-01 log). Entry 0 is the
    // stable word; the single-entry rung is safe because it is banded to
    // the section's FIXED entry count (min_fo/max_fo on FindSectionBase:
    // magic 256 entries = first_off 0x200, command 24 = 0x30 â€” measured
    // from vanilla kernel2.bin by ff7_kernel2_sig_ranges.py, which also
    // showed bare "Cure|" self-validates at exactly ONE place game-wide).
    uint8_t sig_magic_fb[8], sig_cmd_fb[8];
    const size_t len_magic_fb = EncodeSignature("Cure|",   sig_magic_fb, sizeof(sig_magic_fb));
    const size_t len_cmd_fb   = EncodeSignature("Attack|", sig_cmd_fb,   sizeof(sig_cmd_fb));
    // v2.30.57 SPELL DESCRIPTIONS. Head measured from vanilla kernel2
    // (ff7_kernel2_section_enum.py): entries 0/1/2 are all "Restores HP"
    // (Cure/Cure2/Cure3), section = 256 entries, index-aligned with the
    // magic NAME section. The two-entry head matches twice in the file,
    // so the entry-count band (first_off 0x200) is what pins it — the
    // same shape-check rung v2.30.47 introduced for retranslations.
    uint8_t sig_mgdesc[32];
    const size_t len_mgdesc = EncodeSignature("Restores HP|Restores HP|",
                                              sig_mgdesc, sizeof(sig_mgdesc));
    // v2.31 item-menu sections. Armor/accessory heads are kernel entry 0
    // ("Bronze Bangle"/"Power Wrist", both present in walkthrough.txt);
    // the item-description head is Potion's caption, ground-truthed by
    // items_menu_1.png. Signature-or-fallback as always.
    const size_t len_armor  = EncodeSignature("Bronze Bangle|",       sig_armor,  sizeof(sig_armor));
    const size_t len_access = EncodeSignature("Power Wrist|",         sig_access, sizeof(sig_access));
    const size_t len_idesc  = EncodeSignature("Restores HP by 100|",  sig_idesc,  sizeof(sig_idesc));
    // v2.30.28 shop sections â€” heads ground-truthed from kernel2.bin (the
    // runtime text; see the Kernel2Sections comment for why kernel2, not
    // kernel.bin, is the authority here).
    const size_t len_mname = EncodeSignature("MP Plus|HP Plus|",       sig_mname, sizeof(sig_mname));
    const size_t len_mdesc = EncodeSignature("Increases MP capacity|", sig_mdesc, sizeof(sig_mdesc));
    const size_t len_wdesc = EncodeSignature("Initial equipment|",     sig_wdesc, sizeof(sig_wdesc));

    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t addr = 0x00400000;
    while (addr < 0x7FFF0000 &&
           (!g_k2.magic || !g_k2.item || !g_k2.weapon || !g_k2.command ||
            !g_k2.armor || !g_k2.accessory || !g_k2.item_desc ||
            !g_k2.materia_name || !g_k2.materia_desc || !g_k2.weapon_desc ||
            !g_k2.accessory_desc || !g_k2.magic_desc)) {
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
            break;
        const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        // Only committed, private (heap â€” excludes the exe/DLL images, whose
        // .data contains battle-menu inventory copies that would false-match),
        // plain read-write pages.  Guard pages (stack tips) are excluded by
        // the exact protection match.
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            mbi.Protect == PAGE_READWRITE) {
            // v2.30.43: every sweep goes through the SEH guard â€” the game
            // can free this region under us mid-sweep (see
            // FindSectionBaseSafe). A vanished region just yields nullptr
            // for the remaining signatures and the walk continues.
            const uint8_t* p = reinterpret_cast<const uint8_t*>(base);
            if (!g_k2.magic) {
                g_k2.magic = FindSectionBaseSafe(p, mbi.RegionSize, sig_magic, len_magic);
                if (g_k2.magic) {
                    g_k2_magic_sig = "Cure|Cure2|";
                } else {
                    g_k2.magic = FindSectionBaseSafe(p, mbi.RegionSize,
                                                     sig_magic_fb, len_magic_fb,
                                                     0x1F0, 0x210);
                    if (g_k2.magic)
                        g_k2_magic_sig = "Cure|";
                }
            }
            if (!g_k2.item)    g_k2.item    = FindSectionBaseSafe(p, mbi.RegionSize, sig_item,    len_item);
            if (!g_k2.weapon)  g_k2.weapon  = FindSectionBaseSafe(p, mbi.RegionSize, sig_weapon,  len_weapon);
            if (!g_k2.command) {
                g_k2.command = FindSectionBaseSafe(p, mbi.RegionSize, sig_command, len_command);
                if (g_k2.command) {
                    g_k2_command_sig = "Attack|Magic|";
                } else {
                    g_k2.command = FindSectionBaseSafe(p, mbi.RegionSize,
                                                       sig_cmd_fb, len_cmd_fb,
                                                       0x28, 0x40);
                    if (g_k2.command)
                        g_k2_command_sig = "Attack|";
                }
            }
            if (!g_k2.armor)     g_k2.armor     = FindSectionBaseSafe(p, mbi.RegionSize, sig_armor,  len_armor);
            if (!g_k2.accessory) g_k2.accessory = FindSectionBaseSafe(p, mbi.RegionSize, sig_access, len_access);
            if (!g_k2.item_desc) g_k2.item_desc = FindSectionBaseSafe(p, mbi.RegionSize, sig_idesc,  len_idesc);
            if (!g_k2.magic_desc)
                g_k2.magic_desc = FindSectionBaseSafe(p, mbi.RegionSize,
                                                      sig_mgdesc, len_mgdesc,
                                                      0x1F0, 0x210);
            if (!g_k2.materia_name)   g_k2.materia_name   = FindSectionBaseSafe(p, mbi.RegionSize, sig_mname, len_mname);
            if (!g_k2.materia_desc)   g_k2.materia_desc   = FindSectionBaseSafe(p, mbi.RegionSize, sig_mdesc, len_mdesc);
            if (!g_k2.weapon_desc)    g_k2.weapon_desc    = FindSectionBaseSafe(p, mbi.RegionSize, sig_wdesc, len_wdesc);
            if (!g_k2.accessory_desc) g_k2.accessory_desc = FindSectionBaseSafe(p, mbi.RegionSize, kAccessoryDescSig, sizeof(kAccessoryDescSig));
        }
        addr = base + mbi.RegionSize;
    }

    // Fruitless-scan backoff (v2.30.43): no new section this pass doubles
    // the wait before the NEXT non-urgent scan (30s, 1m, 2m ... capped at
    // 10 min); any progress clears it. The streak/backoff pair is only
    // written here, under the busy guard, so plain writes are fine.
    const int found_after = count_found();
    if (found_after > found_before) {
        g_k2_fruitless_streak = 0;
        g_k2_backoff_until    = 0;
    } else {
        if (g_k2_fruitless_streak < 30)   // stop shifting long past the cap
            ++g_k2_fruitless_streak;
        ULONGLONG wait_ms = 30000ull << (g_k2_fruitless_streak - 1);
        if (wait_ms > 600000ull) wait_ms = 600000ull;
        g_k2_backoff_until = GetTickCount64() + wait_ms;
    }

    char dbg[400];
    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
        "[FF7Access] kernel2 section scan: magic=%p item=%p weapon=%p command=%p "
        "armor=%p accessory=%p item_desc=%p mat_name=%p mat_desc=%p "
        "weap_desc=%p acc_desc=%p mg_desc=%p avs=%ld streak=%ld msig='%s' csig='%s'",
        g_k2.magic, g_k2.item, g_k2.weapon, g_k2.command,
        g_k2.armor, g_k2.accessory, g_k2.item_desc,
        g_k2.materia_name, g_k2.materia_desc,
        g_k2.weapon_desc, g_k2.accessory_desc, g_k2.magic_desc,
        g_k2_scan_avs, g_k2_fruitless_streak,
        g_k2_magic_sig, g_k2_command_sig);
    Log::Write(dbg);

    InterlockedExchange(&g_k2_scan_busy, 0);
}

// Decode entry `entry` of a kernel2 text section into `out`.
// Returns false (leaving generic-label fallback to the caller) when the
// section is missing, the entry is out of table bounds, or the text is
// empty/blank â€” never returns a wrong or garbage name.
static bool SectionEntryText(const uint8_t* base, uint32_t entry, std::wstring& out)
{
    if (!base || entry >= 0xE0)   // 0xE0 = the game's own entry-index guard
        return false;
    uint16_t tab_size;
    memcpy(&tab_size, base, sizeof(tab_size));
    if ((entry + 1) * 2 > tab_size)   // offset word must lie inside the table
        return false;
    uint16_t off;
    memcpy(&off, base + entry * 2, sizeof(off));
    // Sanity: strings live after the table; sections are a few KB at most.
    if (off < tab_size || off > 0x8000)
        return false;
    const uint8_t* text = base + off;
    // Limit break names begin with an F8+parameter colour code (2 bytes,
    // e.g. F8 02 "Braver").  The dialog decoder treats 0xF8 as a single-byte
    // button-icon token (correct for dialog), which would leave the colour
    // parameter byte to decode as a stray character â€” skip both here.
    if (text[0] == 0xF8)
        text += 2;
    if (text[0] == 0xFF)
        return false;
    out = FF7Text::Decode(reinterpret_cast<const char*>(text));
    for (wchar_t c : out)
        if (c != L' ')
            return true;
    return false;   // blank/whitespace-only entry (padding) â€” treat as no name
}

// Resolve (command_index, action_index) from the flash-message struct into the
// exact display name, replicating dispatcher sub_6D1CC0's branch table.
// Branch semantics derived by static disassembly and live-verified 2026-07-11
// (Ice / Potion / Machine Gun / Tentacle).  Returns false for commands with
// no flash text (branch 9) or any resolution failure.
static bool ResolveActionName(uint32_t cmd, uint32_t idx, std::wstring& out)
{
    if (cmd > FF7Addr::BATTLE_DISPATCH_MAX_CMD)
        return false;

    // v2.22.1: revalidate the cached section pointers at USE time â€” a
    // freed-and-reused section must fall back to generic labels, never
    // decode reused memory (see ValidatedSection / the lifetime note).
    const uint8_t* const k2_magic  = ValidatedSection(&g_k2.magic,  g_k2_magic_sig);
    const uint8_t* const k2_item   = ValidatedSection(&g_k2.item,   "Potion|Hi-Potion|");
    const uint8_t* const k2_weapon = ValidatedSection(&g_k2.weapon, "Buster Sword|");

    const uint8_t branch = *reinterpret_cast<const uint8_t*>(
        FF7Addr::BATTLE_DISPATCH_BYTE_TABLE + cmd);
    switch (branch) {
    case 0:   // section 0 (unused cmd 0x00)
    case 1:   // cmd 0x02 Magic: spell names are magic entries 0-55
        return SectionEntryText(k2_magic, idx, out);
    case 2:   // cmd 0x03 Summon.  The game uses the separate summon-attack-
              // name file for idx<16, but its heap copy has no locatable
              // signature; magic entries 56-71 hold the identical summon
              // names ('Choco/Mog'â€¦'Knights of Round', verified live), so
              // use those.  idx>=16 falls through to the magic file as the
              // game itself does.
        if (idx < 16)
            return SectionEntryText(k2_magic, idx + 56, out);
        return SectionEntryText(k2_magic, idx, out);
    case 3:   // cmd 0x04 Item
    case 5:   // cmd 0x08 (item variant)
        if (idx < 128)
            return SectionEntryText(k2_item, idx, out);
        if (idx < 256)   // thrown weapons share the item id space at 128+
            return SectionEntryText(k2_weapon, idx - 128, out);
        return false;    // armor/accessory ids never flash in battle
    case 4: { // cmd 0x07: the game composes this name into a fixed buffer
        const char* buf = reinterpret_cast<const char*>(0x00DC3640);
        if (static_cast<uint8_t>(buf[0]) == 0xFF || buf[0] == 0)
            return false;
        out = FF7Text::Decode(buf);
        return !out.empty();
    }
    case 6:   // cmd 0x0D Enemy Skill: magic entries 72-95 ('Frog Song'â€¦)
        return SectionEntryText(k2_magic, idx + 72, out);
    case 7:   // cmd 0x14 Limit Break: magic entries 128+ ('Braver'â€¦)
        // LIVE-VERIFIED 2026-08-04 (v2.30.76 probe, BOTH installs): the
        // flash idx IS the 0-based limit index (idx 0 -> entry 128
        // "Braver", idx 7 -> entry 135 "Big Shot", raw bytes vanilla on
        // 2013+7H and 2026 alike). The 2026-08-03 junk report was a stale
        // section copy passing the head-only re-check — closed by
        // SectionBodyPlausible, not by any change here.
        if (idx == 0x7F)   // the game's '????' sentinel for unnamed limits
            return false;
        return SectionEntryText(k2_magic, idx + 128, out);
    case 8: { // cmd 0x20 enemy attack: per-formation table from scene.bin
        if (idx >= 64)     // formation attack slots are small indices (0-31)
            return false;
        const char* entry = reinterpret_cast<const char*>(
            FF7Addr::ENEMY_ATTACK_NAME_TABLE + idx * FF7Addr::ENEMY_ATTACK_NAME_STRIDE);
        if (static_cast<uint8_t>(entry[0]) == 0xFF)
            return false;
        out = FF7Text::Decode(entry);
        for (wchar_t c : out)
            if (c != L' ')
                return true;
        return false;
    }
    default:  // branch 9 (Attack/Steal/â€¦ â€” no flash text) or unknown
        return false;
    }
}

// Generic command labels â€” the v2.5 fallback, used when no exact name exists
// (plain Attack, Steal) or resolution fails (non-English kernel2, timeouts).
static const wchar_t* GenericActionLabel(uint8_t command_id, wchar_t* buf, size_t buf_count)
{
    switch (command_id) {
    case 0x01: return L"Attack";
    case 0x02: return L"Magic";
    case 0x03: return L"Summon";
    case 0x04: return L"Item";
    case 0x06: return L"Steal";
    case 0x0D: return L"Enemy Skill";
    case 0x14: return L"Limit Break";
    case 0x20: return L"attacks";
    default:
        _snwprintf_s(buf, buf_count, _TRUNCATE, L"command %u",
                     static_cast<unsigned>(command_id));
        return buf;
    }
}

// ---------------------------------------------------------------------------
// Real enemy names for battle announcements (v2.10).
//
// Replicates get_kernel_text section 7 â€” the game's OWN target-name lookup,
// found by static disassembly of the section jump table at 0x419A38
// (investigate/ff7_target_name_disasm.py, 2026-07-13; details in
// ff7_addresses.h SECTION 1c3). Chain: formation slot table (u16 record
// index per enemy slot) -> loaded scene.bin enemy record (stride 0xB8,
// FF7-encoded name in bytes 0-0x1F) -> duplicate-type suffix, spoken as a
// 1-based NUMBER ("MP 1" / "MP 2") where the screen shows letters
// ("MP A" / "MP B"), so two same-type enemies stay distinguishable by ear.
//
// Returns false (caller keeps its generic label) when the slot is not an
// enemy, the formation slot is empty (record -1), the record index is
// outside the 3-record scene range (battle module not initialized), or the
// decoded name is blank.
// ---------------------------------------------------------------------------
static bool EnemySlotName(uint8_t slot, std::wstring& out)
{
    if (slot < 4 || slot > 9)
        return false;
    const uint32_t enemy_idx = slot - 4u;

    const int16_t record = *reinterpret_cast<const volatile int16_t*>(
        FF7Addr::BATTLE_FORMATION_SLOTS +
        enemy_idx * FF7Addr::BATTLE_FORMATION_SLOT_STRIDE);
    if (record < 0 ||
        record >= static_cast<int16_t>(FF7Addr::BATTLE_ENEMY_RECORD_COUNT))
        return false;

    // The name field may occupy all 0x20 bytes with NO 0xFF terminator, so
    // decode per byte under the length cap â€” the game itself copies at most
    // 0x20 bytes and then writes its own terminator (0x41999B). Decode()ing
    // the record in place could run past the name into stat bytes.
    const volatile uint8_t* name = reinterpret_cast<const volatile uint8_t*>(
        FF7Addr::BATTLE_ENEMY_RECORDS +
        static_cast<uint32_t>(record) * FF7Addr::BATTLE_ENEMY_RECORD_STRIDE);
    out.clear();
    for (uint32_t i = 0; i < FF7Addr::BATTLE_ENEMY_NAME_LEN; ++i) {
        const uint8_t b = name[i];
        if (b == 0xFF)
            break;
        const wchar_t c = FF7Text::DecodeChar(b);
        if (c != L'\0')
            out += c;
    }
    // Blank / whitespace-only = record not populated (stale zeroed BSS).
    if (out.find_first_not_of(L' ') == std::wstring::npos)
        return false;
    while (out.back() == L' ')   // non-empty here per the check above
        out.pop_back();

    // Duplicate-type suffix, indexed by ACTOR slot as in the game's code
    // ((idx+4)*0x44). 0xFF = this enemy type is unique in the formation;
    // the game renders base-char + index on SCREEN as letters (0='A',
    // 1='B', ...), but we SPEAK 1-based numbers ("MP 1" / "MP 2") because
    // digits are easier to tell apart by ear than letter names (v2.30.85).
    const uint8_t dup = *reinterpret_cast<const volatile uint8_t*>(
        FF7Addr::BATTLE_DUP_LETTER_TABLE +
        static_cast<uint32_t>(slot) * FF7Addr::BATTLE_DUP_LETTER_STRIDE);
    if (dup != 0xFF && dup < 26) {
        out += L' ';
        out += std::to_wstring(dup + 1);
    }
    return true;
}

// ---------------------------------------------------------------------------
// HP readout for target announcements (v2.11).
//
// Speaks "HP <current> of <max>" for the actor under the target cursor,
// with exact information parity to the sighted target window (see
// ff7_addresses.h SECTION 1c4): party slots always (their HP is always
// on-screen in battle), enemy slots only after Sense set their display
// flag. HP is read as the full i32 pair from the battle actor-vars struct
// (FFNx battle_actor_vars), NOT the game's u16 display words, so
// >65535-HP bosses can't truncate.
//
// Returns false (caller speaks the bare name) for non-actor slots,
// un-Sensed enemies, or implausible values (battle module mid-init).
// ---------------------------------------------------------------------------
static bool TargetHPText(uint8_t slot, std::wstring& out)
{
    bool show = false;
    if (slot <= 2) {
        show = true;
    } else if (slot >= 4 && slot <= 9) {
        // speak_enemy_hp_always (v2.12) overrides the Sense parity rule for
        // players who prefer full information over matching the screen.
        if (Config::Get().speak_enemy_hp_always) {
            show = true;
        } else {
            const uint8_t flags = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::BATTLE_SENSED_FLAG_TABLE +
                static_cast<uint32_t>(slot) * FF7Addr::BATTLE_DUP_LETTER_STRIDE);
            show = (flags & FF7Addr::BATTLE_SENSED_FLAG_BIT) != 0;
        }
    }
    if (!show)
        return false;

    const uint32_t base = FF7Addr::BATTLE_ACTOR_VARS +
        static_cast<uint32_t>(slot) * FF7Addr::BATTLE_ACTOR_VARS_STRIDE;
    const int32_t cur = *reinterpret_cast<const volatile int32_t*>(
        base + FF7Addr::BAVARS_OFF_CURRENT_HP);
    const int32_t max = *reinterpret_cast<const volatile int32_t*>(
        base + FF7Addr::BAVARS_OFF_MAX_HP);

    // Plausibility gate: max must be positive and current within [0, max].
    // 10,000,000 comfortably exceeds the biggest HP in the game (Ruby/
    // Emerald Weapon: 800k/1M) while rejecting uninitialized garbage.
    if (max <= 0 || max > 10000000 || cur < 0 || cur > max)
        return false;

    wchar_t buf[48];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"HP %d of %d",
                 static_cast<int>(cur), static_cast<int>(max));
    out = buf;
    return true;
}

// ---------------------------------------------------------------------------
// Party character names from the savemap (v2.19).
//
// Pre-v2.19 the battle threads could only name party slot 0 (PARTY_LEADER â†’
// hardcoded default names); slots 1-2 were positional "ally 2"/"ally 3" â€”
// the user's play test heard Barret announced as "ally 2" all through the
// reactor. The savemap has had everything needed all along (TODO.txt's
// party-KO entry predicted this): the three party-member character IDs at
// SAVEMAP_PARTY_IDS, and each character's LIVE name (renames included) in
// their character record. See ff7_addresses.h SECTION 1b for the layout
// derivation and the cross-check that guards it.
// ---------------------------------------------------------------------------

// Read character `char_id`'s current name from its savemap record.
// Returns false when the name is empty/undecodable (zeroed savemap before
// any save is loaded, or an ID with no record) â€” callers then fall back.
static bool SavemapCharName(uint8_t char_id, std::wstring& out)
{
    // Flashback aliases: Young Cloud (9) and Sephiroth (10) have no records
    // of their own â€” the game stores their data in Cait Sith's and Vincent's
    // record slots for the duration (community-documented savemap behavior).
    // Mapping them here means the Kalm flashback battles speak "Sephiroth"
    // (the game writes his name into record 7) instead of "ally 2".
    uint8_t rec = char_id;
    if (char_id == 9)  rec = 6;
    if (char_id == 10) rec = 7;
    if (rec > 8)
        return false;

    const uint8_t* name = reinterpret_cast<const uint8_t*>(
        FF7Addr::SAVEMAP_CHAR_RECORDS +
        rec * FF7Addr::SAVEMAP_CHAR_REC_SIZE +
        FF7Addr::SAVEMAP_CHAR_NAME_OFF);

    // Per-byte decode (FF7 encoding, 0xFF terminator, hard 12-byte cap) â€”
    // same approach as the name-entry echo; Decode() is dialog-oriented
    // (token expansion) and wrong for a fixed name field.
    std::wstring decoded;
    for (uint32_t i = 0; i < FF7Addr::SAVEMAP_CHAR_NAME_LEN && name[i] != 0xFF; ++i) {
        const wchar_t ch = FF7Text::DecodeChar(name[i]);
        if (ch != L'\0')
            decoded += ch;
    }

    // A zeroed record decodes to all spaces (byte 0x00 = ' ') â€” trim, and
    // treat an all-blank result as "no name" so defaults kick in.
    const std::wstring::size_type first = decoded.find_first_not_of(L' ');
    if (first == std::wstring::npos)
        return false;
    const std::wstring::size_type last = decoded.find_last_not_of(L' ');
    out = decoded.substr(first, last - first + 1);
    return true;
}

// FF7Text name provider (registered in InitThread): lets dialog speaker
// tokens ("Barret:") and inline name tokens speak the live savemap names.
static bool DialogNameProvider(int char_id, std::wstring& out)
{
    return char_id >= 0 && char_id <= 0xFF &&
           SavemapCharName(static_cast<uint8_t>(char_id), out);
}

// Spoken label for battle party slot 0-2, shared by the action announcer and
// the target announcer. Resolution order:
//   1. savemap party-member ID -> that character's live savemap name;
//   2. the default English name for the ID (savemap name blank â€” in practice
//      only before a save is loaded);
//   3. positional "ally N" (cross-check failed, empty slot, or unknown ID).
// The cross-check (slot 0's party ID must equal the live-proven PARTY_LEADER
// byte) validates the whole derived party array on every call: if the layout
// derivation were ever wrong for a build, players hear the OLD positional
// labels, never a wrong name. See ff7_addresses.h SECTION 1b.
static void PartySlotLabel(uint8_t slot, wchar_t* buf, size_t buf_count)
{
    const uint8_t leader_id =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::PARTY_LEADER);
    const uint8_t slot0_id =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::SAVEMAP_PARTY_IDS);
    const uint8_t char_id =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::SAVEMAP_PARTY_IDS + slot);

    if (slot <= 2 && slot0_id == leader_id && char_id != 0xFF) {
        std::wstring name;
        if (SavemapCharName(char_id, name)) {
            _snwprintf_s(buf, buf_count, _TRUNCATE, L"%ls", name.c_str());
            return;
        }
        const wchar_t* def = FF7Text::DefaultCharName(char_id);
        if (def) {
            _snwprintf_s(buf, buf_count, _TRUNCATE, L"%ls", def);
            return;
        }
    }

    _snwprintf_s(buf, buf_count, _TRUNCATE, L"ally %u",
                 static_cast<unsigned>(slot + 1u));
}

// ---------------------------------------------------------------------------
// ITEM menu TTS (v2.31, 2026-07-18). Addresses and their provenance: the
// ITEMMENU_* block in ff7_addresses.h (guided scan item_menu_scan_20260718_
// 114427 â€” every pass a single intersected candidate â€” plus the dispatcher
// disasm that supplies the which-screen gate). Inventory data comes straight
// from savemap items[320]; names/descriptions from the kernel2 sections.
// ---------------------------------------------------------------------------

// Savemap HP/MP readout for the use-on-whom pane, guarded by the same
// leader cross-check as PartySlotLabel (wrong layout -> no numbers spoken,
// never wrong numbers). Appends ", HP x of y, MP a of b" to `msg`.
static void AppendPartyHpMp(uint8_t slot, std::wstring& msg)
{
    const uint8_t leader_id =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::PARTY_LEADER);
    const uint8_t slot0_id =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::SAVEMAP_PARTY_IDS);
    const uint8_t char_id =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::SAVEMAP_PARTY_IDS + slot);
    if (slot > 2 || slot0_id != leader_id || char_id == 0xFF)
        return;
    uint8_t rec = char_id;
    if (char_id == 9)  rec = 6;   // flashback aliases, as SavemapCharName
    if (char_id == 10) rec = 7;
    if (rec > 8)
        return;
    const uint32_t base = FF7Addr::SAVEMAP_CHAR_RECORDS +
                          rec * FF7Addr::SAVEMAP_CHAR_REC_SIZE;
    const uint16_t hp    = *reinterpret_cast<const volatile uint16_t*>(
        base + FF7Addr::SAVEMAP_CHAR_HP_OFF);
    const uint16_t maxhp = *reinterpret_cast<const volatile uint16_t*>(
        base + FF7Addr::SAVEMAP_CHAR_MAXHP_OFF);
    const uint16_t mp    = *reinterpret_cast<const volatile uint16_t*>(
        base + FF7Addr::SAVEMAP_CHAR_MP_OFF);
    const uint16_t maxmp = *reinterpret_cast<const volatile uint16_t*>(
        base + FF7Addr::SAVEMAP_CHAR_MAXMP_OFF);
    if (maxhp == 0)   // zeroed savemap (no save loaded) â€” numbers meaningless
        return;
    wchar_t tail[64];
    _snwprintf_s(tail, _countof(tail), _TRUNCATE,
                 L", HP %u of %u, MP %u of %u",
                 static_cast<unsigned>(hp), static_cast<unsigned>(maxhp),
                 static_cast<unsigned>(mp), static_cast<unsigned>(maxmp));
    msg += tail;
}

// Name for one inventory word's id across the four kernel namespaces (the
// id-range split ResolveActionName already uses for thrown weapons, now
// with the armor/accessory sections added for menu use).
static bool InventoryEntryName(uint32_t id, std::wstring& out)
{
    if (id < 128)
        return SectionEntryText(
            ValidatedSection(&g_k2.item, "Potion|Hi-Potion|"), id, out);
    if (id < 256)
        return SectionEntryText(
            ValidatedSection(&g_k2.weapon, "Buster Sword|"), id - 128, out);
    if (id < 288)
        return SectionEntryText(
            ValidatedSection(&g_k2.armor, "Bronze Bangle|"), id - 256, out);
    if (id < 320)
        return SectionEntryText(
            ValidatedSection(&g_k2.accessory, "Power Wrist|"), id - 288, out);
    return false;
}

// ---------------------------------------------------------------------------
// SHOP menus (v2.30.28, 2026-07-26) + the G gil-announce key.
//
// Every address is static-derived from one offline disasm session
// (ff7_shop_static.py â€” provenance in ff7_addresses.h's SHOP block): the
// shop is its own top-level menu-module branch selected by GAME_MODE == 8,
// NOT a menu_subs_call_table screen, with a 7-state loop at 0x71AAA3 whose
// state variable, cursor widgets, catalog, and price table all fell out of
// the annotated dump. Shipped static-first with debug logging as the live
// verify â€” the same discipline as v2.32's FOCUS_MODE and v2.34's timer.
// ---------------------------------------------------------------------------

// Materia name / description via the kernel2 sections (heads ground-truthed
// from kernel2.bin â€” see the Kernel2Sections comment).
static bool MateriaName(uint8_t id, std::wstring& out)
{
    return SectionEntryText(
        ValidatedSection(&g_k2.materia_name, "MP Plus|HP Plus|"), id, out);
}

static bool MateriaDesc(uint8_t id, std::wstring& out)
{
    return SectionEntryText(
        ValidatedSection(&g_k2.materia_desc, "Increases MP capacity|"), id, out);
}

// Description for one inventory/gear id (the I key). Armor has no section:
// kernel2's armor descriptions are blank, so armor rows return false and
// the caller speaks its no-description line â€” same info a sighted player
// gets from the empty description bar.
static bool InventoryEntryDesc(uint32_t id, std::wstring& out)
{
    if (id < 128)
        return SectionEntryText(
            ValidatedSection(&g_k2.item_desc, "Restores HP by 100|"), id, out);
    if (id < 256)
        return SectionEntryText(
            ValidatedSection(&g_k2.weapon_desc, "Initial equipment|"), id - 128, out);
    if (id < 288)
        return false;   // armor: blank descriptions by ground truth
    if (id < 320)
        return SectionEntryText(
            ValidatedSectionBytes(&g_k2.accessory_desc, kAccessoryDescSig,
                                  sizeof(kAccessoryDescSig), "accessory desc"),
            id - 288, out);
    return false;
}

// How many of item `id` the party owns (savemap items[320], word = id|qty<<9;
// the game keeps one slot per id, but summing all matches costs nothing and
// survives any duplicate-slot state).
static uint32_t CountOwnedItems(uint32_t id)
{
    uint32_t total = 0;
    for (uint32_t i = 0; i < FF7Addr::SAVEMAP_ITEMS_COUNT; ++i) {
        const uint16_t w = *reinterpret_cast<const volatile uint16_t*>(
            FF7Addr::SAVEMAP_ITEMS + i * 2);
        if (w != 0xFFFF && (w & 0x1FF) == id)
            total += w >> 9;
    }
    return total;
}

// How many materia orbs of `id` sit in the inventory list (one slot = one
// orb). Equipped orbs live in the char records instead and are NOT counted
// here â€” this feeds the buy screen's "own N" hint, not the full Owned+
// Equipped split the sighted header shows.
static uint32_t CountOwnedMateria(uint8_t id)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < FF7Addr::SAVEMAP_MATERIA_COUNT; ++i) {
        const uint32_t w = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::SAVEMAP_MATERIA + i * 4);
        if (w != 0xFFFFFFFF && (w & 0xFF) == id)
            ++n;
    }
    return n;
}

// Read ware `idx` of shop `shop_id` from the static catalog. Returns false
// past the shop's ware count (or on an insane shop id â€” the catalog region
// is finite; 0x80 is far above the game's real shop count).
static bool ShopWare(uint32_t shop_id, uint32_t idx, int& type, uint32_t& id)
{
    if (shop_id >= 0x80 || idx >= 10)
        return false;
    const uint32_t rec = FF7Addr::SHOP_CATALOG +
                         shop_id * FF7Addr::SHOP_CATALOG_STRIDE;
    const uint16_t count = *reinterpret_cast<const uint16_t*>(rec + 2);
    if (idx >= count || count > 10)
        return false;
    type = *reinterpret_cast<const int16_t*>(rec + 4 + idx * 8);
    id   = *reinterpret_cast<const uint32_t*>(rec + 8 + idx * 8);
    return type == 0 || type == 1;
}

// Buy price via the shop's live price table ([SHOP_PRICE_TABLE_PTR]; items
// at id*4, materia at +0x600). Pointer-validated every read â€” it is a heap
// allocation, not a static (the ValidatedSection lesson applied to data).
static bool ShopBuyPrice(int type, uint32_t id, uint32_t& price)
{
    const uint32_t table = *reinterpret_cast<const volatile uint32_t*>(
        FF7Addr::SHOP_PRICE_TABLE_PTR);
    if (!table || !IsReadableSpan(reinterpret_cast<const void*>(table),
                                  FF7Addr::SHOP_PRICE_MATERIA_OFF + 96 * 4))
        return false;
    if (type == 0)
        price = *reinterpret_cast<const volatile uint32_t*>(
            table + (id & 0x1FF) * 4);
    else
        price = *reinterpret_cast<const volatile uint32_t*>(
            table + FF7Addr::SHOP_PRICE_MATERIA_OFF + (id & 0xFF) * 4);
    return true;
}

// Bit 0 of the kernel gear record's restriction word = cannot sell (the
// sell handler's own test at shop_loop+0x31BD). The four kernel data
// arrays are loaded to static BSS at startup, so plain reads are safe.
static bool ItemUnsellable(uint32_t id)
{
    uint32_t addr;
    if (id < 0x80)        addr = FF7Addr::KERNEL_ITEM_RESTRICT   + id * 0x1C;
    else if (id < 0x100)  addr = FF7Addr::KERNEL_WEAPON_RESTRICT + (id - 0x80) * 0x2C;
    else if (id < 0x120)  addr = FF7Addr::KERNEL_ARMOR_RESTRICT  + (id - 0x100) * 0x24;
    else if (id < 0x140)  addr = FF7Addr::KERNEL_ACCESS_RESTRICT + (id - 0x120) * 0x10;
    else return false;
    const uint16_t w = *reinterpret_cast<const volatile uint16_t*>(addr);
    return (w & 1) != 0;
}

// "<name>, <price> gil, own <N>" for one buy-list ware. Name falls back to
// a numbered label (non-English kernel2), price is omitted if the table
// pointer is not live â€” degraded, never wrong.
static bool ShopBuyLine(uint32_t shop_id, uint32_t idx, std::wstring& out)
{
    int type; uint32_t id;
    if (!ShopWare(shop_id, idx, type, id))
        return false;
    std::wstring name;
    wchar_t buf[64];
    if (type == 0) {
        if (!InventoryEntryName(id & 0x1FF, name)) {
            _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"item %u", id & 0x1FF);
            name = buf;
        }
    } else {
        if (!MateriaName(static_cast<uint8_t>(id & 0xFF), name)) {
            _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"materia %u", id & 0xFF);
            name = buf;
        }
        name += L" materia";
    }
    out = name;
    uint32_t price;
    if (ShopBuyPrice(type, id, price)) {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L", %lu gil",
                     static_cast<unsigned long>(price));
        out += buf;
    }
    const uint32_t owned = (type == 0)
        ? CountOwnedItems(id & 0x1FF)
        : CountOwnedMateria(static_cast<uint8_t>(id & 0xFF));
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L", own %lu",
                 static_cast<unsigned long>(owned));
    out += buf;
    return true;
}

// One sell-item row: "<name>, 4 owned, sells for <p> gil" / "Empty."
static void ShopSellItemLine(uint32_t idx, std::wstring& out)
{
    out.clear();
    if (idx >= FF7Addr::SAVEMAP_ITEMS_COUNT) {
        out = L"Empty";
        return;
    }
    const uint16_t w = *reinterpret_cast<const volatile uint16_t*>(
        FF7Addr::SAVEMAP_ITEMS + idx * 2);
    if (w == 0xFFFF) {
        out = L"Empty";
        return;
    }
    const uint32_t id  = w & 0x1FF;
    const uint32_t qty = w >> 9;
    wchar_t buf[64];
    if (!InventoryEntryName(id, out)) {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"item %lu",
                     static_cast<unsigned long>(id));
        out = buf;
    }
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L", %lu owned",
                 static_cast<unsigned long>(qty));
    out += buf;
    if (ItemUnsellable(id)) {
        out += L", can't sell";
        return;
    }
    uint32_t price;
    if (ShopBuyPrice(0, id, price)) {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L", sells for %lu gil",
                     static_cast<unsigned long>(price >> 1));
        out += buf;
    }
}

// One sell-materia row: "<name> materia, sells for <p> gil[, mastered]" /
// "Empty." Sell price = the game's get_materia_gil (0x71FCF9) replicated:
// AP field 0xFFFFFF (mastered) -> base price * 70, else the raw AP count
// ("Price through AP" on the sighted panel â€” screenshot-verified: Restore
// with 0 AP showed 0, and its master price 52500 = base 750 * 70).
static void ShopSellMateriaLine(uint32_t idx, std::wstring& out)
{
    out.clear();
    if (idx >= FF7Addr::SAVEMAP_MATERIA_COUNT) {
        out = L"Empty";
        return;
    }
    const uint32_t w = *reinterpret_cast<const volatile uint32_t*>(
        FF7Addr::SAVEMAP_MATERIA + idx * 4);
    if (w == 0xFFFFFFFF || (w & 0xFF) == 0xFF) {
        out = L"Empty";
        return;
    }
    const uint8_t  id = static_cast<uint8_t>(w & 0xFF);
    const uint32_t ap = w >> 8;
    wchar_t buf[64];
    if (!MateriaName(id, out)) {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"materia %u", id);
        out = buf;
    }
    out += L" materia";
    uint32_t base;
    const bool mastered = (ap == 0xFFFFFF);
    uint32_t sell = ap;
    if (ShopBuyPrice(1, id, base)) {
        if (base == 1)
            sell = 1;              // the game's unsellable-materia marker
        else if (mastered)
            sell = base * 70;
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L", sells for %lu gil",
                     static_cast<unsigned long>(sell));
        out += buf;
    } else if (!mastered) {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L", sells for %lu gil",
                     static_cast<unsigned long>(ap));
        out += buf;
    }
    if (mastered)
        out += L", mastered";
}

static DWORD WINAPI ShopMenuThread(LPVOID /*unused*/)
{
    bool     was_open   = false;
    uint32_t last_state = 0xFFFFFFFF;
    uint32_t last_bar   = 0xFFFFFFFF;   // Buy/Sell/Exit cursor
    uint32_t last_stype = 0xFFFFFFFF;   // Item/Materia sell-type cursor
    uint32_t last_idx   = 0xFFFFFFFF;   // list index in the active list state
    uint32_t last_word  = 0xFFFFFFFF;   // items/materia word under the cursor
                                        // (selling rewrites it in place)
    uint32_t last_qty   = 0xFFFFFFFF;
    bool     i_was_down = false;
    ULONGLONG next_scan_tick = 0;

    static const wchar_t* const kBar[3]   = { L"Buy", L"Sell", L"Exit" };
    static const wchar_t* const kSType[2] = { L"Item", L"Materia" };

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_menus) {
            was_open = false;
            continue;
        }

        const uint8_t game_mode = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::GAME_MODE);
        if (game_mode != FF7Addr::GAME_MODE_SHOP) {
            was_open = false;
            continue;
        }

        const uint32_t shop_id = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::SHOP_ID);
        const uint32_t state = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::SHOP_STATE);

        // Kernel2 sections are needed for every name â€” kick the scan early
        // (rate-limited) instead of waiting for the first battle.
        if ((!g_k2.item || !g_k2.materia_name) &&
            GetTickCount64() >= next_scan_tick) {
            next_scan_tick = GetTickCount64() + 3000;
            ScanKernel2Sections();
        }

        bool opened_this_tick = false;
        if (!was_open) {
            was_open   = true;
            opened_this_tick = true;
            last_state = 0xFFFFFFFF;   // force the state announce below
            last_bar   = last_stype = last_idx = last_qty = 0xFFFFFFFF;
            last_word  = 0xFFFFFFFF;
            i_was_down = true;         // swallow a held I across the open

            // "<Shop name>. <Greeting>" â€” both FF7-encoded statics in the
            // exe's own .data (catalog provenance in ff7_addresses.h).
            const uint32_t name_idx = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::SHOP_NAME_IDX);
            const uint32_t text_idx = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::SHOP_TEXT_IDX);
            std::wstring greet;
            if (name_idx < 32) {
                // Shop titles are packed 0x14 bytes apart and may use the
                // full width â€” copy out and force a terminator.
                char nbuf[0x15];
                memcpy(nbuf, reinterpret_cast<const void*>(
                    FF7Addr::SHOP_NAME_STRINGS + name_idx * 0x14), 0x14);
                nbuf[0x14] = static_cast<char>(0xFF);
                greet = FF7Text::Decode(nbuf);
                if (!greet.empty())
                    greet += L". ";
            }
            if (text_idx < 16)
                greet += FF7Text::Decode(reinterpret_cast<const char*>(
                    FF7Addr::SHOP_GREET_STRINGS + text_idx * 0x1CC));
            if (!greet.empty())
                TTS::Speak(greet.c_str(), /*interrupt=*/true);

            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] SHOP open: id=%lu name_idx=%lu text_idx=%lu state=%lu",
                static_cast<unsigned long>(shop_id),
                static_cast<unsigned long>(name_idx),
                static_cast<unsigned long>(text_idx),
                static_cast<unsigned long>(state));
            Log::Write(dbg);
        }

        // â”€â”€ Screen-state transitions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        const bool state_changed = (state != last_state);
        if (state_changed) {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] SHOP state %lu -> %lu",
                static_cast<unsigned long>(last_state),
                static_cast<unsigned long>(state));
            Log::Write(dbg);
            last_state = state;
            // Fresh screen: force the per-screen announcers below to speak
            // the current selection even if the cursor value didn't move.
            last_bar = last_stype = last_idx = last_qty = 0xFFFFFFFF;
            last_word = 0xFFFFFFFF;

            // Right after the shop-open greeting, QUEUE the screen intro
            // instead of interrupting it â€” the greeting is one sentence and
            // the intro should follow it, not clobber it.
            const bool intr = !opened_this_tick;
            switch (state) {
            case 0:  TTS::Speak(L"Buy, Sell, or Exit.", intr); break;
            case 6:  TTS::Speak(L"Sell Item or Materia.", intr); break;
            case 1: {
                const uint32_t gil = *reinterpret_cast<const volatile uint32_t*>(
                    FF7Addr::SAVEMAP_GIL);
                wchar_t msg[64];
                _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                             L"Buying. You have %lu gil.",
                             static_cast<unsigned long>(gil));
                TTS::Speak(msg, intr);
                break;
            }
            case 2:  TTS::Speak(L"Selling items.", intr); break;
            case 3:  TTS::Speak(L"Selling materia.", intr); break;
            case 4:
            case 5:  TTS::Speak(L"How many?", intr); break;
            default: break;   // unmapped value â€” logged above, stay quiet
            }
        }

        // â”€â”€ Per-screen cursor tracking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        switch (state) {
        case 0: {   // Buy / Sell / Exit bar
            const uint32_t bar = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::SHOP_BAR_CURSOR);
            if (bar != last_bar && bar < 3) {
                last_bar = bar;
                TTS::Speak(kBar[bar], !state_changed);
            }
            break;
        }
        case 6: {   // sell-type bar: Item / Materia
            const uint32_t st = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::SHOP_SELLTYPE_CURSOR);
            if (st != last_stype && st < 2) {
                last_stype = st;
                TTS::Speak(kSType[st], !state_changed);
            }
            break;
        }
        case 1: {   // buy list
            const uint32_t idx =
                *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_BUY_ROW) +
                *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_BUY_SCROLL);
            if (idx != last_idx && idx < 10) {
                last_idx = idx;
                std::wstring line;
                if (ShopBuyLine(shop_id, idx, line))
                    TTS::Speak(line.c_str(), !state_changed);
            }
            break;
        }
        case 2: {   // sell item list â€” idx formula from the confirm handler
            const uint32_t idx =
                *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLI_COL) +
                (*reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLI_ROW) +
                 *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLI_SCROLL)) * 2;
            const uint32_t word = (idx < FF7Addr::SAVEMAP_ITEMS_COUNT)
                ? *reinterpret_cast<const volatile uint16_t*>(
                      FF7Addr::SAVEMAP_ITEMS + idx * 2)
                : 0xFFFF;
            // Re-announce on slot change OR content change (a sale rewrites
            // the word in place while the cursor stays put).
            if (idx != last_idx || word != last_word) {
                last_idx  = idx;
                last_word = word;
                std::wstring line;
                ShopSellItemLine(idx, line);
                TTS::Speak(line.c_str(), !state_changed);
            }
            break;
        }
        case 3: {   // sell materia list
            const uint32_t idx =
                *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLM_ROW) +
                *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLM_SCROLL);
            const uint32_t word = (idx < FF7Addr::SAVEMAP_MATERIA_COUNT)
                ? *reinterpret_cast<const volatile uint32_t*>(
                      FF7Addr::SAVEMAP_MATERIA + idx * 4)
                : 0xFFFFFFFF;
            if (idx != last_idx || word != last_word) {
                last_idx  = idx;
                last_word = word;
                std::wstring line;
                ShopSellMateriaLine(idx, line);
                TTS::Speak(line.c_str(), !state_changed);
            }
            break;
        }
        case 4:     // buy quantity
        case 5: {   // sell-item quantity
            const uint32_t qty = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::SHOP_QTY);
            if (qty != last_qty && qty <= 99) {
                last_qty = qty;
                // Unit price of the ware/item the quantity applies to.
                uint32_t unit = 0;
                bool have_unit = false;
                if (state == 4) {
                    const uint32_t widx =
                        *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_BUY_ROW) +
                        *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_BUY_SCROLL);
                    int type; uint32_t id;
                    if (ShopWare(shop_id, widx, type, id))
                        have_unit = ShopBuyPrice(type, id, unit);
                } else {
                    const uint32_t iidx =
                        *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLI_COL) +
                        (*reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLI_ROW) +
                         *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLI_SCROLL)) * 2;
                    if (iidx < FF7Addr::SAVEMAP_ITEMS_COUNT) {
                        const uint16_t w = *reinterpret_cast<const volatile uint16_t*>(
                            FF7Addr::SAVEMAP_ITEMS + iidx * 2);
                        uint32_t buy;
                        if (w != 0xFFFF && ShopBuyPrice(0, w & 0x1FF, buy)) {
                            unit = buy >> 1;
                            have_unit = true;
                        }
                    }
                }
                wchar_t msg[64];
                if (have_unit)
                    _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                                 L"%lu, total %lu gil",
                                 static_cast<unsigned long>(qty),
                                 static_cast<unsigned long>(qty * unit));
                else
                    _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"%lu",
                                 static_cast<unsigned long>(qty));
                TTS::Speak(msg, !state_changed);
            }
            break;
        }
        default:
            break;
        }

        // â”€â”€ I key: description of the highlighted ware (FF4-scheme parity:
        // "I: In shop menus, reads description of highlighted item") â”€â”€â”€â”€â”€â”€
        DWORD fg_pid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &fg_pid);
        const bool focused = (fg_pid == GetCurrentProcessId());
        const bool i_down  = (GetAsyncKeyState('I') & 0x8000) != 0;
        // v2.30.42: the F8 settings menu owns I while open (same
        // stand-down rule as the pathfinder's whole key set).
        const bool i_edge  = focused && !SettingsMenu::IsOpen() &&
                             i_down && !i_was_down;
        i_was_down = i_down;
        if (i_edge) {
            std::wstring desc;
            bool have = false;
            if (state == 1 || state == 4) {
                const uint32_t widx =
                    *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_BUY_ROW) +
                    *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_BUY_SCROLL);
                int type; uint32_t id;
                if (ShopWare(shop_id, widx, type, id))
                    have = (type == 0)
                        ? InventoryEntryDesc(id & 0x1FF, desc)
                        : MateriaDesc(static_cast<uint8_t>(id & 0xFF), desc);
            } else if (state == 2 || state == 5) {
                const uint32_t iidx =
                    *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLI_COL) +
                    (*reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLI_ROW) +
                     *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLI_SCROLL)) * 2;
                if (iidx < FF7Addr::SAVEMAP_ITEMS_COUNT) {
                    const uint16_t w = *reinterpret_cast<const volatile uint16_t*>(
                        FF7Addr::SAVEMAP_ITEMS + iidx * 2);
                    if (w != 0xFFFF)
                        have = InventoryEntryDesc(w & 0x1FF, desc);
                }
            } else if (state == 3) {
                const uint32_t midx =
                    *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLM_ROW) +
                    *reinterpret_cast<const volatile uint32_t*>(FF7Addr::SHOP_SELLM_SCROLL);
                if (midx < FF7Addr::SAVEMAP_MATERIA_COUNT) {
                    const uint32_t w = *reinterpret_cast<const volatile uint32_t*>(
                        FF7Addr::SAVEMAP_MATERIA + midx * 4);
                    if (w != 0xFFFFFFFF && (w & 0xFF) != 0xFF)
                        have = MateriaDesc(static_cast<uint8_t>(w & 0xFF), desc);
                }
            }
            TTS::Speak(have ? desc.c_str() : L"No description", true);
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// MATERIA menu TTS (v2.30.33). All addresses static-derived in one session
// (provenance: ff7_addresses.h MATMENU block / ff7_materia_menu_static.py).
// Gate: MENU_OPEN + dispatch index 3 â€” the same shape as the Item (index 1)
// and Status (index 5) screens, with the same victory-screen and
// foreign-screen stand-downs. Mode semantics are static-derived; the mode
// change debug line is the live-confirm channel (the v2.32 FOCUS_MODE
// precedent).
// ---------------------------------------------------------------------------

// "<name> materia" (+ ", mastered") for one materia word; "Empty" for an
// empty slot/list entry.
static void MateriaWordLine(uint32_t w, std::wstring& out)
{
    out.clear();
    if (w == 0xFFFFFFFF || (w & 0xFF) == 0xFF) {
        out = L"Empty";
        return;
    }
    wchar_t buf[48];
    if (!MateriaName(static_cast<uint8_t>(w & 0xFF), out)) {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"materia %u",
                     static_cast<unsigned>(w & 0xFF));
        out = buf;
    }
    out += L" materia";
    if ((w >> 8) == 0xFFFFFF)
        out += L", mastered";
}

// Savemap record VA for a party slot (defined with the equip thread below,
// shared here since v2.30.79 -- see MateriaSlotWord).
static uint32_t CharRecFromPartySlot(uint32_t sel);

// The materia word under the equipment-slot cursor (modes 1 and 4). Returns
// false when the party-slot -> record resolution fails its layout check â€”
// the reader then speaks position-only, never wrong contents.
//
// v2.30.79: resolve the character via MATMENU_PARTY_SLOT -> SAVEMAP_PARTY_IDS,
// NOT via MATMENU_CHARREC_PTR. The pointer at 0xDCA810 is initialized to
// Cloud's record (0xDBFD8C) and the page-up/down character flip does NOT
// rewrite it -- it only receives a copy on paths this reader doesn't gate on.
// Result: every character's slots spoke CLOUD's equipped materia (2026-08-04
// play report). This is the exact bug class the equip screen had in v2.30.50
// (CHARSEL_CHOSEN vs EQMENU_PARTY_SLOT -- the "Barret wearing Bronze Bangle"
// report); the fix is the same shape: trust the live per-screen party-slot
// cursor, which this thread ALREADY reads to announce the character's name
// on a flip -- so name and contents now come from the same source and can
// never disagree.
static bool MateriaSlotWord(uint32_t row, uint32_t slot, uint32_t& w)
{
    const uint32_t party = *reinterpret_cast<const volatile uint32_t*>(
        FF7Addr::MATMENU_PARTY_SLOT);
    // CharRecFromPartySlot carries the leader cross-check + flashback-alias
    // mapping (ids 9/10 -> Cait Sith/Vincent records) and returns 0 when the
    // savemap layout check fails -- speak nothing wrong, ever.
    const uint32_t rec = CharRecFromPartySlot(party);
    if (rec == 0)
        return false;
    if (row > 1 || slot > 7)
        return false;
    const uint32_t off = (row == 0) ? FF7Addr::SAVEMAP_CHAR_WMATERIA_OFF
                                    : FF7Addr::SAVEMAP_CHAR_AMATERIA_OFF;
    w = *reinterpret_cast<const volatile uint32_t*>(rec + off + slot * 4);
    return true;
}

// "Weapon slot 3: Lightning materia" for the current slot cursor.
static void MateriaSlotLine(uint32_t row, uint32_t slot, std::wstring& out)
{
    wchar_t head[32];
    _snwprintf_s(head, _countof(head), _TRUNCATE, L"%ls slot %u: ",
                 row == 0 ? L"Weapon" : L"Armor",
                 static_cast<unsigned>(slot + 1));
    out = head;
    uint32_t w;
    std::wstring content;
    if (MateriaSlotWord(row, slot, w))
        MateriaWordLine(w, content);
    out += content;
}

static DWORD WINAPI MateriaMenuThread(LPVOID /*unused*/)
{
    bool     was_open   = false;
    uint32_t last_mode  = 0xFFFFFFFF;
    uint32_t last_key   = 0xFFFFFFFF;  // packed cursor identity per mode
    uint32_t last_word  = 0xFFFFFFFF;  // content under cursor (equip/remove
                                       // rewrites it while the cursor parks)
    uint32_t last_party = 0xFFFFFFFF;
    bool     i_was_down = false;
    ULONGLONG next_scan_tick = 0;

    static const wchar_t* const kBar[2]   = { L"Check", L"Arrange" };
    static const wchar_t* const kPopup[4] =
        { L"Arrange", L"Exchange", L"Remove all", L"Trash" };

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        // v2.30.37: GameOverTitleContext â€” the post-game-over title prompt
        // raises MENU_OPEN with EVERY menu byte below stale (incl. a stale
        // dispatch index that can equal this screen's) â€” stand down, the
        // v2.30.32 foreign-screen rule.
        if (!Config::Get().speak_menus || MenuModuleForeignScreen() ||
            GameOverTitleContext() || Hooks::TutorialActive()) {
            was_open = false;
            continue;
        }

        const int16_t field_id = *reinterpret_cast<const volatile int16_t*>(
            FF7Addr::FIELD_ID);
        const uint8_t menu_open = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::MENU_OPEN);
        const uint32_t screen = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::MENU_DISPATCH_INDEX);
        // v2.30.75: the victory-screen stand-down is GAME_MODE != 9 (the
        // results screens keep GAME_MODE=2 with MENU_OPEN=1 â€” 2026-08-03
        // handoff log). The old guard here was battle_end != 0, which was
        // a DEAD GATE: BATTLE_END_MODE rests at 5 between battles (it is
        // only 0 before the session's first battle and during the first
        // results screen), so after any battle this thread went silent
        // for the rest of the session â€” the "menu has issues after a
        // victory screen" report.
        const uint8_t game_mode = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::GAME_MODE);
        if (menu_open != 1 || field_id == 0 ||
            screen != FF7Addr::MATMENU_SCREEN_INDEX ||
            game_mode != FF7Addr::GAME_MODE_MAIN_MENU) {
            was_open = false;
            continue;
        }

        if ((!g_k2.materia_name) && GetTickCount64() >= next_scan_tick) {
            next_scan_tick = GetTickCount64() + 3000;
            ScanKernel2Sections();
        }

        const uint32_t mode = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::MATMENU_MODE);
        const uint32_t party = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::MATMENU_PARTY_SLOT);

        bool announce_context = false;
        if (!was_open) {
            was_open  = true;
            last_mode = 0xFFFFFFFF;
            last_key  = last_word = 0xFFFFFFFF;
            last_party = party;
            i_was_down = true;
            wchar_t who[32];
            PartySlotLabel(static_cast<uint8_t>(party <= 2 ? party : 0),
                           who, _countof(who));
            std::wstring msg = L"Materia. ";
            msg += who;
            TTS::Speak(msg.c_str(), true);
            announce_context = true;
        } else if (party != last_party && party <= 2) {
            // Page-up/down flips characters in place â€” re-announce whose
            // materia we're now looking at.
            last_party = party;
            wchar_t who[32];
            PartySlotLabel(static_cast<uint8_t>(party), who, _countof(who));
            TTS::Speak(who, true);
            last_key = last_word = 0xFFFFFFFF;   // re-announce the cursor line
            announce_context = true;   // v2.30.51: the re-announce must
                                       // QUEUE behind the name (see equip)
        }

        if (mode != last_mode) {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] MATERIA mode %lu -> %lu",
                static_cast<unsigned long>(last_mode),
                static_cast<unsigned long>(mode));
            Log::Write(dbg);
            last_mode = mode;
            last_key  = last_word = 0xFFFFFFFF;
            switch (mode) {
            case 3:  TTS::Speak(L"Choose materia.", !announce_context); break;
            case 4:  TTS::Speak(L"Check.", !announce_context); break;
            case 9:
            case 10: TTS::Speak(L"Choose materia.", !announce_context); break;
            default: break;   // 0/1 announce via their cursor lines below;
                              // 5/6/7 transient; others logged above
            }
        }

        // â”€â”€ Per-mode cursor tracking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        std::wstring line;
        uint32_t key  = 0xFFFFFFFF;
        uint32_t word = 0;
        bool     have = false;

        switch (mode) {
        case 0: {   // Check / Arrange bar
            const uint32_t bar = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::MATMENU_BAR_CURSOR);
            if (bar < 2) {
                key  = bar;
                line = kBar[bar];
                have = true;
            }
            break;
        }
        case 1:     // equipment slots (live cursor globals)
        case 4: {   // Check mode (widget col/row)
            uint32_t row, slot;
            if (mode == 1) {
                row  = *reinterpret_cast<const volatile uint32_t*>(
                    FF7Addr::MATMENU_SLOT_ROW);
                slot = *reinterpret_cast<const volatile uint32_t*>(
                    FF7Addr::MATMENU_SLOT_IDX);
            } else {
                row  = *reinterpret_cast<const volatile uint32_t*>(
                    FF7Addr::MATMENU_CHECK_ROW);
                slot = *reinterpret_cast<const volatile uint32_t*>(
                    FF7Addr::MATMENU_CHECK_COL);
            }
            if (row <= 1 && slot <= 7) {
                key = (row << 8) | slot;
                MateriaSlotWord(row, slot, word);
                MateriaSlotLine(row, slot, line);
                have = true;
            }
            break;
        }
        case 3: {   // equip list over materia[200]
            const uint32_t idx =
                *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MATMENU_EQUIP_ROW) +
                *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MATMENU_EQUIP_SCROLL);
            if (idx < FF7Addr::SAVEMAP_MATERIA_COUNT) {
                key  = idx;
                word = *reinterpret_cast<const volatile uint32_t*>(
                    FF7Addr::SAVEMAP_MATERIA + idx * 4);
                MateriaWordLine(word, line);
                have = true;
            }
            break;
        }
        case 9:
        case 10: {  // arrange-mode list phases
            const uint32_t idx =
                *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MATMENU_ARR_ROW) +
                *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MATMENU_ARR_SCROLL);
            if (idx < FF7Addr::SAVEMAP_MATERIA_COUNT) {
                key  = idx;
                word = *reinterpret_cast<const volatile uint32_t*>(
                    FF7Addr::SAVEMAP_MATERIA + idx * 4);
                MateriaWordLine(word, line);
                have = true;
            }
            break;
        }
        case 8: {   // Arrange popup
            const uint32_t rowp = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::MATMENU_POPUP_ROW);
            if (rowp < 4) {
                key  = rowp;
                line = kPopup[rowp];
                have = true;
            }
            break;
        }
        default:
            break;
        }

        // Announce on cursor movement OR content change under a parked
        // cursor (equipping/removing rewrites the slot/list word in place).
        if (have && (key != last_key || word != last_word)) {
            last_key  = key;
            last_word = word;
            TTS::Speak(line.c_str(), /*interrupt=*/!announce_context);
        }

        // â”€â”€ I key: description + AP of the highlighted materia â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        DWORD fg_pid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &fg_pid);
        const bool focused = (fg_pid == GetCurrentProcessId());
        const bool i_down  = (GetAsyncKeyState('I') & 0x8000) != 0;
        // v2.30.42: the F8 settings menu owns I while open (same
        // stand-down rule as the pathfinder's whole key set).
        const bool i_edge  = focused && !SettingsMenu::IsOpen() &&
                             i_down && !i_was_down;
        i_was_down = i_down;
        if (i_edge) {
            uint32_t w = 0xFFFFFFFF;
            if (mode == 1 || mode == 4) {
                const uint32_t row = *reinterpret_cast<const volatile uint32_t*>(
                    mode == 1 ? FF7Addr::MATMENU_SLOT_ROW : FF7Addr::MATMENU_CHECK_ROW);
                const uint32_t slot = *reinterpret_cast<const volatile uint32_t*>(
                    mode == 1 ? FF7Addr::MATMENU_SLOT_IDX : FF7Addr::MATMENU_CHECK_COL);
                MateriaSlotWord(row, slot, w);
            } else if (mode == 3 || mode == 9 || mode == 10) {
                const uint32_t idx = (mode == 3)
                    ? *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MATMENU_EQUIP_ROW) +
                      *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MATMENU_EQUIP_SCROLL)
                    : *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MATMENU_ARR_ROW) +
                      *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MATMENU_ARR_SCROLL);
                if (idx < FF7Addr::SAVEMAP_MATERIA_COUNT)
                    w = *reinterpret_cast<const volatile uint32_t*>(
                        FF7Addr::SAVEMAP_MATERIA + idx * 4);
            }
            std::wstring msg;
            if (w != 0xFFFFFFFF && (w & 0xFF) != 0xFF) {
                std::wstring desc;
                if (MateriaDesc(static_cast<uint8_t>(w & 0xFF), desc))
                    msg = desc;
                const uint32_t ap = w >> 8;
                wchar_t buf[48];
                if (ap == 0xFFFFFF) {
                    msg += msg.empty() ? L"Mastered" : L". Mastered";
                } else {
                    _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                                 L"%lsAP %lu",
                                 msg.empty() ? L"" : L". ",
                                 static_cast<unsigned long>(ap));
                    msg += buf;
                }
            }
            TTS::Speak(msg.empty() ? L"No description" : msg.c_str(), true);
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// EQUIP menu TTS (v2.30.34). All state static-derived (ff7_addresses.h
// EQMENU block / ff7_equip_menu_static.py) â€” the item/status/materia gate
// shape. Speaks the three category rows with their equipped gear, the
// candidate list by name, and I = gear description. Stat deltas (the
// Attack 14 -> 16 compare pane) are a documented residual: they need the
// menu's computed-stats scratch, not yet hunted.
// ---------------------------------------------------------------------------

// Savemap record VA for the character the char-select pane committed
// (CHARSEL_CHOSEN party slot), with the same leader/alias guards as
// AppendPartyHpMp. 0 = layout check failed (speak nothing wrong).
// v2.30.50: takes the party slot EXPLICITLY. The equip thread used to
// route through CHARSEL_CHOSEN here, but the equip screen's live
// character is EQMENU_PARTY_SLOT (the L1/R1 cycler) — CHARSEL only
// receives a copy on specific key paths, so gear names could describe
// the PRE-FLIP character (the Barret "Bronze Bangle" report's second
// bug, hidden behind the category-cursor one).
static uint32_t CharRecFromPartySlot(uint32_t sel)
{
    if (sel > 2)
        return 0;
    const uint8_t leader_id =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::PARTY_LEADER);
    const uint8_t slot0_id =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::SAVEMAP_PARTY_IDS);
    const uint8_t char_id =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::SAVEMAP_PARTY_IDS + sel);
    if (slot0_id != leader_id || char_id == 0xFF)
        return 0;
    uint8_t rec = char_id;
    if (char_id == 9)  rec = 6;
    if (char_id == 10) rec = 7;
    if (rec > 8)
        return 0;
    return FF7Addr::SAVEMAP_CHAR_RECORDS + rec * FF7Addr::SAVEMAP_CHAR_REC_SIZE;
}

// "Weapon: Gatling Gun" for one equip category row (0/1/2), from the
// record's equipment id bytes. Gear id namespaces per v2.31's inventory
// split: weapons 128+, armor 256+, accessories 288+ (0xFF byte = none).
static void EquipCategoryLine(uint32_t cat, uint32_t slot, std::wstring& out)
{
    static const wchar_t* const kCat[3] = { L"Weapon", L"Armor", L"Accessory" };
    out = kCat[cat < 3 ? cat : 0];
    out += L": ";
    const uint32_t rec = CharRecFromPartySlot(slot);
    if (!rec)
        return;
    static const uint32_t kOff[3]  = { FF7Addr::SAVEMAP_CHAR_WEAPON_OFF,
                                       FF7Addr::SAVEMAP_CHAR_ARMOR_OFF,
                                       FF7Addr::SAVEMAP_CHAR_ACCESS_OFF };
    static const uint32_t kBase[3] = { 128, 256, 288 };
    const uint8_t id = *reinterpret_cast<const volatile uint8_t*>(
        rec + kOff[cat < 3 ? cat : 0]);
    if (id == 0xFF) {
        out += L"nothing equipped";
        return;
    }
    std::wstring name;
    if (InventoryEntryName(kBase[cat < 3 ? cat : 0] + id, name))
        out += name;
    else {
        wchar_t buf[32];
        _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"gear %u",
                     static_cast<unsigned>(id));
        out += buf;
    }
}

// Candidate gear id (full 0-319 namespace) under the equip list cursor.
// Returns false past the candidate count or on the 0xFF terminator.
static bool EquipListCandidate(uint32_t cat, uint32_t& full_id)
{
    const uint32_t idx =
        *reinterpret_cast<const volatile uint32_t*>(FF7Addr::EQMENU_LIST_ROW) +
        *reinterpret_cast<const volatile uint32_t*>(FF7Addr::EQMENU_LIST_SCROLL);
    const uint32_t count = *reinterpret_cast<const volatile uint32_t*>(
        FF7Addr::EQMENU_LIST_COUNT);
    if (cat > 2 || idx >= count || idx >= 64)
        return false;
    const uint8_t b = *reinterpret_cast<const volatile uint8_t*>(
        FF7Addr::EQMENU_LIST_BYTES + idx);
    if (b == 0xFF)
        return false;
    static const uint32_t kBase[3] = { 128, 256, 288 };
    full_id = kBase[cat] + b;
    return true;
}

static DWORD WINAPI EquipMenuThread(LPVOID /*unused*/)
{
    bool     was_open  = false;
    uint32_t last_cat  = 0xFFFFFFFF;
    uint32_t last_pane = 0xFFFFFFFF;
    uint32_t last_idx  = 0xFFFFFFFF;
    uint32_t last_gear = 0xFFFFFFFF;  // equipped id under the category row
                                      // (equipping rewrites it in place)
    uint32_t last_sel  = 0xFFFFFFFF;  // character (char-flip re-announce)
    bool     i_was_down = false;
    ULONGLONG next_scan_tick = 0;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        // v2.30.37: GameOverTitleContext â€” stale menu bytes on the
        // post-game-over title prompt; see MateriaMenuThread's gate.
        if (!Config::Get().speak_menus || MenuModuleForeignScreen() ||
            GameOverTitleContext() || Hooks::TutorialActive()) {
            was_open = false;
            continue;
        }
        const int16_t field_id = *reinterpret_cast<const volatile int16_t*>(
            FF7Addr::FIELD_ID);
        const uint8_t menu_open = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::MENU_OPEN);
        const uint32_t screen = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::MENU_DISPATCH_INDEX);
        // v2.30.75: GAME_MODE==9 replaces the battle_end != 0 victory
        // guard â€” that byte rests at 5 between battles, which dead-gated
        // this thread after the session's first battle (see the materia
        // gate comment for the full derivation).
        const uint8_t game_mode = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::GAME_MODE);
        if (menu_open != 1 || field_id == 0 ||
            game_mode != FF7Addr::GAME_MODE_MAIN_MENU ||
            (screen != FF7Addr::EQMENU_SCREEN_INDEX && screen != 15)) {
            was_open = false;
            continue;
        }

        if ((!g_k2.weapon || !g_k2.armor) && GetTickCount64() >= next_scan_tick) {
            next_scan_tick = GetTickCount64() + 3000;
            ScanKernel2Sections();
        }

        const uint32_t cat = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::EQMENU_CATEGORY);
        const uint32_t pane = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::EQMENU_LIST_OPEN);
        // v2.30.50: the screen's live character is its own party-slot
        // cycler, not CHARSEL_CHOSEN (see EQMENU_PARTY_SLOT provenance).
        const uint32_t sel = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::EQMENU_PARTY_SLOT);

        bool fresh = false;
        if (!was_open) {
            was_open = true;
            fresh = true;
            last_cat = last_pane = last_idx = last_gear = 0xFFFFFFFF;
            last_sel = sel;
            i_was_down = true;
            wchar_t who[32];
            PartySlotLabel(static_cast<uint8_t>(sel <= 2 ? sel : 0),
                           who, _countof(who));
            std::wstring msg = L"Equip. ";
            msg += who;
            TTS::Speak(msg.c_str(), true);
        } else if (sel != last_sel && sel <= 2) {
            last_sel = sel;
            wchar_t who[32];
            PartySlotLabel(static_cast<uint8_t>(sel), who, _countof(who));
            TTS::Speak(who, true);
            last_cat = last_idx = last_gear = 0xFFFFFFFF;
            // v2.30.51: the row re-announce this reset triggers lands in
            // the SAME poll — it must QUEUE behind the name or it cuts it
            // off after a syllable (user report: L1/R1 spoke only the
            // gear). fresh is exactly the "queue the follow-up" flag the
            // entry path already uses.
            fresh = true;
        }

        if (pane != last_pane) {
            char dbg[80];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] EQUIP pane %lu -> %lu (cat=%lu)",
                static_cast<unsigned long>(last_pane),
                static_cast<unsigned long>(pane),
                static_cast<unsigned long>(cat));
            Log::Write(dbg);
            last_pane = pane;
            last_cat = last_idx = last_gear = 0xFFFFFFFF;
        }

        if (pane == 0) {
            // Category rows: announce on row move OR when the equipped id
            // under the parked cursor changes (an equip just committed).
            uint32_t gear = 0xFFFFFFFE;
            const uint32_t rec = CharRecFromPartySlot(sel);
            if (rec && cat < 3) {
                static const uint32_t kOff[3] = {
                    FF7Addr::SAVEMAP_CHAR_WEAPON_OFF,
                    FF7Addr::SAVEMAP_CHAR_ARMOR_OFF,
                    FF7Addr::SAVEMAP_CHAR_ACCESS_OFF };
                gear = *reinterpret_cast<const volatile uint8_t*>(rec + kOff[cat]);
            }
            if (cat < 3 && (cat != last_cat || gear != last_gear)) {
                last_cat  = cat;
                last_gear = gear;
                std::wstring line;
                EquipCategoryLine(cat, sel, line);
                TTS::Speak(line.c_str(), !fresh);
            }
        } else {
            // Candidate list.
            const uint32_t idx =
                *reinterpret_cast<const volatile uint32_t*>(FF7Addr::EQMENU_LIST_ROW) +
                *reinterpret_cast<const volatile uint32_t*>(FF7Addr::EQMENU_LIST_SCROLL);
            if (idx != last_idx) {
                last_idx = idx;
                uint32_t full_id;
                std::wstring line;
                if (EquipListCandidate(cat, full_id)) {
                    if (!InventoryEntryName(full_id, line)) {
                        wchar_t buf[32];
                        _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                                     L"gear %lu", static_cast<unsigned long>(full_id));
                        line = buf;
                    }
                } else {
                    line = L"Empty";
                }
                TTS::Speak(line.c_str(), true);
            }
        }

        // I key: description of the highlighted gear (list) or the
        // equipped gear (category rows).
        DWORD fg_pid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &fg_pid);
        const bool focused = (fg_pid == GetCurrentProcessId());
        const bool i_down  = (GetAsyncKeyState('I') & 0x8000) != 0;
        // v2.30.42: the F8 settings menu owns I while open (same
        // stand-down rule as the pathfinder's whole key set).
        const bool i_edge  = focused && !SettingsMenu::IsOpen() &&
                             i_down && !i_was_down;
        i_was_down = i_down;
        if (i_edge) {
            uint32_t full_id = 0xFFFFFFFF;
            if (pane == 1) {
                EquipListCandidate(cat, full_id);
            } else {
                const uint32_t rec = CharRecFromPartySlot(sel);
                if (rec && cat < 3) {
                    static const uint32_t kOff[3] = {
                        FF7Addr::SAVEMAP_CHAR_WEAPON_OFF,
                        FF7Addr::SAVEMAP_CHAR_ARMOR_OFF,
                        FF7Addr::SAVEMAP_CHAR_ACCESS_OFF };
                    static const uint32_t kBase[3] = { 128, 256, 288 };
                    const uint8_t id = *reinterpret_cast<const volatile uint8_t*>(
                        rec + kOff[cat]);
                    if (id != 0xFF)
                        full_id = kBase[cat] + id;
                }
            }
            std::wstring desc;
            const bool have = full_id != 0xFFFFFFFF &&
                              InventoryEntryDesc(full_id, desc);
            TTS::Speak(have ? desc.c_str() : L"No description", true);
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// LIMIT menu TTS (v2.30.35). Provenance: ff7_addresses.h LIMITMENU block.
// Set/Check bar + the 2x2 LEVEL grid, with each level announced together
// with the technique names the character has LEARNED at that level (the
// exact information the sighted grid shows â€” unlearned levels read as
// "not learned"). Grid tracking is deliberately mode-agnostic: both grid
// instances are watched every poll, so the static mode-value guesses
// can't silence a pane (the debug log settles the real mapping).
// ---------------------------------------------------------------------------

// Savemap record + kernel limit-name block for the limit menu's party
// slot. The kernel's limit blocks swap Aeris/Tifa relative to savemap
// record order (kernel2 ground truth â€” see the header comment).
static bool LimitCharInfo(uint32_t party_slot, uint32_t& rec_va, uint32_t& block)
{
    if (party_slot > 2)
        return false;
    const uint8_t char_id = *reinterpret_cast<const volatile uint8_t*>(
        FF7Addr::SAVEMAP_PARTY_IDS + party_slot);
    if (char_id == 0xFF)
        return false;
    uint8_t rec = char_id;
    if (char_id == 9)  rec = 6;
    if (char_id == 10) rec = 7;
    if (rec > 8)
        return false;
    rec_va = FF7Addr::SAVEMAP_CHAR_RECORDS + rec * FF7Addr::SAVEMAP_CHAR_REC_SIZE;
    block  = (rec == 2) ? 3u : (rec == 3) ? 2u : rec;   // the Aeris/Tifa swap
    return true;
}

// "Level 2: Blade Beam, Climhazzard" / "Level 4: not learned" for one
// grid position (level = row*2 + col, 0-based internally).
static void LimitLevelLine(uint32_t party_slot, uint32_t level, std::wstring& out)
{
    wchar_t head[24];
    _snwprintf_s(head, _countof(head), _TRUNCATE, L"Level %u: ",
                 static_cast<unsigned>(level + 1));
    out = head;
    uint32_t rec, block;
    if (!LimitCharInfo(party_slot, rec, block) || level > 3) {
        out += L"unknown";
        return;
    }
    const uint16_t bits = *reinterpret_cast<const volatile uint16_t*>(
        rec + FF7Addr::SAVEMAP_CHAR_LIMITBITS_OFF);
    const uint32_t techs = (level < 3) ? 2u : 1u;
    bool any = false;
    for (uint32_t t = 0; t < techs; ++t) {
        if (!(bits & (1u << (level * 3 + t))))
            continue;
        const uint32_t name_idx = 128 + block * 7 +
                                  ((level < 3) ? level * 2 + t : 6u);
        std::wstring name;
        if (SectionEntryText(ValidatedSection(&g_k2.magic, g_k2_magic_sig),
                             name_idx, name)) {
            if (any)
                out += L", ";
            out += name;
            any = true;
        }
    }
    if (!any)
        out += L"not learned";
}

static DWORD WINAPI LimitMenuThread(LPVOID /*unused*/)
{
    bool     was_open  = false;
    uint32_t last_mode = 0xFFFFFFFF;
    uint32_t last_bar  = 0xFFFFFFFF;
    uint32_t last_setg = 0xFFFFFFFF;   // packed col|row<<8
    uint32_t last_chkg = 0xFFFFFFFF;
    uint32_t last_slot = 0xFFFFFFFF;
    ULONGLONG next_scan_tick = 0;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        // v2.30.37: GameOverTitleContext â€” stale menu bytes on the
        // post-game-over title prompt; see MateriaMenuThread's gate.
        if (!Config::Get().speak_menus || MenuModuleForeignScreen() ||
            GameOverTitleContext() || Hooks::TutorialActive()) {
            was_open = false;
            continue;
        }
        const int16_t field_id = *reinterpret_cast<const volatile int16_t*>(
            FF7Addr::FIELD_ID);
        const uint8_t menu_open = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::MENU_OPEN);
        const uint32_t screen = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::MENU_DISPATCH_INDEX);
        // v2.30.75: GAME_MODE==9 replaces the battle_end != 0 victory
        // guard â€” that byte rests at 5 between battles, which dead-gated
        // this thread after the session's first battle (see the materia
        // gate comment for the full derivation).
        const uint8_t game_mode = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::GAME_MODE);
        if (menu_open != 1 || field_id == 0 ||
            game_mode != FF7Addr::GAME_MODE_MAIN_MENU ||
            screen != FF7Addr::LIMITMENU_SCREEN_INDEX) {
            was_open = false;
            continue;
        }

        if (!g_k2.magic && GetTickCount64() >= next_scan_tick) {
            next_scan_tick = GetTickCount64() + 3000;
            ScanKernel2Sections();
        }

        const uint32_t mode = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::LIMITMENU_MODE);
        const uint32_t slot = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::LIMITMENU_PARTY_SLOT);

        bool fresh = false;
        if (!was_open) {
            was_open = true;
            fresh = true;
            last_mode = last_bar = last_setg = last_chkg = 0xFFFFFFFF;
            last_slot = slot;
            wchar_t who[32];
            PartySlotLabel(static_cast<uint8_t>(slot <= 2 ? slot : 0),
                           who, _countof(who));
            std::wstring msg = L"Limit. ";
            msg += who;
            uint32_t rec, block;
            if (LimitCharInfo(slot <= 2 ? slot : 0, rec, block)) {
                const uint8_t lvl = *reinterpret_cast<const volatile uint8_t*>(
                    rec + FF7Addr::SAVEMAP_CHAR_LIMITLVL_OFF);
                if (lvl >= 1 && lvl <= 4) {
                    wchar_t buf[32];
                    _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                                 L". Limit level %u", static_cast<unsigned>(lvl));
                    msg += buf;
                }
            }
            TTS::Speak(msg.c_str(), true);
        } else if (slot != last_slot && slot <= 2) {
            last_slot = slot;
            wchar_t who[32];
            PartySlotLabel(static_cast<uint8_t>(slot), who, _countof(who));
            TTS::Speak(who, true);
            last_bar = last_setg = last_chkg = 0xFFFFFFFF;
            fresh = true;   // v2.30.51: queue the follow-up (see equip)
        }

        if (mode != last_mode) {
            char dbg[80];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] LIMIT mode %lu -> %lu",
                static_cast<unsigned long>(last_mode),
                static_cast<unsigned long>(mode));
            Log::Write(dbg);
            last_mode = mode;
            last_bar = last_setg = last_chkg = 0xFFFFFFFF;
        }

        if (mode == 0) {
            const uint32_t bar = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::LIMITMENU_BAR_CURSOR);
            if (bar < 2 && bar != last_bar) {
                last_bar = bar;
                TTS::Speak(bar == 0 ? L"Set" : L"Check", !fresh);
            }
        } else {
            // Mode-agnostic grid tracking: whichever grid instance moves
            // is the live one (the two never move in the same poll â€”
            // only one pane has focus).
            const uint32_t sc = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::LIMITMENU_SETG_COL);
            const uint32_t sr = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::LIMITMENU_SETG_ROW);
            const uint32_t cc = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::LIMITMENU_CHKG_COL);
            const uint32_t cr = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::LIMITMENU_CHKG_ROW);
            const uint32_t setg = (sc <= 1 && sr <= 1) ? (sc | (sr << 8)) : 0xFFFFFFFF;
            const uint32_t chkg = (cc <= 1 && cr <= 1) ? (cc | (cr << 8)) : 0xFFFFFFFF;
            uint32_t level = 0xFFFFFFFF;
            if (setg != 0xFFFFFFFF &&
                (last_setg == 0xFFFFFFFF || setg != last_setg))
                level = sr * 2 + sc;
            else if (chkg != 0xFFFFFFFF && chkg != last_chkg &&
                     last_chkg != 0xFFFFFFFF)
                level = cr * 2 + cc;
            if (setg != last_setg || chkg != last_chkg) {
                const bool first_grid_poll =
                    (last_setg == 0xFFFFFFFF && last_chkg == 0xFFFFFFFF);
                last_setg = setg;
                last_chkg = chkg;
                if (level != 0xFFFFFFFF || first_grid_poll) {
                    if (level == 0xFFFFFFFF && setg != 0xFFFFFFFF)
                        level = sr * 2 + sc;   // fresh pane: speak Set grid
                    if (level != 0xFFFFFFFF) {
                        std::wstring line;
                        LimitLevelLine(slot <= 2 ? slot : 0, level, line);
                        // v2.30.51: !fresh so a slot-flip's grid
                        // re-announce queues behind the name.
                        TTS::Speak(line.c_str(), !fresh);
                    }
                }
            }
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// MAGIC menu polling thread (v2.30.48) — the out-of-battle spell list, the
// last main-menu screen besides PHS with no narration (user report
// 2026-08-01: players read the silence as "no spells").
//
// EVERYTHING here is the static session's derivation (ff7_magic_menu_static
// .py; constants + full provenance in ff7_addresses.h MAGICMENU block):
// the menu's spell list IS battle's per-slot magic list
// (BATTLE_CHAR_BLOCK + slot*0x440 + BCHAR_OFF_MAGIC_LIST, stride 8, u8 id,
// 0xFF empty), the cursor is a standard 3-column list widget, and the
// grayed "battle only" state is the renderer's own byte table at
// MAGIC_MENU_USABLE_TABLE — we read the SAME table it draws from, so the
// spoken state cannot disagree with the visible gray.
//
// Names come from the kernel2 magic section through the v2.30.47
// retranslation-tolerant signature, so spells speak correctly under 7th
// Heaven text mods too (the report that exposed this screen's absence).
//
// v1 RESIDUALS (TODO [MAGICMENU]): I-key descriptions (needs a kernel2
// magic-description section signature), MP cost readout, the Summon /
// Enemy Skill top-bar tabs (their widgets are unmapped — log-only for
// now), and pane-1 target semantics (least-proven static piece: spoken,
// but flagged for live verify).
// ---------------------------------------------------------------------------
static DWORD WINAPI MagicMenuThread(LPVOID /*unused*/)
{
    bool      was_open   = false;
    uint32_t  last_sel   = 0xFFFFFFFF;   // packed col|((row+scroll)<<8)
    uint32_t  last_slot  = 0xFFFFFFFF;
    uint32_t  last_pane  = 0xFFFFFFFF;
    uint32_t  last_trow  = 0xFFFFFFFF;
    uint32_t  last_tslot = 0xFFFFFFFF;   // v2.30.58: target-pane cursor
    uint32_t  last_id    = 0xFFFFFFFF;   // v2.30.57: spell under the cursor
    bool      i_was_down = false;        // v2.30.57: I-key edge (descriptions)
    ULONGLONG next_scan_tick = 0;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_menus || MenuModuleForeignScreen() ||
            GameOverTitleContext() || Hooks::TutorialActive()) {
            was_open = false;
            continue;
        }
        const int16_t field_id = *reinterpret_cast<const volatile int16_t*>(
            FF7Addr::FIELD_ID);
        const uint8_t menu_open = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::MENU_OPEN);
        const uint32_t screen = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::MENU_DISPATCH_INDEX);
        // v2.30.75: GAME_MODE==9 replaces the battle_end != 0 victory
        // guard â€” that byte rests at 5 between battles, which dead-gated
        // this thread after the session's first battle (see the materia
        // gate comment for the full derivation).
        const uint8_t game_mode = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::GAME_MODE);

        if (menu_open != 1 || field_id == 0 ||
            game_mode != FF7Addr::GAME_MODE_MAIN_MENU ||
            screen != FF7Addr::MAGICMENU_SCREEN_INDEX) {
            was_open = false;
            continue;
        }

        if ((!g_k2.magic || !g_k2.magic_desc) &&
            GetTickCount64() >= next_scan_tick) {
            next_scan_tick = GetTickCount64() + 3000;
            ScanKernel2Sections();
        }

        // ---- I key: description of the spell under the cursor -----------
        // v2.30.57. FF4-scheme parity ("I ... reads description of the
        // highlighted item"), same focus/edge/settings-menu discipline as
        // the shop/materia/equip readers. Handled BEFORE the change-driven
        // returns below so it answers on any poll, not only when the
        // cursor moved.
        {
            DWORD fg_pid = 0;
            GetWindowThreadProcessId(GetForegroundWindow(), &fg_pid);
            const bool focused = (fg_pid == GetCurrentProcessId());
            const bool i_down  = (GetAsyncKeyState('I') & 0x8000) != 0;
            const bool i_edge  = focused && !SettingsMenu::IsOpen() &&
                                 i_down && !i_was_down;
            i_was_down = i_down;
            if (i_edge) {
                std::wstring d;
                if (last_id != 0xFFFFFFFF && last_id != 0xFF &&
                    SectionEntryText(ValidatedSection(&g_k2.magic_desc,
                                                      "Restores HP|Restores HP|"),
                                     last_id, d) && !d.empty())
                    TTS::Speak(d.c_str(), true);
                else
                    TTS::Speak(L"No description", true);
            }
        }

        const uint32_t slot = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::MAGICMENU_PARTY_SLOT);
        // v2.30.53: SIGNED — the screen parks at -1 while entering.
        const int32_t pane = *reinterpret_cast<const volatile int32_t*>(
            FF7Addr::MAGICMENU_MODE);
        const uint32_t tab = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::MAGICMENU_TAB);

        // v2.30.54: per-TAB list geometry — each tab owns a widget, a
        // per-character list base, and a column count (all three read off
        // the sub's own draw/OK paths; see the MAGICMENU block).
        struct TabInfo {
            uint32_t col_va, row_va, scroll_va, list_off, ncols;
            const wchar_t* name;
        };
        static const TabInfo kTabs[3] = {
            { FF7Addr::MAGICMENU_LIST_COL, FF7Addr::MAGICMENU_LIST_ROW,
              FF7Addr::MAGICMENU_LIST_SCROLL, FF7Addr::BCHAR_OFF_MAGIC_LIST,
              3, L"Magic" },
            { FF7Addr::MAGICMENU_SUM_COL, FF7Addr::MAGICMENU_SUM_ROW,
              FF7Addr::MAGICMENU_SUM_SCROLL, FF7Addr::BCHAR_OFF_SUMMON_LIST,
              2, L"Summon" },
            { FF7Addr::MAGICMENU_ESK_COL, FF7Addr::MAGICMENU_ESK_ROW,
              FF7Addr::MAGICMENU_ESK_SCROLL, FF7Addr::BCHAR_OFF_ESKILL_LIST,
              2, L"Enemy Skill" },
        };
        // Which tab's list is on screen: in a list mode it is mode-2; on
        // the selector it is the tab cursor itself.
        const uint32_t list_tab =
            (pane >= FF7Addr::MAGICMENU_MODE_LIST_MIN &&
             pane <= FF7Addr::MAGICMENU_MODE_LIST_MAX)
                ? static_cast<uint32_t>(pane - FF7Addr::MAGICMENU_MODE_LIST_MIN)
                : (tab < 3 ? tab : 0);
        const TabInfo& ti = kTabs[list_tab < 3 ? list_tab : 0];
        const uint32_t col = *reinterpret_cast<const volatile uint32_t*>(
            ti.col_va);
        const uint32_t row = *reinterpret_cast<const volatile uint32_t*>(
            ti.row_va);
        const uint32_t scroll = *reinterpret_cast<const volatile uint32_t*>(
            ti.scroll_va);

        bool fresh = false;
        if (!was_open) {
            was_open = true;
            fresh = true;
            last_sel = last_pane = last_trow = 0xFFFFFFFF;
            last_slot = slot;
            i_was_down = true;   // v2.30.57: swallow a held I from elsewhere
            wchar_t who[32];
            PartySlotLabel(static_cast<uint8_t>(slot <= 2 ? slot : 0),
                           who, _countof(who));
            std::wstring msg = L"Magic. ";
            msg += who;
            // v2.30.57: the character's MP is on screen the whole time —
            // say it on entry so the player can judge affordability
            // before browsing (same char-block pair the cost check uses).
            const uint32_t mp0 = FF7Addr::BATTLE_CHAR_BLOCK +
                                 (slot <= 2 ? slot : 0) *
                                     FF7Addr::BATTLE_CHAR_SLOT_STRIDE +
                                 FF7Addr::BCHAR_OFF_MP;
            if (IsReadableSpan(reinterpret_cast<const void*>(mp0), 4)) {
                const uint16_t cur = *reinterpret_cast<const volatile uint16_t*>(mp0);
                const uint16_t max = *reinterpret_cast<const volatile uint16_t*>(mp0 + 2);
                if (max != 0 && cur <= max && max < 10000) {
                    wchar_t buf[40];
                    _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                                 L". %u of %u MP", static_cast<unsigned>(cur),
                                 static_cast<unsigned>(max));
                    msg += buf;
                }
            }
            TTS::Speak(msg.c_str(), true);
        } else if (slot != last_slot && slot <= 2) {
            last_slot = slot;
            wchar_t who[32];
            PartySlotLabel(static_cast<uint8_t>(slot), who, _countof(who));
            TTS::Speak(who, true);
            last_sel = 0xFFFFFFFF;   // new character: re-announce selection
            fresh = true;   // v2.30.51: queue the follow-up (see equip)
        }

        // ---- mode transitions --------------------------------------------
        // v2.30.54 (delta-scan truth): -1 entering, 0 = TAB SELECTOR,
        // 2/3/4 = the Magic / Summon / Enemy Skill lists.
        if (static_cast<uint32_t>(pane) != last_pane) {
            if (last_pane != 0xFFFFFFFF) {
                char dbg[64];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] MAGICM mode %ld -> %ld",
                    static_cast<long>(static_cast<int32_t>(last_pane)),
                    static_cast<long>(pane));
                Log::Write(dbg);
            }
            last_pane = static_cast<uint32_t>(pane);
            last_trow = 0xFFFFFFFF;
            last_sel  = 0xFFFFFFFF;   // re-announce on entering the grid
        }

        // ---- TAB SELECTOR (mode 0, and the -1 entry frames) ---------------
        // The tab cursor is the one address the v2.30.54 delta scan saw
        // move under the player's presses (0→1→2→0). Speaking it is what
        // the three broken versions were missing: the player was on this
        // selector the whole time, hearing character names.
        //
        // ⚠ v2.30.59 CONTROL-FLOW FIX: this guard used to swallow EVERY
        // mode outside 2..4 — including the target pane (mode 1) — and
        // `continue`, so the v2.30.58 target branch below was never
        // reached. MSVC proved that unreachability and eliminated the
        // whole block, which is how it was caught: the branch's log
        // string was missing from the shipped DLL even after a clean
        // rebuild. Excluding the target mode here restores the fallthrough.
        if (pane != FF7Addr::MAGICMENU_MODE_TARGET &&
            (pane < FF7Addr::MAGICMENU_MODE_LIST_MIN ||
             pane > FF7Addr::MAGICMENU_MODE_LIST_MAX)) {
            if (tab < 3 && tab != last_trow) {
                const bool first = (last_trow == 0xFFFFFFFF);
                last_trow = tab;
                // On the open poll this queues behind "Magic. <name>"
                // (v2.30.51 rule); later moves interrupt.
                if (!(first && fresh))
                    TTS::Speak(kTabs[tab].name, /*interrupt=*/!fresh);
            }
            continue;   // no list is focused yet
        }

        // ---- TARGET pane: "use Cure on whom?" (v2.30.58) -------------------
        // Choosing a field-usable spell (Cure...) opens the character
        // picker. BOTH pieces are now play-confirmed (2026-08-01):
        //   * the pane is mode 1 (MAGICMENU_MODE_TARGET, measured from
        //     the "mode 2 -> 1" transition when Cure was selected), and
        //   * MAGICMENU_TARGET_SLOT (0xDD16D4) IS its cursor — the same
        //     slot the game's OK path feeds to SAVEMAP_PARTY_IDS at
        //     0x7137F8; the picker "spoke characters cleanly" once the
        //     control-flow fix below let this branch run.
        // last_tslot resets on every mode change, so the pane's initial
        // write cannot speak a name before the player has moved.
        const uint32_t tslot = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::MAGICMENU_TARGET_SLOT);


        if (pane == FF7Addr::MAGICMENU_MODE_TARGET) {
            if (tslot <= 2 && tslot != last_tslot) {
                const bool first = (last_tslot == 0xFFFFFFFF);
                last_tslot = tslot;
                wchar_t who[32];
                PartySlotLabel(static_cast<uint8_t>(tslot), who, _countof(who));
                std::wstring m;
                if (first) m = L"Use on whom? ";
                m += who;
                // v2.30.57's MP line applies to the CASTER, not the
                // target; the target's own MP/HP is what the picker
                // shows, so speak the target's HP the way the screen does.
                const uint32_t rec = CharRecFromPartySlot(tslot);
                if (rec) {
                    const uint16_t hp = *reinterpret_cast<const volatile uint16_t*>(
                        rec + FF7Addr::SAVEMAP_CHAR_HP_OFF);
                    const uint16_t hpmax = *reinterpret_cast<const volatile uint16_t*>(
                        rec + FF7Addr::SAVEMAP_CHAR_MAXHP_OFF);
                    if (hpmax != 0 && hp <= hpmax) {
                        wchar_t buf[40];
                        _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                                     L", %u of %u HP",
                                     static_cast<unsigned>(hp),
                                     static_cast<unsigned>(hpmax));
                        m += buf;
                    }
                }
                if (Config::Get().debug_log) {
                    char dbg[112];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] MAGICM target mode=%ld slot=%lu",
                        static_cast<long>(pane),
                        static_cast<unsigned long>(tslot));
                    Log::Write(dbg);
                }
                TTS::Speak(m.c_str(), true);
            }
            continue;   // the spell grid is parked while targeting
        }

        // ---- list browsing (modes 2/3/4 = Magic / Summon / Enemy Skill) ---
        if (col >= ti.ncols || row > 20 || scroll > 20 || slot > 2)
            continue;   // widget mid-rebuild; values settle next poll
        const uint32_t sel = col | ((row + scroll) << 8);
        if (sel == last_sel)
            continue;
        last_sel = sel;

        const uint32_t idx = col + (row + scroll) * ti.ncols;
        const uint32_t entry = FF7Addr::BATTLE_CHAR_BLOCK +
                               slot * FF7Addr::BATTLE_CHAR_SLOT_STRIDE +
                               ti.list_off +
                               idx * FF7Addr::BLIST_MAGIC_STRIDE;
        if (idx >= 64 ||
            !IsReadableSpan(reinterpret_cast<const void*>(entry), 8))
            continue;
        const uint8_t id = *reinterpret_cast<const volatile uint8_t*>(entry);

        std::wstring msg;
        if (id == 0xFF) {
            msg = L"Empty";
        } else {
            if (!SectionEntryText(ValidatedSection(&g_k2.magic,
                                                   g_k2_magic_sig),
                                  id, msg) || msg.empty()) {
                wchar_t buf[24];
                _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"Spell %u",
                             static_cast<unsigned>(id) + 1u);
                msg = buf;
            }
            // v2.30.57: MP COST + affordability — the two things printed
            // beside every spell on screen. Both come from the game's own
            // OK-press check (0x7137C4..0x7137E5): cost = list entry byte
            // +1, current MP = u16 at [slot*0x440 + 0xDBA4AC] (= the char
            // block's +0x14 MP pair), and the handler refuses the cast
            // when MP < cost — which is exactly when the screen dims the
            // spell. Speaking both mirrors the sighted readout.
            const uint8_t cost = *reinterpret_cast<const volatile uint8_t*>(
                entry + 1);
            const uint32_t mp_va = FF7Addr::BATTLE_CHAR_BLOCK +
                                   slot * FF7Addr::BATTLE_CHAR_SLOT_STRIDE +
                                   FF7Addr::BCHAR_OFF_MP;
            uint16_t cur_mp = 0xFFFF;
            if (IsReadableSpan(reinterpret_cast<const void*>(mp_va), 4))
                cur_mp = *reinterpret_cast<const volatile uint16_t*>(mp_va);
            wchar_t mpbuf[24];
            _snwprintf_s(mpbuf, _countof(mpbuf), _TRUNCATE, L", %u MP",
                         static_cast<unsigned>(cost));
            msg += mpbuf;
            // The renderer's own usable table: cases 0/1/2 = white, case 3
            // (and ids past the table) = grayed battle-only. Reading the
            // exe image in-process — no ASLR, .text is always mapped.
            bool usable = false;
            if (id <= 0x33) {
                const uint8_t uc = *reinterpret_cast<const uint8_t*>(
                    FF7Addr::MAGIC_MENU_USABLE_TABLE + id);
                usable = (uc != FF7Addr::MAGIC_MENU_USABLE_GRAY_CASE);
            }
            if (!usable)
                msg += L", battle only";
            else if (cur_mp != 0xFFFF && cur_mp < cost)
                msg += L", not enough MP";
        }

        last_id = id;   // v2.30.57: the I key describes THIS spell

        if (Config::Get().debug_log) {
            char dbg[160];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] MAGICM %ls slot=%lu idx=%lu id=0x%02X '%ls'",
                ti.name, static_cast<unsigned long>(slot),
                static_cast<unsigned long>(idx), id, msg.c_str());
            Log::Write(dbg);
        }
        // On the open poll the selection QUEUES behind "Magic. <name>"
        // (the F8-menu lesson: two interrupt=true utterances back-to-back
        // cut the first off mid-word); every later move interrupts.
        TTS::Speak(msg.c_str(), /*interrupt=*/!fresh);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// On-demand announcement keys (FF4-scheme parity, accessiblity_keys.txt):
//   G â€” "Announce current Gil" (v2.30.28). Works any time a game is
//       loaded: field, menus, shops, battle. The gil dword is
//       savemap+0xB7C â€” live-proven by the v2.35 victory total and the
//       shop's own buy/sell arithmetic.
//   H â€” "In battle, announce character hp, mp, status effects"
//       (v2.30.30). Reads the CURRENT-TURN character: BATTLE_ACTIVE_SLOT
//       is the party slot whose battle menu is open (the v2.37 whose-turn
//       source; it retains the last acting slot during animations, which
//       is still "the current-most character"). HP/MP come from the same
//       actor-vars fields the v2.11 target readout uses; statuses from
//       actor_vars +0x00 statusMask (FFNx battle_actor_vars field name).
// ---------------------------------------------------------------------------

// FF7's kernel status-mask bit order â€” the one 32-bit status layout every
// kernel/save tool documents (WallMarket/Proud Clod/qhimm "Battle
// Mechanics"; corroborated in-repo: the Sadness/Fury bits 0x10/0x20 match
// the savemap flag convention, and bit 0 = Death matches the KO'd actors
// observed with currentHP 0). Names checked against walkthrough.txt terms.
// Buff-side bits (Haste/Regen/Barrier/...) are spoken too â€” they answer
// "what's on me right now" exactly like the FF4 mod's H does.
static const struct { uint32_t bit; const wchar_t* name; } kBattleStatusNames[] = {
    { 0x00000001, L"Death"          },
    { 0x00000002, L"Near death"     },
    { 0x00000004, L"Sleep"          },
    { 0x00000008, L"Poison"         },
    { 0x00000010, L"Sadness"        },
    { 0x00000020, L"Fury"           },
    { 0x00000040, L"Confusion"      },
    { 0x00000080, L"Silence"        },
    { 0x00000100, L"Haste"          },
    { 0x00000200, L"Slow"           },
    { 0x00000400, L"Stop"           },
    { 0x00000800, L"Frog"           },
    { 0x00001000, L"Small"          },
    { 0x00002000, L"Slow numb"      },
    { 0x00004000, L"Petrify"        },
    { 0x00008000, L"Regen"          },
    { 0x00010000, L"Barrier"        },
    { 0x00020000, L"M Barrier"      },   // the game's own term (walkthrough
                                         // -verified); spelled with a space
                                         // so TTS says "em barrier"
    { 0x00040000, L"Reflect"        },
    // 0x00080000 "Dual" â€” internal pairing flag, not a player-facing
    // condition; skipped rather than spoken as jargon.
    { 0x00100000, L"Shield"         },
    { 0x00200000, L"Death sentence" },
    { 0x00400000, L"Manipulate"     },
    { 0x00800000, L"Berserk"        },
    { 0x01000000, L"Peerless"       },
    { 0x02000000, L"Paralyzed"      },
    { 0x04000000, L"Darkness"       },
};

static DWORD WINAPI AnnounceKeysThread(LPVOID /*unused*/)
{
    bool g_was_down = false;
    bool h_was_down = false;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        DWORD fg_pid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &fg_pid);
        const bool focused = (fg_pid == GetCurrentProcessId());
        const bool g_down  = (GetAsyncKeyState('G') & 0x8000) != 0;
        const bool h_down  = (GetAsyncKeyState('H') & 0x8000) != 0;
        const bool g_edge  = focused && g_down && !g_was_down;
        const bool h_edge  = focused && h_down && !h_was_down;
        g_was_down = g_down;
        h_was_down = h_down;
        if (!g_edge && !h_edge)
            continue;

        const int16_t field_id = *reinterpret_cast<const volatile int16_t*>(
            FF7Addr::FIELD_ID);
        const uint8_t game_mode = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::GAME_MODE);

        // â”€â”€ G: current gil â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // No game loaded -> the savemap is zeroed and "0 gil" would be a
        // lie about a game that doesn't exist yet. The naming screen gets
        // typed letters â€” G there is text entry, not a query.
        //
        // v2.30.36: FIELD_ID != 0 was the wrong "game loaded" test â€” it
        // really means "standing on a field": the WORLD MAP also reads 0
        // (this file's own FIELD_ID comments), so G was silently dead
        // there despite a fully valid savemap ("can I afford the inn?"
        // is exactly a world-map question). "A game is loaded" is now
        // proven by the savemap's location caption (LOCATION_NAME_BUFFER,
        // savemap+0xF0C): every started game has one (MPNAM persists it
        // through saves â€” including world-map saves, since it IS savemap
        // state), while the fresh-boot title screen's zeroed savemap
        // reads 0x00 there (no caption ever starts with byte 0x00 â€” FF7
        // text starts captions with letter glyphs, and BSS zero-init is
        // what a never-loaded savemap holds). Residual, accepted: after
        // a quit-to-title the stale savemap may keep its caption, so G
        // on the title screen can speak the just-quit game's gil â€” a
        // cosmetic slip, chosen over a functionally dead key on the
        // world map.
        // v2.30.37: !GameOverTitleContext() â€” after a game over BOTH halves
        // of the test go stale-positive (dead FIELD_ID, dead savemap
        // caption): G on the game-over reel or title prompt would speak the
        // dead run's gil. The run is over; silence is the truthful answer.
        // (The quit-to-title stale caption stays an accepted residual â€”
        // there is no latch for that path yet.)
        const uint8_t caption0 = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::LOCATION_NAME_BUFFER);
        const bool game_loaded =
            !GameOverTitleContext() &&
            ((field_id != 0) || (caption0 != 0x00 && caption0 != 0xFF));
        if (g_edge && game_loaded &&
            game_mode != FF7Addr::GAME_MODE_NAME_ENTRY) {
            const uint32_t gil = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::SAVEMAP_GIL);
            wchar_t msg[32];
            _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"%lu gil",
                         static_cast<unsigned long>(gil));
            TTS::Speak(msg, true);
        }

        // â”€â”€ H: current character's HP/MP/status, battle only â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if (h_edge && game_mode == 2) {
            uint8_t slot = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::BATTLE_ACTIVE_SLOT);
            if (slot > 2)
                slot = 0;   // no menu opened yet this battle â€” leader

            wchar_t label[32];
            PartySlotLabel(slot, label, _countof(label));
            std::wstring msg = label;

            const uint32_t base = FF7Addr::BATTLE_ACTOR_VARS +
                static_cast<uint32_t>(slot) * FF7Addr::BATTLE_ACTOR_VARS_STRIDE;
            const int32_t cur_hp = *reinterpret_cast<const volatile int32_t*>(
                base + FF7Addr::BAVARS_OFF_CURRENT_HP);
            const int32_t max_hp = *reinterpret_cast<const volatile int32_t*>(
                base + FF7Addr::BAVARS_OFF_MAX_HP);
            const uint16_t cur_mp = *reinterpret_cast<const volatile uint16_t*>(
                base + FF7Addr::BAVARS_OFF_CURRENT_MP);
            const uint16_t max_mp = *reinterpret_cast<const volatile uint16_t*>(
                base + FF7Addr::BAVARS_OFF_MAX_MP);

            // Same plausibility gate as TargetHPText â€” mid-init garbage
            // speaks as name-only, never as wrong numbers.
            if (max_hp > 0 && max_hp <= 10000000 &&
                cur_hp >= 0 && cur_hp <= max_hp && max_mp <= 9999) {
                wchar_t nums[96];
                _snwprintf_s(nums, _countof(nums), _TRUNCATE,
                             L", HP %d of %d, MP %u of %u",
                             static_cast<int>(cur_hp),
                             static_cast<int>(max_hp),
                             static_cast<unsigned>(cur_mp),
                             static_cast<unsigned>(max_mp));
                msg += nums;
            }

            const uint32_t status = *reinterpret_cast<const volatile uint32_t*>(
                base + FF7Addr::BAVARS_OFF_STATUS_MASK);
            bool any_status = false;
            for (const auto& s : kBattleStatusNames) {
                if (status & s.bit) {
                    msg += any_status ? L", " : L". ";
                    msg += s.name;
                    any_status = true;
                }
            }
            if (!any_status)
                msg += L". No status effects";

            if (Config::Get().debug_log) {
                char dbg[96];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] H key: slot=%u status=%08lX",
                    static_cast<unsigned>(slot),
                    static_cast<unsigned long>(status));
                Log::Write(dbg);
            }
            TTS::Speak(msg, true);
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// MENU TUTORIAL narration, per-slide (v2.30.29).
//
// Play report on v2.30.27's up-front model: "reads the entire tutorial in
// one long buffer... once the text is read, the user is left to guess how
// to move through each slide in silence." The live state the v1 comment
// called unmapped is now mapped (TUTWIN_* / TUTORIAL_RUNNING provenance in
// ff7_addresses.h): the menu module's tutorial VM opens one text window
// per slide, holds until the player presses ANY key (renderer state 2's
// close test is `pressed-digest != 0` â€” there is no per-slide magic key;
// what LOOKED like "sometimes a direction, sometimes a button" was the
// demo phases between slides, where the VM injects scripted key presses
// and discards real input entirely), then runs the scripted demo to the
// next slide.
//
// Model: follow the window renderer's state byte exactly like FFNx's own
// voice-acting hook does â€” speak THE CURRENT slide when its window
// reaches state 2 (text showing), tell the player "Press any button to
// continue" (input-advanced windows only â€” TUTWIN_MODE 0 windows are
// timer-closed info popups and take no input), and say when the lesson
// is over (TUTORIAL_RUNNING 1->0), which also releases the menu-thread
// suppression latch. Non-tutorial uses of the same renderer (the save
// screens' "file corrupted"-class popups) get spoken too under
// speak_menus â€” they were previously silent.
// ---------------------------------------------------------------------------

// Bounded copy-out + decode of an FF7 string at an arbitrary game pointer.
// The text lives in the field buffer (tutorial slides) or exe .data
// (popups); copy in page-safe chunks until the 0xFF terminator, then
// decode the LOCAL copy â€” never hand a raw unbounded pointer to Decode.
static bool SafeDecodeFF7At(uint32_t addr, std::wstring& out)
{
    char local[1024];
    size_t n = 0;
    while (n < sizeof(local) - 1) {
        const size_t chunk = 64;
        if (!IsReadableSpan(reinterpret_cast<const void*>(addr + n), chunk))
            break;
        bool done = false;
        for (size_t i = 0; i < chunk && n < sizeof(local) - 1; ++i) {
            const char c = *reinterpret_cast<const volatile char*>(addr + n);
            local[n++] = c;
            if (static_cast<uint8_t>(c) == 0xFF) {
                done = true;
                break;
            }
        }
        if (done)
            break;
    }
    if (n == 0)
        return false;
    local[n] = static_cast<char>(0xFF);   // force-terminate a truncated copy
    out = FF7Text::Decode(local);
    for (wchar_t c : out)
        if (c != L' ')
            return true;
    return false;
}

static DWORD WINAPI TutorialThread(LPVOID /*unused*/)
{
    bool     was_running = false;
    uint32_t last_text   = 0;       // text ptr of the last SPOKEN window
    bool     first_slide = false;   // next slide gets the "Tutorial." prefix
    // v2.30.36: deferred latch release (see the finished-edge below).
    bool     release_pending = false;
    DWORD    release_tick    = 0;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        const bool running = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::TUTORIAL_RUNNING) != 0;
        const uint8_t state = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::TUTWIN_STATE);
        const uint32_t text_ptr = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::TUTWIN_TEXT_PTR);
        const uint8_t mode = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::TUTWIN_MODE);

        if (running && !was_running) {
            first_slide = true;
            last_text   = 0;
            Log::Write("[FF7Access] TUTORIAL started (engine flag up)");
        } else if (!running && was_running) {
            // The VM hit its END opcode â€” no more slides. Saying so is the
            // difference between "lesson over, menus are yours again" and
            // the silence the play report described.
            TTS::Speak(L"Tutorial finished.", /*interrupt=*/false);
            // v2.30.36: DEFER the latch release. Clearing it in this same
            // poll let whichever menu screen-thread matched the still-open
            // menu see a "fresh open" on its very next 50ms poll (its
            // open-latch had been reset every poll by the TutorialActive
            // gate) and speak its opening announce with interrupt=true â€”
            // wiping the just-queued cue before it could play. The player
            // never heard it. While the latch holds, those threads keep
            // tracking silently, so nothing is lost: their announce lands
            // right after the release, AFTER the cue has had time to
            // speak.
            release_pending = true;
            release_tick    = GetTickCount();
            Log::Write("[FF7Access] TUTORIAL finished (engine flag down), "
                       "latch release deferred");
        }
        was_running = running;

        // v2.30.36: a new lesson starting during the grace keeps the
        // suppression up â€” cancel the pending release.
        if (running)
            release_pending = false;
        if (release_pending && (GetTickCount() - release_tick) >= 1500) {
            release_pending = false;
            Hooks::ClearTutorialActive();
            Log::Write("[FF7Access] TUTORIAL latch released");
        }

        // One announcement per window SHOWING. last_text re-arms when the
        // window fully closes, so the compare-to-last is both the "spoke
        // this one already" guard and the back-to-back-windows detector
        // (every window passes through state 0 between shows â€” the VM's
        // hold flag waits for it).
        const bool showing = (state == 2);
        const bool announce = showing && text_ptr != 0 &&
                              text_ptr != last_text;
        if (announce) {
            std::wstring text;
            if (SafeDecodeFF7At(text_ptr, text)) {
                if (running) {
                    std::wstring msg = first_slide ? L"Tutorial. " : L"";
                    msg += text;
                    // Input-advanced window: tell the player exactly how
                    // to move on (any key â€” the close test is literal
                    // "any pressed bit"). Timer windows advance alone.
                    if (mode != 0)
                        msg += L" Press any button to continue.";
                    // Interrupt: the previous slide's speech is stale the
                    // moment the player advanced past it.
                    TTS::Speak(msg, /*interrupt=*/true);
                    first_slide = false;
                } else if (Config::Get().speak_menus) {
                    // Non-tutorial info popup on the shared renderer
                    // (save screens' "file corrupted" class) â€” speak it
                    // plainly; these had no speech path before.
                    TTS::Speak(text, /*interrupt=*/true);
                }
                last_text = text_ptr;

                char dbg[128];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] TUTWIN show: text=%08lX mode=%u running=%d",
                    static_cast<unsigned long>(text_ptr),
                    static_cast<unsigned>(mode), running ? 1 : 0);
                Log::Write(dbg);
            }
        }
        if (!showing && state == 0)
            last_text = 0;   // window fully closed â€” re-arm for re-shows
    }

    return 0;
}

static DWORD WINAPI ItemMenuThread(LPVOID /*unused*/)
{
    bool      was_open  = false;
    uint8_t   last_mode = 0xFF;
    uint8_t   last_top  = 0xFF;
    uint8_t   last_row  = 0xFF;
    uint8_t   last_tgt  = 0xFF;
    uint16_t  last_word = 0xFFFF;  // slot word under the cursor: using an item
                                   // rewrites it (qty-1 or 0xFFFF) while the
                                   // cursor stays put â€” re-announce so the
                                   // player hears the new count
    uint8_t   last_unknown = 0xFF; // debug-log throttle for unmapped modes
    ULONGLONG next_scan_tick = 0;  // kernel2 rescan rate limit

    static const wchar_t* const kTopBar[3] = { L"Use", L"Arrange", L"Key Items" };

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 150) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_menus) {
            was_open = false;
            continue;
        }

        // v2.30.32: the dispatch index is stale on foreign menu screens
        // (shop/PHS/name entry) â€” a leftover 1 would fake "item screen".
        // v2.30.37: the post-game-over title prompt is the same stale-bytes
        // situation (MENU_OPEN=1, stale dispatch index, stale FIELD_ID).
        if (MenuModuleForeignScreen() || GameOverTitleContext()) {
            was_open = false;
            continue;
        }

        // Gate: main menu open, in field, and the dispatcher is running the
        // ITEM sub-screen. The dispatch index is the menu module's own
        // "which screen" variable (see ff7_addresses.h) â€” but its value on
        // the PLAIN main menu is not yet observed, so if play ever shows a
        // spurious "Item menu" announce on menu open, log the index here
        // and add the missing differentiator.
        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        const uint32_t screen =
            *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MENU_DISPATCH_INDEX);
        if (menu_open != 1 || field_id == 0 ||
            screen != FF7Addr::ITEMMENU_SCREEN_INDEX ||
            // v2.30.75: victory screens raise MENU_OPEN with a STALE
            // dispatch index, but keep GAME_MODE=2 â€” the real item screen
            // only exists under the main-menu module, GAME_MODE==9
            // (2026-08-03 handoff log; replaces the v2.35.1 flag +
            // 4-second battle-recency window, which also wrongly muted
            // real menu opens within 4s of a battle).
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE) !=
                FF7Addr::GAME_MODE_MAIN_MENU ||
            // v2.30.27: a menu TUTORIAL drives the screens itself â€”
            // stand down, the tutorial narration is the speech.
            Hooks::TutorialActive()) {
            was_open = false;
            last_mode = last_top = last_row = last_tgt = 0xFF;
            last_word = 0xFFFF;
            last_unknown = 0xFF;
            continue;
        }

        // The list needs item names; kick the (rate-limited) kernel2 scan
        // if the menu opened before any battle populated the sections.
        if ((!g_k2.item || !g_k2.armor || !g_k2.accessory || !g_k2.item_desc)) {
            const ULONGLONG now = GetTickCount64();
            if (now >= next_scan_tick) {
                next_scan_tick = now + 3000;
                ScanKernel2Sections();
            }
        }

        const uint8_t mode =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::ITEMMENU_MODE);

        if (!was_open) {
            was_open = true;
            TTS::Speak(L"Item menu", /*interrupt=*/true);
            // Leave last_* unseeded so the state announce below fires and
            // describes where the cursor actually is (the menu opens in
            // the ITEM LIST â€” player-corrected flow 2026-07-18).
        }

        // A state announce right after "Item menu" (or any unseeded entry)
        // must QUEUE behind it, not cancel it; navigation announces
        // interrupt as every other menu cursor does.
        const bool chain = (last_mode == 0xFF);

        switch (mode) {
        case 0: {   // top bar: Use / Arrange / Key Items
            const uint8_t top = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::ITEMMENU_TOPBAR_CURSOR);
            if (top <= 2 && (top != last_top || mode != last_mode))
                TTS::Speak(kTopBar[top], /*interrupt=*/!chain);
            last_top = top;
            break;
        }
        case 1: {   // item list
            const uint8_t row = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::ITEMMENU_LIST_CURSOR);
            uint16_t word = 0xFFFF;
            if (row < FF7Addr::SAVEMAP_ITEMS_COUNT)
                word = *reinterpret_cast<const volatile uint16_t*>(
                    FF7Addr::SAVEMAP_ITEMS + row * 2u);
            if (row != last_row || mode != last_mode || word != last_word) {
                std::wstring msg;
                if (word == 0xFFFF) {
                    msg = L"Empty";
                } else {
                    const uint32_t id  = word & 0x1FF;
                    const uint32_t qty = word >> 9;
                    std::wstring name;
                    if (!InventoryEntryName(id, name)) {
                        wchar_t fb[24];
                        _snwprintf_s(fb, _countof(fb), _TRUNCATE,
                                     L"item %u", id);
                        name = fb;
                    }
                    wchar_t line[96];
                    _snwprintf_s(line, _countof(line), _TRUNCATE,
                                 L"%ls, %u", name.c_str(), qty);
                    msg = line;
                    // Description bar parity (items only â€” the sighted bar
                    // shows one for equipment too, but those live in other
                    // kernel sections; extend when a play report asks).
                    std::wstring desc;
                    if (id < 128 &&
                        SectionEntryText(
                            ValidatedSection(&g_k2.item_desc,
                                             "Restores HP by 100|"),
                            id, desc)) {
                        msg += L". ";
                        msg += desc;
                    }
                }
                TTS::Speak(msg, /*interrupt=*/!chain);
            }
            last_row = row;
            last_word = word;
            break;
        }
        case 2: {   // use-on-whom target pane
            const uint8_t tgt = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::ITEMMENU_TARGET_CURSOR);
            if (tgt <= 2 && (tgt != last_tgt || mode != last_mode)) {
                wchar_t label[64];
                PartySlotLabel(tgt, label, _countof(label));
                std::wstring msg = label;
                AppendPartyHpMp(tgt, msg);
                TTS::Speak(msg, /*interrupt=*/!chain);
            }
            last_tgt = tgt;

            // Using the item (OK press) rewrites its inventory word while
            // the pane stays open â€” the player can use several in a row.
            // Speak the remaining count so each use is audible. last_row/
            // last_word survive from the list state that opened this pane.
            if (last_row < FF7Addr::SAVEMAP_ITEMS_COUNT &&
                last_word != 0xFFFF) {
                const uint16_t word = *reinterpret_cast<const volatile uint16_t*>(
                    FF7Addr::SAVEMAP_ITEMS + last_row * 2u);
                if (word != last_word) {
                    if (word == 0xFFFF) {
                        TTS::Speak(L"None left", /*interrupt=*/false);
                    } else {
                        wchar_t line[32];
                        _snwprintf_s(line, _countof(line), _TRUNCATE,
                                     L"%u left", word >> 9);
                        TTS::Speak(line, /*interrupt=*/false);
                    }
                    last_word = word;
                }
            }
            break;
        }
        default:
            // Unmapped mode (Arrange popup? Key Items pane?) â€” stay silent,
            // log once per distinct value so play sessions harvest the map.
            if (mode != last_unknown) {
                last_unknown = mode;
                char dbg[96];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] ITEMMENU unmapped mode=%u", mode);
                Log::Write(dbg);
            }
            break;
        }
        last_mode = mode;
    }

    return 0;
}

// ---------------------------------------------------------------------------
// ORDER menu TTS + main-menu pane focus (v2.32, 2026-07-18).
//
// The Order "screen" is the main-menu screen with input focus moved into
// the party pane â€” no dispatch change, no confirm chime (player-observed;
// proven by the 0x6CA346 handler disasm â€” provenance in ff7_addresses.h at
// the ORDERMENU block). MENU_FOCUS_MODE drives everything:
//   0 = menu bar (MenuCursorThread's domain â€” silent here)
//   1 = character-select pane (Magic/Equip/Status/... rows): speak the
//       pane cursor by name so "whose screen?" is audible
//   2 = Order pane: full flow â€” member + position + row on cursor moves,
//       spoken how-to on entry (the user's explicit request), selection /
//       swap / row-toggle outcomes read back from the data that actually
//       changed (party-ID array, row bytes), never inferred from input.
// ---------------------------------------------------------------------------

// Battle-row spoken label for a party slot, or nullptr when unknown/empty.
static const wchar_t* PartySlotRowLabel(uint8_t slot)
{
    const uint8_t char_id =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::SAVEMAP_PARTY_IDS + slot);
    if (char_id == 0xFF)
        return nullptr;
    uint8_t rec = char_id;
    if (char_id == 9)  rec = 6;   // flashback aliases, as SavemapCharName
    if (char_id == 10) rec = 7;
    if (rec > 8)
        return nullptr;
    const uint8_t row = *reinterpret_cast<const volatile uint8_t*>(
        FF7Addr::SAVEMAP_CHAR_RECORDS + rec * FF7Addr::SAVEMAP_CHAR_REC_SIZE +
        FF7Addr::SAVEMAP_CHAR_ROW_OFF);
    if (row == FF7Addr::SAVEMAP_ROW_FRONT) return L"front row";
    if (row == FF7Addr::SAVEMAP_ROW_BACK)  return L"back row";
    return nullptr;   // unexpected value â€” say nothing rather than guess
}

// "Cloud, position 1, front row" / "Empty, position 3" for one pane slot.
static void OrderSlotAnnounceText(uint8_t slot, std::wstring& out)
{
    const uint8_t char_id =
        *reinterpret_cast<const volatile uint8_t*>(FF7Addr::SAVEMAP_PARTY_IDS + slot);
    wchar_t buf[80];
    if (char_id == 0xFF) {
        _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                     L"Empty, position %u", static_cast<unsigned>(slot + 1u));
        out = buf;
        return;
    }
    wchar_t label[64];
    PartySlotLabel(slot, label, _countof(label));
    const wchar_t* row = PartySlotRowLabel(slot);
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%ls, position %u%ls%ls",
                 label, static_cast<unsigned>(slot + 1u),
                 row ? L", " : L"", row ? row : L"");
    out = buf;
}

static DWORD WINAPI OrderMenuThread(LPVOID /*unused*/)
{
    uint8_t  last_focus   = 0xFF;   // 0xFF = gate closed last poll
    uint8_t  last_cursor  = 0xFF;   // Order-pane cursor
    uint32_t last_charsel = 0xFFFFFFFF;   // mode-1 pane cursor
    bool     latch_armed  = false;  // latch was 1 last poll
    // Data snapshot taken when the latch sets, diffed when it clears â€”
    // the outcome (swap / row toggle / cancel) is read from what actually
    // changed, so a missed press can never announce a wrong result.
    uint8_t  snap_ids[3]  = {};
    uint8_t  snap_rows[3] = {};

    const auto row_byte_of_slot = [](uint8_t slot) -> uint8_t {
        const uint8_t char_id = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::SAVEMAP_PARTY_IDS + slot);
        uint8_t rec = char_id;
        if (char_id == 9)  rec = 6;
        if (char_id == 10) rec = 7;
        if (char_id == 0xFF || rec > 8)
            return 0;
        return *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::SAVEMAP_CHAR_RECORDS + rec * FF7Addr::SAVEMAP_CHAR_REC_SIZE +
            FF7Addr::SAVEMAP_CHAR_ROW_OFF);
    };

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 150) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_menus) {
            last_focus = 0xFF;
            continue;
        }

        // v2.30.32: MENU_FOCUS_MODE and the Order-pane bytes are stale on
        // foreign menu screens (shop/PHS/name entry) â€” stand down.
        // v2.30.37: same for the post-game-over title prompt (its MENU_OPEN=1
        // woke this thread with a stale FOCUS_MODE â€” 2026-07-27 log 10:03:03).
        if (MenuModuleForeignScreen() || GameOverTitleContext()) {
            last_focus = 0xFF;
            continue;
        }

        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        const uint32_t screen =
            *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MENU_DISPATCH_INDEX);
        // v2.30.75: dispatch index 0 is ALSO its normal parked value while
        // the victory screens hold MENU_OPEN=1 (dispatch returns to 0 when
        // the player cancels back to the main bar, and the menu can only
        // close from there) â€” this gate previously passed on every victory
        // screen and stayed quiet only because the stale FOCUS_MODE byte
        // happened not to move. GAME_MODE==9 makes the stand-down positive
        // (2026-08-03 handoff log: victory keeps GAME_MODE=2).
        if (menu_open != 1 || field_id == 0 || screen != 0 ||
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE) !=
                FF7Addr::GAME_MODE_MAIN_MENU) {
            last_focus = 0xFF;
            latch_armed = false;
            continue;
        }

        const uint8_t focus =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_FOCUS_MODE);

        // v2.30.27: tutorial scripts move menu focus too â€” track
        // silently, never lecture over the tutorial narration.
        if (Hooks::TutorialActive()) {
            last_focus = focus;
            latch_armed = false;
            continue;
        }

        if (focus != last_focus) {
            char dbg[64];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] ORDER focus=%u (was %u)", focus, last_focus);
            Log::Write(dbg);
            if (focus == 2 && last_focus != 0xFF) {
                // Entering the Order pane (the transition the entry probe
                // couldn't see â€” FOCUS_MODE is written silently at 0x6CA526).
                // last_focus != 0xFF: only a REAL barâ†’pane transition â€” a
                // stale 2 at gate-open must not lecture the player.
                TTS::Speak(L"Order. Confirm one member, then another, to "
                           L"swap places. Confirm the same member twice to "
                           L"change rows.", /*interrupt=*/true);
                std::wstring msg;
                OrderSlotAnnounceText(*reinterpret_cast<const volatile uint8_t*>(
                    FF7Addr::ORDERMENU_CURSOR), msg);
                TTS::Speak(msg, /*interrupt=*/false);
            } else if (focus == 1 && last_focus != 0xFF) {
                // Character-select pane (Magic/Equip/Status rows). Only on a
                // real transition (not gate-open with stale 1) â€” the chime
                // already told the player something happened; name the pane.
                TTS::Speak(L"Choose a member.", /*interrupt=*/true);
                wchar_t label[64];
                PartySlotLabel(static_cast<uint8_t>(
                    *reinterpret_cast<const volatile uint32_t*>(
                        FF7Addr::CHARSEL_CURSOR) & 0xFF), label, _countof(label));
                TTS::Speak(label, /*interrupt=*/false);
            }
            last_focus = focus;
            last_cursor = 0xFF;
            last_charsel = 0xFFFFFFFF;
            // A focus change with the latch armed means the pane was left
            // mid-selection â€” drop the pending outcome.
            latch_armed = (focus == 2) ? latch_armed : false;
            continue;   // announce settled; next poll resumes tracking
        }

        if (focus == 2) {
            // â”€â”€ Order pane â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            const uint8_t cursor = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::ORDERMENU_CURSOR);
            if (cursor <= 2 && cursor != last_cursor) {
                if (last_cursor != 0xFF) {   // first poll after entry already spoke
                    std::wstring msg;
                    OrderSlotAnnounceText(cursor, msg);
                    TTS::Speak(msg, /*interrupt=*/true);
                }
                last_cursor = cursor;
            }

            const uint32_t latch = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::ORDERMENU_LATCH);
            if (latch == 1 && !latch_armed) {
                latch_armed = true;
                for (uint8_t s = 0; s <= 2; ++s) {
                    snap_ids[s] = *reinterpret_cast<const volatile uint8_t*>(
                        FF7Addr::SAVEMAP_PARTY_IDS + s);
                    snap_rows[s] = row_byte_of_slot(s);
                }
                const uint8_t first = *reinterpret_cast<const volatile uint8_t*>(
                    FF7Addr::ORDERMENU_FIRST_SLOT);
                wchar_t label[64];
                PartySlotLabel(first <= 2 ? first : 0, label, _countof(label));
                wchar_t msg[160];
                _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                    L"%ls selected. Confirm another member to swap, or %ls "
                    L"again to change rows.", label, label);
                TTS::Speak(msg, /*interrupt=*/true);
            } else if (latch == 0 && latch_armed) {
                latch_armed = false;
                bool ids_changed = false, rows_changed = false;
                uint8_t row_slot = 0xFF;
                for (uint8_t s = 0; s <= 2; ++s) {
                    if (*reinterpret_cast<const volatile uint8_t*>(
                            FF7Addr::SAVEMAP_PARTY_IDS + s) != snap_ids[s])
                        ids_changed = true;
                    if (row_byte_of_slot(s) != snap_rows[s]) {
                        rows_changed = true;
                        row_slot = s;
                    }
                }
                if (ids_changed) {
                    // Speak the resulting order â€” the outcome the player
                    // actually cares about, read from the rewritten array.
                    std::wstring msg = L"Swapped. ";
                    bool first_part = true;
                    for (uint8_t s = 0; s <= 2; ++s) {
                        const uint8_t id = *reinterpret_cast<const volatile uint8_t*>(
                            FF7Addr::SAVEMAP_PARTY_IDS + s);
                        if (id == 0xFF)
                            continue;
                        wchar_t part[96];
                        wchar_t label[64];
                        PartySlotLabel(s, label, _countof(label));
                        _snwprintf_s(part, _countof(part), _TRUNCATE,
                                     L"%ls%ls position %u",
                                     first_part ? L"" : L", ",
                                     label, static_cast<unsigned>(s + 1u));
                        msg += part;
                        first_part = false;
                    }
                    TTS::Speak(msg, /*interrupt=*/true);
                } else if (rows_changed) {
                    wchar_t label[64];
                    PartySlotLabel(row_slot, label, _countof(label));
                    const wchar_t* row = PartySlotRowLabel(row_slot);
                    wchar_t msg[96];
                    _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"%ls, %ls",
                                 label, row ? row : L"row changed");
                    TTS::Speak(msg, /*interrupt=*/true);
                } else {
                    TTS::Speak(L"Cancelled", /*interrupt=*/true);
                }
            }
        } else if (focus == 1) {
            // â”€â”€ Character-select pane â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            const uint32_t sel = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::CHARSEL_CURSOR);
            if (sel <= 2 && sel != last_charsel) {
                if (last_charsel != 0xFFFFFFFF) {
                    const uint8_t id = *reinterpret_cast<const volatile uint8_t*>(
                        FF7Addr::SAVEMAP_PARTY_IDS + sel);
                    if (id == 0xFF) {
                        TTS::Speak(L"Empty", /*interrupt=*/true);
                    } else {
                        wchar_t label[64];
                        PartySlotLabel(static_cast<uint8_t>(sel),
                                       label, _countof(label));
                        TTS::Speak(label, /*interrupt=*/true);
                    }
                }
                last_charsel = sel;
            }
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// BATTLE VICTORY screens TTS (v2.35, 2026-07-19). Speaks the two results
// screens (Screenshots/BattleScreen/victory_screen_1..3.jpg):
//   mode â†’ 1: "Victory! Gained X experience and Y A P." (pools CAPTURED at
//             results entry â€” the game consumes them on apply, see the
//             BATTLE_END_MODE block in ff7_addresses.h)
//   level bytes changing during the results window: "<name> grew to
//             level N!" (savemap watcher â€” catches multi-level-ups)
//   mode â†’ 3: "Gained X gil, total Y." + drop item names ("No items"
//             when the list is empty)
// All state transitions debug-logged (mode value 2's on-screen meaning is
// not yet known; the log will name it).
// ---------------------------------------------------------------------------
static DWORD WINAPI VictoryThread(LPVOID /*unused*/)
{
    uint16_t last_mode   = 0xFFFF;
    bool     in_results  = false;
    uint32_t cap_exp = 0, cap_ap = 0, cap_gil = 0;   // pools captured at entry
    bool     spoke_gil   = false;
    // v2.30.61 level watcher state — see the LEVEL WATCH block below for
    // why this is per-slot AND keyed by character id.
    uint8_t  seen_char[3]  = { 0xFF, 0xFF, 0xFF };
    uint8_t  seen_level[3] = {};
    bool     levels_valid  = false;

    // v2.30.90: detected level-ups are BUFFERED, not spoken at detection.
    // The 2026-08-05 logs proved the tester's "never hear level ups"
    // report: all 13 detections that day fired 150-160ms BEFORE the
    // victory window opened (the engine writes the savemap level as the
    // results screen comes up), so the level line spoke first and the
    // victory announce's interrupt=true then cancelled it — every time.
    // The v2.30.61 interrupt=false was aimed at queuing BEHIND victory,
    // but the order is the reverse. So: buffer here, and the victory
    // announce appends the buffer to its own utterance ("Victory! Gained
    // 100 experience and 10 A P. Barret grew to level 7!") — one speak,
    // nothing to cancel. Level-ups with no victory window (scripted EXP)
    // speak standalone after a short wait.
    std::wstring pending_levelups;
    ULONGLONG    first_levelup_tick = 0;
    constexpr ULONGLONG LEVELUP_ORPHAN_MS = 2500;

    const auto slot_level = [](uint8_t slot) -> uint8_t {
        const uint8_t char_id = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::SAVEMAP_PARTY_IDS + slot);
        uint8_t rec = char_id;
        if (char_id == 9)  rec = 6;
        if (char_id == 10) rec = 7;
        if (char_id == 0xFF || rec > 8)
            return 0;
        return *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::SAVEMAP_CHAR_RECORDS + rec * FF7Addr::SAVEMAP_CHAR_REC_SIZE +
            FF7Addr::SAVEMAP_CHAR_LEVEL_OFF);
    };

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 150) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_battle) {
            in_results = false;
            last_mode = 0xFFFF;
            levels_valid = false;   // re-baseline silently when re-enabled
            pending_levelups.clear();
            continue;
        }

        // ---- LEVEL WATCH (v2.30.61) ---------------------------------------
        // Tester request: announce level-ups on the victory screens. The
        // watcher shipped in v2.35 only ran INSIDE the detected results
        // window, so it inherited that window's gates (at the time a
        // 4-second battle-recency heuristic — since replaced by the
        // positive MENU_OPEN+GAME_MODE test, v2.30.75 — plus the
        // MENU_OPEN!=1 `continue` above). A level-up is worth announcing
        // whenever it happens, so this runs EVERY poll, independent of
        // the window — the savemap level byte is the authority and needs
        // no results-screen context.
        //
        // FALSE-POSITIVE GUARDS (a level byte can change for reasons that
        // are not a level-up):
        //   * keyed by CHARACTER ID per slot — a party change (PHS, story
        //     swaps) puts a different person in the slot, which is a
        //     re-baseline, not a level-up;
        //   * first observation after start/re-enable baselines SILENTLY;
        //   * a jump of more than 3 levels is treated as a save load or a
        //     scripted join (Cait Sith arrives mid-game at level ~20) and
        //     re-baselines silently — real battle level-ups are +1, and
        //     even a huge EXP haul steps one level at a time through this
        //     150ms poll.
        // Detections are buffered into pending_levelups (see above) — the
        // victory announce speaks them; never speak directly from here.
        {
            for (uint8_t s = 0; s <= 2; ++s) {
                const uint8_t char_id = *reinterpret_cast<const volatile uint8_t*>(
                    FF7Addr::SAVEMAP_PARTY_IDS + s);
                uint8_t rec = char_id;
                if (char_id == 9)  rec = 6;
                if (char_id == 10) rec = 7;
                if (char_id == 0xFF || rec > 8) {
                    seen_char[s] = 0xFF;
                    continue;
                }
                const uint8_t lv = *reinterpret_cast<const volatile uint8_t*>(
                    FF7Addr::SAVEMAP_CHAR_RECORDS +
                    rec * FF7Addr::SAVEMAP_CHAR_REC_SIZE +
                    FF7Addr::SAVEMAP_CHAR_LEVEL_OFF);
                if (lv == 0 || lv > 99) {           // savemap mid-write
                    continue;
                }
                const bool same_person = (seen_char[s] == char_id);
                const bool announce = levels_valid && same_person &&
                                      lv > seen_level[s] &&
                                      (lv - seen_level[s]) <= 3;
                if (announce) {
                    wchar_t label[64];
                    PartySlotLabel(s, label, _countof(label));
                    wchar_t msg[96];
                    _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                                 L"%ls grew to level %u!", label,
                                 static_cast<unsigned>(lv));
                    char dbg[112];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] LEVEL UP slot=%u char=%u %u -> %u",
                        s, char_id, seen_level[s], lv);
                    Log::Write(dbg);
                    if (pending_levelups.empty())
                        first_levelup_tick = GetTickCount64();
                    else
                        pending_levelups += L' ';
                    pending_levelups += msg;
                } else if (levels_valid && same_person && lv != seen_level[s] &&
                           Config::Get().debug_log) {
                    char dbg[128];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] LEVEL change slot=%u char=%u %u -> %u "
                        "(re-baselined, not announced)",
                        s, char_id, seen_level[s], lv);
                    Log::Write(dbg);
                }
                seen_char[s]  = char_id;
                seen_level[s] = lv;
            }
            levels_valid = true;
        }

        // Level-ups with no victory window to ride (scripted EXP awards,
        // or a results window whose pools read implausible and stayed
        // silent): speak standalone after a short wait. A real victory
        // consumes the buffer ~150ms after detection, far inside this
        // window, so the fallback never races it.
        if (!pending_levelups.empty() &&
            GetTickCount64() - first_levelup_tick >= LEVELUP_ORPHAN_MS) {
            char dbg[64];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] LEVEL UP spoken standalone");
            Log::Write(dbg);
            TTS::Speak(pending_levelups, /*interrupt=*/false);
            pending_levelups.clear();
        }

        // v2.30.75: the results window is POSITIVELY identified as
        // MENU_OPEN==1 while GAME_MODE is still 2 (battle) â€” the engine
        // keeps the battle module active for the whole victory sequence
        // and only the real main menu runs it at 9 (2026-08-03 handoff
        // log; MENU_OPEN was continuous across both results screens at
        // 30ms sampling, so a mid-window flicker close is not a real
        // shape). This replaces the old open condition â€” MENU_OPEN rise
        // within 4 seconds of the last observed battle poll â€” which
        // missed the window entirely when the battleâ†’results transition
        // outran the tick (and whose tick was only stamped while
        // speak_battle was on). Outside the window the mode global is
        // stale (it RESTS at 5 between battles) â€” transitions are only
        // trusted inside it.
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        const uint8_t game_mode =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE);
        if (menu_open != 1 || game_mode != FF7Addr::GAME_MODE_BATTLE) {
            in_results = false;
            last_mode = 0xFFFF;
            continue;
        }

        // v2.35.2 (player report: announcements trailed the button-driven
        // flow): the mode byte advances on the player's OK presses, not
        // when screens APPEAR â€” the EXP/AP screen shows during mode 0
        // (waiting for OK), mode 1 is the roll-up itself (the chirps), the
        // gil/items screen shows at mode 2, and 3 only lands after its OK
        // (then a ~30ms transient 4 and a RESTING 5 until the next battle
        // â€” the v2.30.75 lifecycle, see BATTLE_END_MODE in ff7_addresses.h).
        // So the victory line fires at the RESULTS WINDOW OPENING (the
        // MENU_OPEN rise under GAME_MODE==2), while the pools are provably
        // intact; the gil/items line fires entering mode 2 (fallback 3,
        // whichever is seen first â€” semantics harvested from the
        // transition log).
        const uint16_t mode =
            *reinterpret_cast<const volatile uint16_t*>(FF7Addr::BATTLE_END_MODE);

        if (!in_results) {
            // The results window just opened (first poll of MENU_OPEN==1
            // under battle mode). Capture the pools NOW â€” the roll-up
            // consumes them â€” and announce before the player's first OK
            // starts the chirping count-up.
            in_results = true;
            spoke_gil = false;
            last_mode = mode;
            cap_exp = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::BATTLE_GAINED_EXP);
            cap_ap = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::BATTLE_GAINED_AP);
            cap_gil = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::BATTLE_GAINED_GIL);
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] VICTORY window open: mode=%u exp=%lu ap=%lu gil=%lu",
                mode, static_cast<unsigned long>(cap_exp),
                static_cast<unsigned long>(cap_ap),
                static_cast<unsigned long>(cap_gil));
            Log::Write(dbg);
            if (cap_exp <= 1000000 && cap_ap <= 1000000) {
                wchar_t head[96];
                _snwprintf_s(head, _countof(head), _TRUNCATE,
                    L"Victory! Gained %lu experience and %lu A P",
                    static_cast<unsigned long>(cap_exp),
                    static_cast<unsigned long>(cap_ap));
                std::wstring msg = head;
                // v2.30.90: append buffered level-ups so they ride THIS
                // utterance — the engine writes the savemap level right
                // before this window opens, and this speak's
                // interrupt=true was cancelling the separately-spoken
                // level line every single time (2026-08-05 logs, 13/13).
                if (!pending_levelups.empty()) {
                    msg += L". ";
                    msg += pending_levelups;
                    pending_levelups.clear();
                    Log::Write("[FF7Access] LEVEL UP spoken with victory line");
                }
                TTS::Speak(msg, /*interrupt=*/true);
            } else {
                Log::Write("[FF7Access] VICTORY pools implausible â€” silent");
            }
        }

        const bool mode_changed = in_results && mode != last_mode;
        if (mode_changed) {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] VICTORY mode %u -> %u", last_mode, mode);
            Log::Write(dbg);
            last_mode = mode;

            if ((mode == 2 || mode == 3) && !spoke_gil) {
                spoke_gil = true;
                const uint32_t total_gil =
                    *reinterpret_cast<const volatile uint32_t*>(
                        FF7Addr::SAVEMAP_GIL);
                std::wstring msg;
                wchar_t part[96];
                _snwprintf_s(part, _countof(part), _TRUNCATE,
                    L"Gained %lu gil, total %lu. ",
                    static_cast<unsigned long>(cap_gil),
                    static_cast<unsigned long>(total_gil));
                msg = part;

                const uint32_t n = *reinterpret_cast<const volatile uint32_t*>(
                    FF7Addr::BATTLE_DROPS_COUNT);
                if (n == 0 || n > FF7Addr::BATTLE_DROPS_MAX) {
                    msg += L"No items.";
                    if (n > FF7Addr::BATTLE_DROPS_MAX) {
                        char dbg[96];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                            "[FF7Access] VICTORY drops count implausible: %lu",
                            static_cast<unsigned long>(n));
                        Log::Write(dbg);
                    }
                } else {
                    msg += L"Received ";
                    for (uint32_t i = 0; i < n; ++i) {
                        const uint32_t entry = FF7Addr::BATTLE_DROPS_ARRAY +
                                               i * FF7Addr::BATTLE_DROPS_STRIDE;
                        const uint16_t id = *reinterpret_cast<const volatile uint16_t*>(entry);
                        const uint16_t f4 = *reinterpret_cast<const volatile uint16_t*>(entry + 4);
                        char dbg[96];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                            "[FF7Access] VICTORY drop[%lu] id=%u f4=%u",
                            static_cast<unsigned long>(i), id, f4);
                        Log::Write(dbg);
                        std::wstring name;
                        if (!InventoryEntryName(id & 0x1FF, name)) {
                            wchar_t fb[16];
                            _snwprintf_s(fb, _countof(fb), _TRUNCATE,
                                         L"item %u", id & 0x1FF);
                            name = fb;
                        }
                        if (i > 0)
                            msg += L", ";
                        msg += name;
                    }
                    msg += L".";
                }
                TTS::Speak(msg, /*interrupt=*/true);
            }
        }

        // (v2.30.61: the level-up watcher used to live here, inside the
        // results window. It now runs every poll near the top of the loop
        // — see the LEVEL WATCH block — so a missed window detection can
        // no longer swallow a level-up.)
    }

    return 0;
}

// ---------------------------------------------------------------------------
// COUNTDOWN TIMER announcements + freeze (v2.34, 2026-07-18).
//
// The timed-escape clock (first: the No.1 Reactor run). Value = u32 WHOLE
// SECONDS at savemap+0xB84, written by the STTIM opcode as h*3600+m*60+s
// and ticked down ~1/sec â€” all established STATICALLY before the first
// timer was reachable in play (provenance: ff7_addresses.h COUNTDOWN
// block). This thread was therefore shipped SPECULATIVELY with heavy debug
// logging; the player's first real escape run is the live verify.
//
// ANNOUNCEMENTS (user spec, config timer_announcements):
//   start â†’ "Timer started, N minutes S seconds"; every minute boundary â†’
//   "N minutes remaining"; 30s â†’ "30 seconds"; final 10 â†’ bare numbers;
//   0 â†’ "Time is up". Battle announces QUEUE (interrupt=false) behind
//   battle speech except the final countdown, which always interrupts â€”
//   in the last ten seconds the clock outranks everything.
//
// RUNNING DETECTION is behavioral: the value must be nonzero AND have
// decreased recently. A stale savemap value (loaded save, finished escape)
// never decreases, so it can never false-start the announcer â€” the same
// never-trust-a-static-snapshot rule as the wall-tone fix.
//
// KEYS (accessiblity_keys.txt, FF1-6 parity â€” same focus/edge discipline
// as FieldNavThread): T = announce time left on demand ("No active timer"
// when none). Shift+T = FREEZE toggle â€” the mod's first gameplay memory
// WRITE: while frozen, the countdown value is rewritten every poll, which
// freezes the on-screen clock (it renders from this value) and keeps
// field-script time checks satisfied indefinitely. The write targets
// plain savemap data, not code â€” no protection change needed.
// ---------------------------------------------------------------------------
static void TimerSpeakRemaining(uint32_t secs, const wchar_t* prefix)
{
    wchar_t msg[96];
    const uint32_t m = secs / 60, s = secs % 60;
    if (m > 0 && s > 0)
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                     L"%ls%u minute%ls %u second%ls remaining", prefix,
                     m, m == 1 ? L"" : L"s", s, s == 1 ? L"" : L"s");
    else if (m > 0)
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                     L"%ls%u minute%ls remaining", prefix,
                     m, m == 1 ? L"" : L"s");
    else
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                     L"%ls%u second%ls remaining", prefix,
                     s, s == 1 ? L"" : L"s");
    TTS::Speak(msg, /*interrupt=*/true);
}

static DWORD WINAPI TimerThread(LPVOID /*unused*/)
{
    // v2.34.1: 50ms, matching FieldNavThread. The original 250ms was too
    // coarse for hotkey EDGE detection â€” a two-key Shift+T press releases
    // faster than a plain T tap, so its brief T-down often fell entirely
    // between two 250ms polls and the edge was lost (player report: T read
    // the time fine, Shift+T did nothing). Shift+J/L work at FieldNavThread's
    // 50ms for the same user, which pinned the cause. The finer poll also
    // makes the freeze rewrite tighter.
    constexpr DWORD     kPollMs        = 50;
    constexpr ULONGLONG kStaleMs       = 3000;  // no tick this long = not running
    constexpr uint32_t  kMaxSane       = 24 * 3600;

    uint32_t  last_val    = 0;
    bool      have_last   = false;
    bool      running     = false;
    ULONGLONG last_change = 0;
    // Tick-cadence diagnostics for the first live run: log the first few
    // observed tick intervals so the log proves (or corrects) the 1/sec
    // static assumption, and shows whether menus/battles pause the clock.
    int       cadence_logged = 0;
    ULONGLONG prev_change    = 0;
    // Freeze state (Shift+T).
    bool      frozen     = false;
    uint32_t  frozen_val = 0;
    // Key edge state.
    bool      t_was_down = false;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, kPollMs) == WAIT_OBJECT_0)
            break;

        volatile uint32_t* const timer =
            reinterpret_cast<volatile uint32_t*>(FF7Addr::COUNTDOWN_TIMER_SECONDS);
        volatile uint32_t* const timer_ms =
            reinterpret_cast<volatile uint32_t*>(FF7Addr::COUNTDOWN_TIMER_MS);

        // â”€â”€ Freeze: hold the clock every poll while enabled â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // v2.34.1: pin BOTH the seconds AND the sub-second accumulator.
        // The seconds alone isn't enough â€” the game keeps advancing the ms
        // counter and decrements seconds when it rolls past 1000, so a
        // seconds-only freeze would creep. Zeroing ms every 50ms means the
        // game never accumulates a full second, so the clock truly stops
        // (and the on-screen clock, which renders from seconds, holds).
        if (frozen) {
            *timer    = frozen_val;
            *timer_ms = 0;
        }

        uint32_t val = *timer;
        const ULONGLONG now = GetTickCount64();

        if (val > kMaxSane) {   // garbage (pre-init) â€” ignore entirely
            have_last = false;
            running = false;
        } else if (!Hooks::SttimSeen()) {
            // v2.30.8: no live STTIM call observed yet THIS PROCESS RUN â€”
            // this savemap field can hold a STALE value left over from an
            // earlier session's save (player report 2026-07-20: loading
            // into the slums, well past the No.1 Reactor escape, made the
            // timer "start again immediately" â€” the escape had ended with
            // time still on the clock, and that value just kept ticking in
            // the background across the save, invisible in vanilla FF7
            // since its on-screen clock window closed with the escape).
            // last_val/have_last still get updated unconditionally below
            // (so a REAL STTIM later doesn't read as a spurious "jump"),
            // but this branch deliberately does NOT touch last_change or
            // `running` â€” leaving both alone keeps timer_live false (see
            // its definition below) for as long as this branch keeps
            // being taken, which correctly makes T/Shift+T report "No
            // active timer" too, not just silence the automatic
            // announcements.
            //
            // v2.30.14 diagnostic: log ONCE per process run when a sane,
            // nonzero, actively-DECREMENTING value is being suppressed by
            // this gate. WHY: this branch was silent, which made the
            // 2026-07-22 log AMBIGUOUS between "the loaded save carried no
            // timer at all" and "a ticking value was correctly suppressed"
            // (fresh-launch load of a post-escape save â€” the suppression
            // demonstrably worked, but only field-trail inference proved a
            // ticking value was even present). It also cannot distinguish
            // the v2.30.8 RESIDUAL (a save made DURING a countdown, loaded
            // fresh â€” a REAL timer the gate would wrongly silence; only
            // reachable at timed sequences that allow saving, which the
            // No.1 escape does not). One log line settles both cases in
            // any future report without speaking or changing behavior.
            static bool s_unarmed_logged = false;
            if (!s_unarmed_logged && have_last && val != 0 &&
                val < last_val && (last_val - val) <= 5) {
                s_unarmed_logged = true;
                char dbg[128];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] TIMER ticking value %lu suppressed (no STTIM "
                    "this run: stale leftover, or a mid-countdown save load)",
                    static_cast<unsigned long>(val));
                Log::Write(dbg);
            }
        } else if (have_last && val != last_val && !frozen) {
            if (val < last_val && (last_val - val) <= 5) {
                // Normal downward tick(s).
                if (!running && val > 0) {
                    running = true;
                    cadence_logged = 0;
                    char dbg[96];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] TIMER started: %lu seconds",
                        static_cast<unsigned long>(val));
                    Log::Write(dbg);
                    if (Config::Get().timer_announcements)
                        TimerSpeakRemaining(val, L"Timer started. ");
                } else if (running) {
                    if (cadence_logged < 5 && prev_change != 0) {
                        char dbg[96];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                            "[FF7Access] TIMER tick %lu -> %lu (%lums)",
                            static_cast<unsigned long>(last_val),
                            static_cast<unsigned long>(val),
                            static_cast<unsigned long>(now - prev_change));
                        Log::Write(dbg);
                        cadence_logged++;
                    }
                    if (Config::Get().timer_announcements) {
                        const uint8_t game_mode =
                            *reinterpret_cast<const volatile uint8_t*>(
                                FF7Addr::GAME_MODE);
                        const bool in_battle = (game_mode == 2);
                        // Handle every value crossed since the last poll so
                        // a slow poll can't skip a boundary.
                        for (uint32_t v = last_val - 1; ; --v) {
                            if (v == 0) {
                                Log::Write("[FF7Access] TIMER reached zero");
                                TTS::Speak(L"Time is up", /*interrupt=*/true);
                            } else if (v <= 10) {
                                wchar_t num[8];
                                _snwprintf_s(num, _countof(num), _TRUNCATE,
                                             L"%u", v);
                                // Final countdown outranks everything.
                                TTS::Speak(num, /*interrupt=*/true);
                            } else if (v == 30) {
                                TTS::Speak(L"30 seconds",
                                           /*interrupt=*/!in_battle);
                            } else if (v % 60 == 0) {
                                wchar_t msg[48];
                                _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                                    L"%u minute%ls remaining", v / 60,
                                    v / 60 == 1 ? L"" : L"s");
                                TTS::Speak(msg, /*interrupt=*/!in_battle);
                            }
                            if (v == val)
                                break;
                        }
                    }
                }
                prev_change = now;
            } else {
                // Jump (new STTIM, save load, script rewrite) â€” re-detect.
                char dbg[96];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] TIMER value jump %lu -> %lu (re-detecting)",
                    static_cast<unsigned long>(last_val),
                    static_cast<unsigned long>(val));
                Log::Write(dbg);
                running = false;
            }
            last_change = now;
        }
        if (running && !frozen && now - last_change > kStaleMs) {
            char dbg[96];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] TIMER stopped/paused at %lu seconds",
                static_cast<unsigned long>(val));
            Log::Write(dbg);
            running = false;
        }
        last_val = val;
        have_last = true;

        // â”€â”€ T / Shift+T (focus-gated edges, as FieldNavThread) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        DWORD fg_pid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &fg_pid);
        const bool focused = (fg_pid == GetCurrentProcessId());
        const bool t_down = (GetAsyncKeyState('T') & 0x8000) != 0;
        const bool t_edge = focused && t_down && !t_was_down;
        t_was_down = t_down;
        if (!t_edge)
            continue;
        const bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        const bool timer_live = frozen || running ||
            (val > 0 && val <= kMaxSane && now - last_change < kStaleMs);
        // v2.30.56: a clock the player can SEE counting down, that the
        // arming gate has suppressed (unarmed = no STTIM/WSPCL this run).
        // The T key must never answer "no active timer" about a number
        // that is visibly ticking — that is what the tester hit after
        // loading a save made mid-escape. The value is reported, with an
        // honest qualifier, and Shift+T is allowed to freeze it (the
        // freeze is a pure savemap write — if the ticking value turns out
        // to be a stale leftover, holding it still harms nothing).
        const bool ticking_unarmed =
            !timer_live && val > 0 && val <= kMaxSane &&
            have_last && now - last_change < kStaleMs;
        // v2.34.1: one line per T press â€” ground truth if anything still
        // misbehaves (shift read, live-detection, freeze state).
        char kdbg[144];
        _snprintf_s(kdbg, sizeof(kdbg), _TRUNCATE,
            "[FF7Access] TIMER key T shift=%d frozen=%d running=%d live=%d "
            "unarmed_tick=%d val=%lu",
            shift ? 1 : 0, frozen ? 1 : 0, running ? 1 : 0,
            timer_live ? 1 : 0, ticking_unarmed ? 1 : 0,
            static_cast<unsigned long>(val));
        Log::Write(kdbg);

        if (!shift) {
            // T: on-demand time readout.
            if (frozen)
                TimerSpeakRemaining(frozen_val, L"Timer frozen. ");
            else if (timer_live)
                TimerSpeakRemaining(val, L"");
            else if (ticking_unarmed)
                TimerSpeakRemaining(val, L"Clock counting down. ");
            else
                TTS::Speak(L"No active timer", /*interrupt=*/true);
        } else {
            // Shift+T: freeze toggle.
            if (!frozen) {
                if (timer_live || ticking_unarmed) {
                    frozen = true;
                    frozen_val = val;
                    char dbg[96];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] TIMER frozen at %lu seconds",
                        static_cast<unsigned long>(frozen_val));
                    Log::Write(dbg);
                    TTS::Speak(L"Timer frozen", /*interrupt=*/true);
                } else {
                    TTS::Speak(L"No active timer", /*interrupt=*/true);
                }
            } else {
                frozen = false;
                last_change = now;   // grace period before stale detection
                running = false;     // re-detect from real ticks
                Log::Write("[FF7Access] TIMER resumed");
                TTS::Speak(L"Timer resumed", /*interrupt=*/true);
            }
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// STATUS screen TTS (v2.33, 2026-07-18). A real dispatched sub-screen
// (dispatch index 5 = FFNx's own status_menu_sub name for table[5]), shown
// for the character committed by the v2.32 char-select pane. The screen is
// a static stat sheet with no cursor, so the reader speaks the whole sheet
// once on entry (and again if the viewed character somehow changes) â€” the
// screen-reader equivalent of what a sighted player takes in at a glance.
//
// Numbers come from two places (provenance: ff7_addresses.h v2.33 notes):
//   savemap record  â€” level, EXP/next, limit level, equipment ids, and the
//                     BASE stats (fallback only);
//   char-data block â€” EFFECTIVE stats + derived Attack/Defense/Magic
//                     atk/def (what the screen actually shows; Cloud's
//                     materia made record and screen disagree, so base
//                     stats alone would contradict a sighted helper).
// The block is trusted only when its HP/maxHP words equal the savemap
// record's (staleness guard) â€” on mismatch the reader speaks base stats
// and skips the derived four, degraded but never wrong.
// Residual: Attack%/Defense%/Magic def% are drawn from kernel equipment
// data and exist nowhere in memory â€” not spoken (TODO).
// ---------------------------------------------------------------------------
static DWORD WINAPI StatusMenuThread(LPVOID /*unused*/)
{
    bool     was_open  = false;
    uint32_t last_slot = 0xFFFFFFFF;
    ULONGLONG next_scan_tick = 0;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 150) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_menus) {
            was_open = false;
            continue;
        }

        // v2.30.32: stale dispatch index on foreign menu screens â€” see
        // the ItemMenuThread gate. v2.30.37: same for the post-game-over
        // title prompt.
        if (MenuModuleForeignScreen() || GameOverTitleContext()) {
            was_open = false;
            continue;
        }

        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        const uint32_t screen =
            *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MENU_DISPATCH_INDEX);
        if (menu_open != 1 || field_id == 0 ||
            screen != FF7Addr::STATUSMENU_SCREEN_INDEX ||
            // v2.30.75: stale dispatch index during victory screens â€” the
            // positive discriminator is GAME_MODE (see ItemMenuThread).
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE) !=
                FF7Addr::GAME_MODE_MAIN_MENU ||
            // v2.30.27: tutorials drive the screens â€” see ItemMenuThread.
            Hooks::TutorialActive()) {
            was_open = false;
            last_slot = 0xFFFFFFFF;
            continue;
        }

        const uint32_t slot = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::CHARSEL_CHOSEN);
        if (slot > 2)
            continue;
        if (was_open && slot == last_slot)
            continue;
        was_open = true;
        last_slot = slot;

        // Equipment names want the kernel2 sections; nudge the scan if the
        // status screen is the session's first consumer.
        if (!g_k2.weapon || !g_k2.armor || !g_k2.accessory) {
            const ULONGLONG now = GetTickCount64();
            if (now >= next_scan_tick) {
                next_scan_tick = now + 3000;
                ScanKernel2Sections();
            }
        }

        // â”€â”€ Resolve the character's savemap record â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        const uint8_t char_id = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::SAVEMAP_PARTY_IDS + slot);
        uint8_t rec = char_id;
        if (char_id == 9)  rec = 6;
        if (char_id == 10) rec = 7;
        if (char_id == 0xFF || rec > 8) {
            TTS::Speak(L"Status", /*interrupt=*/true);
            continue;
        }
        const uint32_t rbase = FF7Addr::SAVEMAP_CHAR_RECORDS +
                               rec * FF7Addr::SAVEMAP_CHAR_REC_SIZE;
        const auto r8  = [&](uint32_t off) {
            return *reinterpret_cast<const volatile uint8_t*>(rbase + off); };
        const auto r16 = [&](uint32_t off) {
            return *reinterpret_cast<const volatile uint16_t*>(rbase + off); };
        const auto r32 = [&](uint32_t off) {
            return *reinterpret_cast<const volatile uint32_t*>(rbase + off); };

        // â”€â”€ Char-data block (effective stats), with staleness guard â”€â”€â”€â”€
        const uint32_t cbase = FF7Addr::BATTLE_CHAR_BLOCK +
                               slot * FF7Addr::BATTLE_CHAR_SLOT_STRIDE;
        const auto c16 = [&](uint32_t off) {
            return *reinterpret_cast<const volatile uint16_t*>(cbase + off); };
        const bool block_ok =
            c16(FF7Addr::BCHAR_OFF_HP)     == r16(FF7Addr::SAVEMAP_CHAR_HP_OFF) &&
            c16(FF7Addr::BCHAR_OFF_HP + 2) == r16(FF7Addr::SAVEMAP_CHAR_MAXHP_OFF);
        if (!block_ok)
            Log::Write("[FF7Access] STATUS char block stale â€” base stats only");

        uint8_t stats[6];   // str, vit, mag, spr, dex, luck (internal order)
        for (int i = 0; i < 6; ++i)
            stats[i] = block_ok
                ? *reinterpret_cast<const volatile uint8_t*>(
                      cbase + FF7Addr::BCHAR_OFF_EFF_STATS + i)
                : r8(0x02 + i);

        // â”€â”€ Compose the sheet (screen order) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        wchar_t label[64];
        PartySlotLabel(static_cast<uint8_t>(slot), label, _countof(label));
        wchar_t head[256];
        _snwprintf_s(head, _countof(head), _TRUNCATE,
            L"Status. %ls, level %u. HP %u of %u. MP %u of %u. "
            L"Experience %lu, %lu to next level. Limit level %u. ",
            label,
            static_cast<unsigned>(r8(FF7Addr::SAVEMAP_CHAR_LEVEL_OFF)),
            static_cast<unsigned>(r16(FF7Addr::SAVEMAP_CHAR_HP_OFF)),
            static_cast<unsigned>(r16(FF7Addr::SAVEMAP_CHAR_MAXHP_OFF)),
            static_cast<unsigned>(r16(FF7Addr::SAVEMAP_CHAR_MP_OFF)),
            static_cast<unsigned>(r16(FF7Addr::SAVEMAP_CHAR_MAXMP_OFF)),
            static_cast<unsigned long>(r32(FF7Addr::SAVEMAP_CHAR_EXP_OFF)),
            static_cast<unsigned long>(r32(FF7Addr::SAVEMAP_CHAR_EXPNEXT_OFF)),
            static_cast<unsigned>(r8(FF7Addr::SAVEMAP_CHAR_LIMITLVL_OFF)));
        std::wstring msg = head;

        wchar_t part[192];
        _snwprintf_s(part, _countof(part), _TRUNCATE,
            L"Strength %u. Dexterity %u. Vitality %u. Magic %u. "
            L"Spirit %u. Luck %u. ",
            stats[0], stats[4], stats[1], stats[2], stats[3], stats[5]);
        msg += part;

        if (block_ok) {
            _snwprintf_s(part, _countof(part), _TRUNCATE,
                L"Attack %u. Defense %u. Magic attack %u. Magic defense %u. ",
                static_cast<unsigned>(c16(FF7Addr::BCHAR_OFF_ATTACK)),
                static_cast<unsigned>(c16(FF7Addr::BCHAR_OFF_DEFENSE)),
                static_cast<unsigned>(c16(FF7Addr::BCHAR_OFF_MAGIC_ATK)),
                static_cast<unsigned>(c16(FF7Addr::BCHAR_OFF_MAGIC_DEF)));
            msg += part;
        }

        // Equipment names via the v2.31 kernel sections; numeric fallback.
        struct EquipLine {
            const wchar_t* caption;
            uint8_t        id;
            const uint8_t** section;
            const char*    sig;
        } lines[3] = {
            { L"Weapon",    r8(FF7Addr::SAVEMAP_CHAR_WEAPON_OFF),
              &g_k2.weapon,    "Buster Sword|" },
            { L"Armor",     r8(FF7Addr::SAVEMAP_CHAR_ARMOR_OFF),
              &g_k2.armor,     "Bronze Bangle|" },
            { L"Accessory", r8(FF7Addr::SAVEMAP_CHAR_ACCESS_OFF),
              &g_k2.accessory, "Power Wrist|" },
        };
        for (const EquipLine& e : lines) {
            if (e.id == 0xFF) {
                msg += e.caption;
                msg += L", none. ";
                continue;
            }
            std::wstring name;
            if (SectionEntryText(ValidatedSection(e.section, e.sig), e.id, name)) {
                msg += e.caption;
                msg += L", ";
                msg += name;
                msg += L". ";
            } else {
                _snwprintf_s(part, _countof(part), _TRUNCATE,
                             L"%ls %u. ", e.caption, e.id);
                msg += part;
            }
        }

        char dbg[128];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] STATUS slot=%lu rec=%u block_ok=%d",
            static_cast<unsigned long>(slot), rec, block_ok ? 1 : 0);
        Log::Write(dbg);
        TTS::Speak(msg, /*interrupt=*/true);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// BATTLE SCENE-MESSAGE reader (v2.36). The battle text display queue carries
// enemy AI dialogue â€” the scorpion's "Attack while it's tail's up!" warning
// and every other scene.bin message â€” a channel no other announcer touches
// (v2.7 speaks ability names from the flash struct; this is separate text).
// Read them from the scene message block and speak on new appearance.
//
// Addresses + the section-8 text lookup are static (ff7_battle_text_static.py
// / ff7_kernel2_text_disasm.py, 2026-07-19); the reader is shipped
// speculatively (the scorpion is a one-shot) with debug logging, exactly like
// the timer. Dedup is by buffer_idx VALUE, not queue slot, so FFNx's queue
// compaction can't re-trigger a lingering message; a message that fully
// leaves and returns (tail down then up again) re-speaks by design.
// ---------------------------------------------------------------------------
static bool DecodeSceneMessage(int16_t buffer_idx, std::wstring& out)
{
    if (buffer_idx < FF7Addr::SCENE_MSG_MIN_IDX)
        return false;
    const uint32_t off_addr = FF7Addr::SCENE_MSG_OFFSETS +
        static_cast<uint32_t>(buffer_idx - FF7Addr::SCENE_MSG_MIN_IDX) * 2u;
    if (!IsReadableSpan(reinterpret_cast<const void*>(off_addr), 2))
        return false;
    const uint16_t off = *reinterpret_cast<const volatile uint16_t*>(off_addr);
    const uint8_t* text = reinterpret_cast<const uint8_t*>(
        FF7Addr::SCENE_MSG_BASE + off);
    if (!IsReadableSpan(text, 1) || text[0] == 0xFF)
        return false;   // unreadable or empty
    out = FF7Text::Decode(reinterpret_cast<const char*>(text));
    for (wchar_t c : out)
        if (c != L' ' && c != L'\n')
            return true;
    return false;   // blank after decode
}

static DWORD WINAPI BattleMessageThread(LPVOID /*unused*/)
{
    std::set<int16_t> prev_present;   // buffer_idx values in the queue last poll

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 150) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_battle) {
            prev_present.clear();
            continue;
        }
        const uint8_t game_mode =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE);
        if (game_mode != 2) {
            prev_present.clear();
            continue;
        }

        std::set<int16_t> cur;
        for (uint32_t i = 0; i < FF7Addr::BATTLE_TEXT_QUEUE_LEN; ++i) {
            const int16_t bidx = *reinterpret_cast<const volatile int16_t*>(
                FF7Addr::BATTLE_TEXT_QUEUE +
                i * FF7Addr::BATTLE_TEXT_QUEUE_STRIDE);
            if (bidx >= FF7Addr::SCENE_MSG_MIN_IDX)
                cur.insert(bidx);
        }
        for (int16_t bidx : cur) {
            if (prev_present.count(bidx))
                continue;   // already present last poll â€” spoken once
            std::wstring text;
            if (DecodeSceneMessage(bidx, text)) {
                char dbg[128];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] BATTLE scene msg idx=0x%X => %ls",
                    static_cast<unsigned>(bidx), text.c_str());
                Log::Write(dbg);
                // Queue behind in-flight action speech, don't clobber it.
                TTS::Speak(text, /*interrupt=*/false);
            } else {
                char dbg[80];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] BATTLE scene msg idx=0x%X undecodable",
                    static_cast<unsigned>(bidx));
                Log::Write(dbg);
            }
        }
        prev_present.swap(cur);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Battle status-effect names (v2.30.89).
//
// Spoken names for the 32 bits of the battle actor-vars statusMask (the
// word at struct offset 0x00 that the defeat/KO watchers already poll for
// bit 0x01 Death). Bit order is the kernel's own status order — the same
// layout the character records, scene.bin immunity masks, and FFNx's
// battle_actor_vars all share, so no translation table is needed.
//
// nullptr = bit deliberately NOT announced here:
//   bit 0 Death      — the defeat / "is down" watchers own that moment;
//   bit 1 Near-death — derived from HP crossing max/4, and the damage
//                      line's ", N left" suffix already covers exactly
//                      that threshold; announcing the bit too would fire
//                      a spurious "status" line on ordinary damage.
// ---------------------------------------------------------------------------
static const wchar_t* const kBattleStatusName[32] = {
    /* 0x00000001 */ nullptr,              // Death (defeat watcher owns)
    /* 0x00000002 */ nullptr,              // Near-death (", N left" owns)
    /* 0x00000004 */ L"sleep",
    /* 0x00000008 */ L"poison",
    /* 0x00000010 */ L"sadness",
    /* 0x00000020 */ L"fury",
    /* 0x00000040 */ L"confusion",
    /* 0x00000080 */ L"silence",
    /* 0x00000100 */ L"haste",
    /* 0x00000200 */ L"slow",
    /* 0x00000400 */ L"stop",
    /* 0x00000800 */ L"frog",
    /* 0x00001000 */ L"small",
    /* 0x00002000 */ L"slow numb",
    /* 0x00004000 */ L"petrify",
    /* 0x00008000 */ L"regen",
    /* 0x00010000 */ L"barrier",
    /* 0x00020000 */ L"magic barrier",
    /* 0x00040000 */ L"reflect",
    /* 0x00080000 */ L"dual",
    /* 0x00100000 */ L"shield",
    /* 0x00200000 */ L"death sentence",
    /* 0x00400000 */ L"manipulated",
    /* 0x00800000 */ L"berserk",
    /* 0x01000000 */ L"peerless",
    /* 0x02000000 */ L"paralyzed",
    /* 0x04000000 */ L"darkness",
    /* 0x08000000 */ L"seizure",
    /* 0x10000000 */ L"death force",
    /* 0x20000000 */ L"resist",
    /* 0x40000000 */ L"lucky girl",
    /* 0x80000000 */ L"imprisoned",
};

// Bits the status watcher reacts to: everything except Death / Near-death
// (the two nullptr rows above). Death aside from being owned elsewhere also
// flaps during battle init; masking both keeps the settle window from
// restarting on changes nothing here would speak.
static constexpr uint32_t kBattleStatusTrackedMask = 0xFFFFFFFCu;

static DWORD WINAPI BattleActionThread(LPVOID /*unused*/)
{
    uint8_t last_actor_id = 0xFF;   // 0xFF = sentinel; announce on next valid actor change

    // v2.12: per-enemy-slot liveness tracking for defeat announcements.
    // A slot must first be SEEN alive (plausible HP, no Death status) before
    // its death can announce â€” battle-init zeroes and empty formation slots
    // therefore never produce a false "defeated". Indexed by actor slot 4-9
    // (index 0 = slot 4). Reset whenever the battle module is not active.
    bool enemy_was_alive[6] = {};

    // v2.30: party KO / revival announcements ("Cloud is down" / "Cloud is
    // back up"), user-requested 2026-07-13 and deferred until the party had
    // a second member. Party slots need THREE states where enemies needed a
    // bool: a member can start the battle already KO'd (carried over from
    // the previous fight), and that must be recorded silently â€” the
    // seen-alive-first rule means no "is down" announce, but a later
    // Phoenix Down still owes the player an "is back up". Reset with the
    // enemy tracker whenever the battle module is not active.
    enum class PartyLife : uint8_t { Unseen, Alive, Dead };
    PartyLife party_life[3] = {};

    // v2.30.84: HP-delta damage/heal tracking (user request: the floating
    // damage number a sighted player sees, spoken). No new addresses — the
    // same actor-vars the defeat/KO watchers above poll. Per-slot baseline
    // tracking: when a slot's (currentHP, statusMask) tuple moves and then
    // holds still for DAMAGE_SETTLE_MS, the accumulated difference from
    // the baseline is reported once. The settle window exists because one
    // game action can write HP more than once (multi-hit attacks,
    // damage+drain) — reporting per poll would spray fragments; the
    // settled sum matches what the player needs ("what did that action
    // cost me") in the fewest words.
    //
    // v2.30.89 extends the tuple with the statusMask (masked to
    // kBattleStatusTrackedMask) so inflicted/removed status effects report
    // through the same window: an attack that writes damage AND poison
    // settles once and produces one fragment ("Cloud minus 50 HP, poison").
    //
    // base_max is part of the baseline: multi-wave battles REUSE enemy
    // slots for new creatures, and a slot whose maxHP changed is a new
    // occupant, not a hit — re-baseline silently (same reasoning as the
    // seen-alive-first rule above).
    struct HpWatch {
        bool      seen;        // baseline captured (first plausible read is silent)
        int32_t   base_hp;     // HP at the last report (delta reference)
        int32_t   base_max;    // maxHP the baseline was read under (occupant id)
        int32_t   last_hp;     // most recent read
        uint32_t  base_status; // statusMask at the last report (tracked bits only)
        uint32_t  last_status; // most recent read (tracked bits only)
        ULONGLONG change_tick; // when the tuple last moved; 0 = nothing pending
    };
    HpWatch hp_watch[10] = {};   // indexed by actor slot; 3 is an engine gap
    constexpr ULONGLONG DAMAGE_SETTLE_MS = 400;

    // v2.30.89: the combined ACTION REPORT (user request 2026-08-05:
    // "[enemy] [attack-type] [character name] minus [amount] hp" — one
    // line saying what attacked, whom, and what it did, and the same for
    // healing and status effects). The action announce no longer speaks on
    // its own: it OPENS a report holding "actor, action" while the effect
    // watcher below attributes each settled HP/status change to it as a
    // per-target fragment. The report speaks as ONE utterance once its
    // effects go quiet:
    //   "MP 1, Machine Gun, Cloud minus 96 HP."
    //   "Cloud, Cure, Barret plus 200 HP."
    //   "MP 1, Bio, Cloud minus 50 HP, poison."
    //   "MP 1, Machine Gun, Cloud minus 96 HP, Barret minus 80 HP."
    // Attribution is temporal — changes that settle while the report is
    // open belong to it — because the engine's damage-display writer was
    // never located (the same reason misses/crits are invisible to HP
    // polling). A counter-hit landing inside the window folds into the
    // attacker's line; accepted, it is the same simultaneity a sighted
    // player reads off one glance at the battle screen.
    struct ActionReport {
        bool         open;
        bool         bare_spoken;   // no-effect deadline already spoke "actor, action."
        uint32_t     gen;           // identity for late flash-name upgrades (v2.30.90)
        wchar_t      actor[64];
        std::wstring action;
        ULONGLONG    open_tick;
        ULONGLONG    frag_tick;       // last fragment append; 0 = none yet
        ULONGLONG    linger_deadline; // prev-slot TTL; 0 while current (v2.30.90)
        std::wstring frag[10];        // per-actor-slot accumulated fragment
        uint8_t      order[10];       // slots in first-fragment order
        uint8_t      n_frags;
    };
    ActionReport report = {};        // the acting turn's report
    // v2.30.90: when a new turn opens, the outgoing report is NOT flushed
    // immediately — it moves here and lingers briefly. The 2026-08-05 logs
    // showed why: the settle window means a change spoken at T was WRITTEN
    // at T-400ms, and the engine starts the next actor's turn the moment
    // damage displays — so the previous action's damage routinely settles
    // just AFTER the next report opened, and attaching by "whichever
    // report is open" misattributed it (Tifa's limit damage spoke as
    // "Barret, Attack, Smogger 2 minus 49 HP", log.3 13:47:30). Fragments
    // are routed by WRITE time vs open time (see the routing below); the
    // lingering slot catches everything written under the previous action.
    ActionReport prev_report = {};
    uint32_t     report_gen_counter = 0;
    // How long after the LAST settled effect the report waits before
    // speaking: long enough to collect every slot of a multi-target action
    // (they settle within a poll or two of each other), short enough that
    // the line lands while the hit still feels like "just now".
    constexpr ULONGLONG REPORT_QUIET_MS = 700;
    // An action that produced no HP/status change by this deadline (miss,
    // Sense, an untracked buff) speaks bare — "MP 1, Machine Gun." — and
    // the report then STAYS open so a late effect (summon and limit
    // animations outlast any reasonable deadline) still speaks as a
    // grouped fragment line instead of being dropped or misattributed.
    // 5000 (was 4000 in v2.30.89): the logs caught Beam Gun's ~4.1s and
    // Beat Rush-class ~4.8s animations speaking "(no effect)" moments
    // before their damage settled — and the report now opens at TURN
    // DETECTION, earlier than the old flash-time open, so the clock needs
    // the extra second.
    constexpr ULONGLONG REPORT_NO_EFFECT_MS = 5000;
    // How long a superseded report lingers for write-lag fragments: a
    // fragment belonging to the old action settles at most SETTLE(400ms)
    // after its write, and the write predates the new turn — 800ms covers
    // it with margin.
    constexpr ULONGLONG REPORT_PREV_LINGER_MS = 800;
    // Minimum time from a turn's ENGINE start to its first possible HP
    // write (windup + swing animation — the fastest observed melee lands
    // ~900ms in; log.3 13:47:30 showed the previous action's damage being
    // written 40ms after the next turn began). A change written earlier
    // than this into the current turn belongs to the PREVIOUS action.
    constexpr ULONGLONG TURN_MIN_DAMAGE_MS = 300;

    // v2.30.90: the engine-side turn-start anchor. Phase-1 turn DETECTION
    // waits for the model-state commandID, which the engine can write up
    // to ~1s after it switches G_ACTIVE_ACTOR_ID (2026-08-05 log.3
    // 13:42:36: Cloud's damage was OBSERVED 100ms before his turn's
    // detection) — so reports are anchored to the moment the actor id
    // itself changed, tracked here independent of the command gate.
    uint8_t   raw_last_actor  = 0xFF;
    ULONGLONG turn_start_tick = 0;

    // v2.30.90: battle-entry grace. At mode->2 the actor-vars still hold
    // the PREVIOUS battle's end values (or partial init) — plausible
    // numbers, so the v2.30.84 "first plausible read is silent" rule
    // baselined on them and then spoke the engine's real init writes as
    // events: "Cloud plus 117 HP"×3 in one tick after a tent (the
    // [TENTHP] tester report, log.2 13:09:48), ghost enemy heals and a
    // ghost "poison removed" at a rematch (log.3 13:44:03). During the
    // grace window settles still FOLD into the baseline — they just don't
    // speak. Real damage can't land this early: the first ATB action is
    // several seconds out.
    ULONGLONG battle_entry_tick = 0;
    constexpr ULONGLONG BATTLE_INIT_GRACE_MS = 2500;

    // v2.12.1: defeats are NOT spoken at detection time. The v2.12 debug log
    // proved the killing blow's tick also fires action announcements (flash
    // resolution + next-turn) whose interrupt=true cancelled the queued
    // defeat speech within the same millisecond, every time. Instead,
    // detected defeats accumulate here and speak (interrupt=false, so they
    // queue after in-flight playback) once NO thread has issued speech for
    // DEFEAT_QUIET_MS â€” the first quiet gap after the action burst. The 5s
    // cap guarantees delivery even under pathological continuous chatter.
    std::wstring pending_defeats;
    ULONGLONG    first_defeat_tick = 0;
    constexpr ULONGLONG DEFEAT_QUIET_MS = 600;
    constexpr ULONGLONG DEFEAT_MAX_WAIT_MS = 5000;

    // v2.12.1 diagnostics (debug_log only): last observed (cur, max, status)
    // per enemy slot, so every real change gets one log line â€” the in-game
    // trail for diagnosing WHY a defeat did or didn't announce.
    int32_t  dbg_last_cur[6]    = {};
    int32_t  dbg_last_max[6]    = {};
    uint32_t dbg_last_status[6] = {};

    // Rate limiter for kernel2 section re-scans while sections are missing.
    ULONGLONG next_scan_tick = 0;

    // Pending flash-message wait state (see ANNOUNCE TIMING above).
    // v2.30.90, combine mode: pending no longer defers the ANNOUNCE (the
    // report opens at turn detection with the generic label) — it defers
    // the NAME: when the flash resolves, the report whose gen matches
    // pending_gen gets its action upgraded in place, wherever it now
    // lives (current or linger slot), as long as it hasn't spoken yet.
    bool      pending           = false;
    uint8_t   pending_cmd       = 0;      // model-state commandID of the pending turn
    uint32_t  pending_s0_cmd    = 0;      // struct snapshot at turn start
    uint32_t  pending_s0_idx    = 0;
    ULONGLONG pending_deadline  = 0;
    uint32_t  pending_gen       = 0;      // report to name-upgrade (combine mode)
    wchar_t   pending_actor[64] = {};   // 64: fits a 32-char enemy name + " A" suffix

    // v2.13: announces that land close together must CHAIN, not clobber.
    // The v2.12 traces showed the pending-flash flush ("MP B, attacks") and
    // the next turn's announce ("Cloud, Attack") firing in the SAME 50ms
    // tick â€” the second's interrupt=true cancelled the first before a
    // syllable played, so enemy actions were routinely inaudible whenever
    // the player's turn arrived at the same instant. An announce within
    // ANNOUNCE_CHAIN_MS of the previous one therefore queues
    // (interrupt=false) behind it instead of interrupting; both are per-turn
    // battle events the player needs to hear, and both are short. Announces
    // farther apart keep interrupt=true (stale leftover speech SHOULD be
    // cut off by a fresh turn).
    ULONGLONG last_announce_tick = 0;
    constexpr ULONGLONG ANNOUNCE_CHAIN_MS = 1500;

    // Speak whatever the given report currently holds and reset it.
    // Fragments join in first-touch order. When the bare "actor, action."
    // already went out at the no-effect deadline, only the late fragments
    // speak — repeating the action would read as a second attack.
    const auto report_flush = [&](ActionReport& r, const char* why) {
        if (!r.open)
            return;
        std::wstring text;
        if (!r.bare_spoken) {
            text  = r.actor;
            text += L", ";
            text += r.action;
        }
        for (uint8_t i = 0; i < r.n_frags; ++i) {
            if (!text.empty())
                text += L", ";
            text += r.frag[r.order[i]];
        }
        r.open        = false;
        r.bare_spoken = false;
        for (auto& f : r.frag)
            f.clear();
        r.n_frags         = 0;
        r.frag_tick       = 0;
        r.linger_deadline = 0;
        if (text.empty())
            return;   // bare already spoken and nothing landed after it
        text += L".";
        const ULONGLONG now = GetTickCount64();
        const bool chain = (now - last_announce_tick) < ANNOUNCE_CHAIN_MS;
        last_announce_tick = now;
        char dbg[224];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] BATTLE report (%s)%ls => %ls",
            why, chain ? L" chained" : L"", text.c_str());
        Log::Write(dbg);
        TTS::Speak(text, /*interrupt=*/!chain);
    };

    // Announce helper: "[actor], [name-or-generic]".  Written as a lambda so
    // both the immediate path and the deferred flash path share it.
    //
    // v2.30.89: with damage or status speech enabled this no longer speaks
    // — it opens the combined action report and lets the effect watcher
    // finish the sentence. v2.30.90: the outgoing report moves to the
    // linger slot instead of flushing (write-lag fragments still find it;
    // see prev_report above); a report already TWO turns old flushes now.
    // With both toggles off there is nothing to combine and the original
    // immediate announce is kept.
    const auto announce = [&](const wchar_t* actor_label, uint8_t command_id,
                              const std::wstring* exact_name) {
        wchar_t generic_buf[32];
        const wchar_t* action = exact_name ? exact_name->c_str()
            : GenericActionLabel(command_id, generic_buf, _countof(generic_buf));
        const bool combine = Config::Get().speak_battle_damage ||
                             Config::Get().speak_battle_status;
        if (combine) {
            if (report.open) {
                report_flush(prev_report, "superseded");
                prev_report = report;
                prev_report.linger_deadline =
                    GetTickCount64() + REPORT_PREV_LINGER_MS;
                report = ActionReport{};
            }
            report.open        = true;
            report.bare_spoken = false;
            report.gen         = ++report_gen_counter;
            wcscpy_s(report.actor, actor_label);
            report.action          = action;
            // Anchor to the engine's turn start (raw actor-id change),
            // not to detection time — detection can lag the engine by up
            // to ~1s waiting for the commandID write, and the routing
            // below compares HP-write times against this anchor.
            report.open_tick       = turn_start_tick ? turn_start_tick
                                                     : GetTickCount64();
            report.frag_tick       = 0;
            report.linger_deadline = 0;
            char dbg[192];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] BATTLE cmd=0x%02X %ls report-open gen=%lu => %ls, %ls",
                static_cast<unsigned>(command_id),
                exact_name ? L"named" : L"generic",
                static_cast<unsigned long>(report.gen), actor_label, action);
            Log::Write(dbg);
            return;
        }
        wchar_t msg[128] = {};
        _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"%ls, %ls", actor_label, action);
        const ULONGLONG now = GetTickCount64();
        const bool chain = (now - last_announce_tick) < ANNOUNCE_CHAIN_MS;
        last_announce_tick = now;
        char dbg[160];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] BATTLE cmd=0x%02X %ls%ls => %ls",
            static_cast<unsigned>(command_id),
            exact_name ? L"named" : L"generic",
            chain ? L" chained" : L"", msg);
        Log::Write(dbg);
        TTS::Speak(msg, /*interrupt=*/!chain);
    };

    for (;;) {
        // Sleep 50ms, or wake immediately if Proxy::Shutdown() signals the event.
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_battle) {
            last_actor_id = 0xFF;
            pending = false;
            continue;
        }

        // ---- v2.12: enemy defeat announcements --------------------------
        // Watch each enemy slot's actor-vars (HP pair + statusMask) every
        // poll while the battle module is active. Death is primarily
        // "currentHP <= 0" with the kernel Death status bit (0x01) as a
        // secondary signal; both only count after the slot was seen alive
        // (see enemy_was_alive above). Runs BEFORE the active-actor
        // classification below because that path `continue`s on slots this
        // check must not miss.
        {
            const uint8_t game_mode =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE);
            if (game_mode != 2) {
                memset(enemy_was_alive, 0, sizeof(enemy_was_alive));
                party_life[0] = party_life[1] = party_life[2] = PartyLife::Unseen;
                memset(hp_watch, 0, sizeof(hp_watch));
                battle_entry_tick = 0;   // re-arm the init grace (v2.30.90)
                // Reports still open at module exit speak what they have —
                // normally the quiet timer fired long before, but a
                // battle-ending action must not swallow its own line.
                report_flush(prev_report, "battle exit");
                report_flush(report, "battle exit");
            } else {
                // First poll of a new battle: stamp the entry for the
                // init-grace window (cleared to 0 whenever mode leaves 2).
                if (battle_entry_tick == 0)
                    battle_entry_tick = GetTickCount64();
                for (uint8_t slot = 4; slot <= 9; ++slot) {
                    const uint32_t base = FF7Addr::BATTLE_ACTOR_VARS +
                        static_cast<uint32_t>(slot) * FF7Addr::BATTLE_ACTOR_VARS_STRIDE;
                    const uint32_t status = *reinterpret_cast<const volatile uint32_t*>(
                        base + 0x00);   // statusMask; bit 0x01 = Death
                    const int32_t cur = *reinterpret_cast<const volatile int32_t*>(
                        base + FF7Addr::BAVARS_OFF_CURRENT_HP);
                    const int32_t max = *reinterpret_cast<const volatile int32_t*>(
                        base + FF7Addr::BAVARS_OFF_MAX_HP);

                    // Struct populated with sane values? (max == 0 means the
                    // slot is empty or was just memset by battle init.)
                    const bool plausible = (max > 0 && max <= 10000000);
                    const bool dead  = plausible && (cur <= 0 || (status & 0x01));
                    const bool alive = plausible && cur > 0 && cur <= max &&
                                       !(status & 0x01);

                    bool& was_alive = enemy_was_alive[slot - 4];

                    // v2.12.1 diagnostics: one line per real value change.
                    if (Config::Get().debug_log) {
                        const uint8_t di = slot - 4;
                        if (cur != dbg_last_cur[di] || max != dbg_last_max[di] ||
                            status != dbg_last_status[di]) {
                            dbg_last_cur[di]    = cur;
                            dbg_last_max[di]    = max;
                            dbg_last_status[di] = status;
                            char dbg[160];
                            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                                "[FF7Access] BATTLE hpwatch slot=%u cur=%ld max=%ld "
                                "status=%08lX alive=%d dead=%d was_alive=%d",
                                static_cast<unsigned>(slot),
                                static_cast<long>(cur), static_cast<long>(max),
                                static_cast<unsigned long>(status),
                                alive ? 1 : 0, dead ? 1 : 0, was_alive ? 1 : 0);
                            Log::Write(dbg);
                        }
                    }
                    if (was_alive && dead) {
                        was_alive = false;
                        std::wstring name;
                        if (!EnemySlotName(slot, name)) {
                            wchar_t fallback[16];
                            _snwprintf_s(fallback, _countof(fallback), _TRUNCATE,
                                         L"enemy %u", static_cast<unsigned>(slot - 3u));
                            name = fallback;
                        }
                        name += L" defeated";
                        char dbg[128];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                            "[FF7Access] BATTLE defeat detected slot=%u => %ls",
                            static_cast<unsigned>(slot), name.c_str());
                        Log::Write(dbg);
                        // Deferred: see pending_defeats above for why this
                        // must NOT speak here.
                        if (pending_defeats.empty())
                            first_defeat_tick = GetTickCount64();
                        else
                            pending_defeats += L". ";
                        pending_defeats += name;
                    } else if (alive) {
                        was_alive = true;
                    }
                }

                // ---- v2.30: party KO / revival watcher ------------------
                // Same actor-vars reads and plausibility rules as the enemy
                // loop above, over party slots 0-2. Announcements ride the
                // SAME pending_defeats quiet-gap buffer: a KO lands in the
                // same tick as the killing action's announce burst (the
                // v2.12.1 lesson), so speaking here would be cancelled
                // within the millisecond. Phrasing is deliberately distinct
                // from enemies ("is down", not "defeated") so the player
                // knows which side lost someone without hearing the name.
                for (uint8_t slot = 0; slot <= 2; ++slot) {
                    const uint32_t base = FF7Addr::BATTLE_ACTOR_VARS +
                        static_cast<uint32_t>(slot) * FF7Addr::BATTLE_ACTOR_VARS_STRIDE;
                    const uint32_t status = *reinterpret_cast<const volatile uint32_t*>(
                        base + 0x00);   // statusMask; bit 0x01 = Death
                    const int32_t cur = *reinterpret_cast<const volatile int32_t*>(
                        base + FF7Addr::BAVARS_OFF_CURRENT_HP);
                    const int32_t max = *reinterpret_cast<const volatile int32_t*>(
                        base + FF7Addr::BAVARS_OFF_MAX_HP);

                    // Empty party slot (2-member party) never becomes
                    // plausible, so it stays Unseen and never announces.
                    const bool plausible = (max > 0 && max <= 10000000);
                    const bool dead  = plausible && (cur <= 0 || (status & 0x01));
                    const bool alive = plausible && cur > 0 && cur <= max &&
                                       !(status & 0x01);

                    PartyLife& life = party_life[slot];
                    const wchar_t* event_suffix = nullptr;
                    if (dead && life != PartyLife::Dead) {
                        // Unseen -> Dead records a battle-start KO silently
                        // (see party_life above); only Alive -> Dead speaks.
                        if (life == PartyLife::Alive)
                            event_suffix = L" is down";
                        life = PartyLife::Dead;
                    } else if (alive && life != PartyLife::Alive) {
                        if (life == PartyLife::Dead)
                            event_suffix = L" is back up";
                        life = PartyLife::Alive;
                    }
                    if (!event_suffix)
                        continue;

                    wchar_t label[64];
                    PartySlotLabel(slot, label, _countof(label));
                    std::wstring msg = label;
                    msg += event_suffix;
                    char dbg[160];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] BATTLE party slot=%u cur=%ld max=%ld "
                        "status=%08lX => %ls",
                        static_cast<unsigned>(slot),
                        static_cast<long>(cur), static_cast<long>(max),
                        static_cast<unsigned long>(status), msg.c_str());
                    Log::Write(dbg);
                    if (pending_defeats.empty())
                        first_defeat_tick = GetTickCount64();
                    else
                        pending_defeats += L". ";
                    pending_defeats += msg;
                }

                // ---- v2.30.84/.89: damage, healing, status effects ------
                // See hp_watch / ActionReport above. Runs over BOTH sides
                // every poll: party slots 0-2 report hits taken (the "how
                // bad was that" the sighted player reads off the floating
                // number), enemy slots 4-9 report the player's own damage
                // dealt (the number over the enemy — visible to sighted
                // players even without Sense, so no Sense gate here; enemy
                // REMAINING HP is what stays hidden and is never spoken).
                for (uint8_t slot = 0; slot <= 9; ++slot) {
                    if (slot == 3)
                        continue;   // engine gap between party and enemies

                    const uint32_t base = FF7Addr::BATTLE_ACTOR_VARS +
                        static_cast<uint32_t>(slot) * FF7Addr::BATTLE_ACTOR_VARS_STRIDE;
                    const int32_t cur = *reinterpret_cast<const volatile int32_t*>(
                        base + FF7Addr::BAVARS_OFF_CURRENT_HP);
                    const int32_t max = *reinterpret_cast<const volatile int32_t*>(
                        base + FF7Addr::BAVARS_OFF_MAX_HP);
                    // Tracked status bits only (see kBattleStatusTrackedMask)
                    // — untracked bits flapping must not restart the settle
                    // window or diff as phantom changes.
                    const uint32_t status = kBattleStatusTrackedMask &
                        *reinterpret_cast<const volatile uint32_t*>(base + 0x00);

                    HpWatch& w = hp_watch[slot];

                    // Same plausibility rule as the watchers above; an
                    // implausible read (battle init memset, empty slot)
                    // drops the baseline so nothing computes a delta
                    // against garbage.
                    const bool plausible = (max > 0 && max <= 10000000 &&
                                            cur >= 0 && cur <= max);
                    if (!plausible) {
                        w.seen = false;
                        continue;
                    }
                    if (!w.seen || max != w.base_max) {
                        // First plausible read, or a new occupant in a
                        // reused slot (maxHP changed): silent re-baseline.
                        w.seen        = true;
                        w.base_hp     = cur;
                        w.base_max    = max;
                        w.last_hp     = cur;
                        w.base_status = status;
                        w.last_status = status;
                        w.change_tick = 0;
                        continue;
                    }

                    const ULONGLONG now = GetTickCount64();
                    if (cur != w.last_hp || status != w.last_status) {
                        w.last_hp     = cur;
                        w.last_status = status;
                        w.change_tick = now;   // (re)start the settle window
                        continue;
                    }
                    if (w.change_tick == 0 || now - w.change_tick < DAMAGE_SETTLE_MS)
                        continue;

                    // The tuple moved and has now held still: fold it into
                    // the baseline FIRST (even when speech below is
                    // suppressed) so a later change never re-reports this.
                    // write_tick is captured before the reset — it is the
                    // moment of the ENGINE'S last write, which is what
                    // fragment routing compares against report open times
                    // (a change written before this turn opened belongs to
                    // the previous action).
                    const int32_t   before     = w.base_hp;
                    const int32_t   after      = w.last_hp;
                    const uint32_t  status_was = w.base_status;
                    const uint32_t  status_now = w.last_status;
                    const ULONGLONG write_tick = w.change_tick;
                    w.base_hp     = after;
                    w.base_status = status_now;
                    w.change_tick = 0;

                    // v2.30.90 battle-entry grace: init writes fold into
                    // the baseline silently (see battle_entry_tick above —
                    // the [TENTHP] ghost-heal class).
                    if (write_tick - battle_entry_tick < BATTLE_INIT_GRACE_MS) {
                        if (Config::Get().debug_log) {
                            char dbg[128];
                            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                                "[FF7Access] BATTLE dmg slot=%u delta=%ld "
                                "grace-suppressed (entry+%lums)",
                                static_cast<unsigned>(slot),
                                static_cast<long>(before - after),
                                static_cast<unsigned long>(write_tick - battle_entry_tick));
                            Log::Write(dbg);
                        }
                        continue;
                    }

                    const bool want_dmg    = Config::Get().speak_battle_damage;
                    const bool want_status = Config::Get().speak_battle_status;
                    if (!want_dmg && !want_status)
                        continue;   // tracked regardless, so toggling a
                                    // setting mid-battle starts clean

                    wchar_t who[64];
                    if (slot <= 2) {
                        PartySlotLabel(slot, who, _countof(who));
                    } else {
                        std::wstring ename;
                        if (EnemySlotName(slot, ename))
                            _snwprintf_s(who, _countof(who), _TRUNCATE,
                                         L"%ls", ename.c_str());
                        else
                            _snwprintf_s(who, _countof(who), _TRUNCATE,
                                         L"enemy %u", static_cast<unsigned>(slot - 3u));
                    }

                    // Build this slot's fragment: HP part first, then any
                    // status changes. v2.30.89 wording (user-specified):
                    // "minus 96 HP" / "plus 200 HP"; the ", N left" low-HP
                    // warning survives from v2.30.84 (spoken only when a
                    // hit leaves a party member at or below a quarter of
                    // max — the moment the on-screen HP turns yellow).
                    //
                    // Killing-blow and revival deltas are INCLUDED now
                    // (v2.30.84 suppressed them): in the combined line the
                    // number is part of the action's own sentence, not a
                    // second utterance racing the defeat/"is down"/"is
                    // back up" announce — which still follows via the
                    // quiet-gap buffer and owns the life-change wording.
                    std::wstring parts;
                    const bool hp_part = want_dmg && after != before;
                    if (hp_part) {
                        const int32_t delta = before - after;   // positive = damage
                        wchar_t hp_buf[48];
                        if (delta > 0) {
                            if (slot <= 2 && after > 0 && after * 4 <= max)
                                _snwprintf_s(hp_buf, _countof(hp_buf), _TRUNCATE,
                                             L"minus %ld HP, %ld left",
                                             static_cast<long>(delta),
                                             static_cast<long>(after));
                            else
                                _snwprintf_s(hp_buf, _countof(hp_buf), _TRUNCATE,
                                             L"minus %ld HP",
                                             static_cast<long>(delta));
                        } else {
                            _snwprintf_s(hp_buf, _countof(hp_buf), _TRUNCATE,
                                         L"plus %ld HP",
                                         static_cast<long>(-delta));
                        }
                        parts = hp_buf;
                    }
                    uint32_t gained = 0, removed = 0;
                    if (want_status) {
                        gained  = status_now & ~status_was;
                        removed = status_was & ~status_now;
                        for (int b = 0; b < 32; ++b) {
                            if (!kBattleStatusName[b])
                                continue;
                            const uint32_t bit = 1u << b;
                            if (gained & bit) {
                                if (!parts.empty()) parts += L", ";
                                parts += kBattleStatusName[b];
                            } else if (removed & bit) {
                                if (!parts.empty()) parts += L", ";
                                parts += kBattleStatusName[b];
                                parts += L" removed";
                            }
                        }
                    }
                    if (parts.empty())
                        continue;   // e.g. HP moved but damage speech is off

                    // "Cloud minus 96 HP" flows without a comma; a
                    // status-only fragment reads better with one
                    // ("Cloud, sleep").
                    std::wstring fragment = who;
                    fragment += hp_part ? L" " : L", ";
                    fragment += parts;

                    // v2.30.90 routing: attribute by WRITE time against
                    // the turn-start anchor, not by "whichever report is
                    // open". A change written at least TURN_MIN_DAMAGE_MS
                    // into the current turn belongs to it (no action can
                    // deal damage faster than its windup); anything
                    // earlier belongs to the lingering previous action —
                    // the misattribution class the 2026-08-05 logs caught
                    // (Tifa's limit damage written 40ms into Barret's
                    // turn spoke as Barret's). No previous report and the
                    // current one open = attach to current (first action
                    // of a battle; the init grace already filtered entry
                    // ghosts). Neither = orphan tick, spoken standalone.
                    ActionReport* home = nullptr;
                    const char*   home_tag = "orphan";
                    if (report.open &&
                        write_tick >= report.open_tick + TURN_MIN_DAMAGE_MS) {
                        home = &report;      home_tag = "cur";
                    } else if (prev_report.open) {
                        home = &prev_report; home_tag = "prev";
                    } else if (report.open) {
                        home = &report;      home_tag = "cur-early";
                    }

                    // Standing rule: every spoken claim ships with a log
                    // line carrying its discriminating inputs.
                    char dbg[224];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] BATTLE dmg slot=%u delta=%ld cur=%ld "
                        "max=%ld sgain=%08lX sdrop=%08lX home=%s => %ls",
                        static_cast<unsigned>(slot),
                        static_cast<long>(before - after),
                        static_cast<long>(after), static_cast<long>(max),
                        static_cast<unsigned long>(gained),
                        static_cast<unsigned long>(removed),
                        home_tag, fragment.c_str());
                    Log::Write(dbg);

                    if (home) {
                        // The same slot settling twice under one action
                        // (multi-hit spanning two windows) extends its
                        // fragment rather than repeating the name.
                        std::wstring& f = home->frag[slot];
                        if (f.empty()) {
                            home->order[home->n_frags++] = slot;
                            f = fragment;
                        } else {
                            f += L", ";
                            f += parts;
                        }
                        home->frag_tick = now;
                    } else {
                        // No action owns it (poison/regen tick between
                        // turns): standalone line, queued so it never clips
                        // an in-flight announce; stamp last_announce_tick
                        // so the NEXT turn's announce chains instead of
                        // wiping it (the v2.12.1 same-tick lesson).
                        std::wstring msg = fragment + L".";
                        last_announce_tick = now;
                        TTS::Speak(msg, /*interrupt=*/false);
                    }
                }

                // ---- v2.30.89/.90: action-report delivery ---------------
                // The lingering previous report speaks once its write-lag
                // fragments settle and go quiet, or closes at its TTL
                // (silently when it already spoke bare and nothing more
                // came). The current report speaks at its quiet timer, or
                // speaks bare at the no-effect deadline and stays open for
                // late effects (summon/limit animations).
                {
                    const ULONGLONG now = GetTickCount64();
                    if (prev_report.open) {
                        if (prev_report.frag_tick != 0 &&
                            now - prev_report.frag_tick >= REPORT_QUIET_MS)
                            report_flush(prev_report, "quiet prev");
                        else if (prev_report.frag_tick == 0 &&
                                 now >= prev_report.linger_deadline)
                            report_flush(prev_report, "linger out");
                    }
                    if (report.open) {
                        if (report.frag_tick != 0 &&
                            now - report.frag_tick >= REPORT_QUIET_MS) {
                            report_flush(report, "quiet");
                        } else if (report.frag_tick == 0 && !report.bare_spoken &&
                                   now - report.open_tick >= REPORT_NO_EFFECT_MS) {
                            std::wstring text = report.actor;
                            text += L", ";
                            text += report.action;
                            text += L".";
                            const bool chain = (now - last_announce_tick) < ANNOUNCE_CHAIN_MS;
                            last_announce_tick = now;
                            char dbg[192];
                            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                                "[FF7Access] BATTLE report (no effect)%ls => %ls",
                                chain ? L" chained" : L"", text.c_str());
                            Log::Write(dbg);
                            TTS::Speak(text, /*interrupt=*/!chain);
                            report.bare_spoken = true;
                        }
                    }
                }
            }

            // Speak accumulated defeats at the first quiet gap (or on
            // leaving battle, so a battle-ending kill is never dropped).
            // The gap must be measured FORWARD from detection, not just
            // backward from now: the death tick IS the action-burst tick
            // (v2.12.1 play test â€” "defeat spoken" and the interrupt=true
            // action announcements share one timestamp in the log), so a
            // defeat younger than the quiet window must keep waiting even
            // if nothing has spoken for a while BEFORE it.
            if (!pending_defeats.empty()) {
                const ULONGLONG now = GetTickCount64();
                const bool quiet   = now - first_defeat_tick    >= DEFEAT_QUIET_MS &&
                                     now - TTS::LastSpeakTick() >= DEFEAT_QUIET_MS;
                const bool overdue = now - first_defeat_tick >= DEFEAT_MAX_WAIT_MS;
                if (quiet || overdue || game_mode != 2) {
                    char dbg[192];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] BATTLE defeat spoken (%s) => %ls",
                        quiet ? "quiet gap" : (overdue ? "overdue" : "battle exit"),
                        pending_defeats.c_str());
                    Log::Write(dbg);
                    TTS::Speak(pending_defeats, /*interrupt=*/false);
                    pending_defeats.clear();
                }
            }
        }

        const uint8_t actor_id =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::G_ACTIVE_ACTOR_ID);

        // Classify the actor.  Slots 0â€“2 = party, 4â€“9 = enemy.  Anything else
        // means the battle module is not active.
        const bool is_party = (actor_id <= 2);
        const bool is_enemy = (actor_id >= 4 && actor_id <= 9);

        // v2.30.90: stamp the engine turn start on the RAW actor change,
        // before the commandID gate below can delay detection (see
        // turn_start_tick above). Only a change TO a valid actor is a
        // turn start; changes to idle values just reset the tracker.
        if (actor_id != raw_last_actor) {
            raw_last_actor = actor_id;
            if (is_party || is_enemy)
                turn_start_tick = GetTickCount64();
        }
        if (!is_party && !is_enemy) {
            last_actor_id = 0xFF;
            pending = false;
            continue;
        }

        // commandID == 0 â†’ slot idle (process start / model state cleared):
        // the primary not-in-battle gate.
        const uint8_t command_id = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::G_BATTLE_MODEL_STATE
            + static_cast<uint32_t>(actor_id) * FF7Addr::BATTLE_MODEL_STATE_STRIDE
            + FF7Addr::BATTLE_COMMAND_ID_OFFSET);

        if (command_id == 0) {
            last_actor_id = 0xFF;
            pending = false;
            continue;
        }

        // Current flash-message struct values (see ff7_addresses.h Â§1c).
        const uint32_t flash_cmd =
            *reinterpret_cast<const volatile uint32_t*>(FF7Addr::BATTLE_ACTOR_CMD_INDEX);
        const uint32_t flash_idx =
            *reinterpret_cast<const volatile uint32_t*>(FF7Addr::BATTLE_ACTOR_ACTION_INDEX);

        // â”€â”€ Phase 2: a name-bearing action is waiting for its flash text â”€â”€
        if (pending) {
            const bool changed = (flash_cmd != pending_s0_cmd) || (flash_idx != pending_s0_idx);
            const bool synced  = ((flash_cmd & 0xFF) == pending_cmd);
            const bool timed_out = GetTickCount64() >= pending_deadline;
            if ((changed && synced) || (timed_out && synced)) {
                // Flash appeared (or the same flash content repeated, in which
                // case the unchanged values already describe this action).
                std::wstring name;
                const bool ok = ResolveActionName(flash_cmd & 0xFF,
                                                  flash_idx & 0xFFFF, name);
                // v2.30.76: the announce line logs cmd but not idx, which
                // left the limit-junk report (2026-08-03) without the one
                // number that mattered. Log the raw flash pair on every
                // named resolution -- builds a per-branch verification
                // corpus from ordinary play.
                if (Config::Get().debug_log) {
                    char fdbg[96];
                    _snprintf_s(fdbg, sizeof(fdbg), _TRUNCATE,
                        "[FF7Access] BATTLE flash cmd=0x%02lX idx=%lu ok=%d",
                        static_cast<unsigned long>(flash_cmd & 0xFF),
                        static_cast<unsigned long>(flash_idx & 0xFFFF),
                        ok ? 1 : 0);
                    Log::Write(fdbg);
                }
                const bool combine = Config::Get().speak_battle_damage ||
                                     Config::Get().speak_battle_status;
                if (combine) {
                    // v2.30.90: the report already opened at turn detection
                    // with the generic label — upgrade its action name in
                    // place if it hasn't spoken yet. An unresolvable flash
                    // (ok=0, e.g. Tifa's limit idx=98) keeps the generic.
                    ActionReport* tgt = nullptr;
                    if (report.open && report.gen == pending_gen)
                        tgt = &report;
                    else if (prev_report.open && prev_report.gen == pending_gen)
                        tgt = &prev_report;
                    if (ok && tgt && !tgt->bare_spoken) {
                        tgt->action = name;
                        char udbg[160];
                        _snprintf_s(udbg, sizeof(udbg), _TRUNCATE,
                            "[FF7Access] BATTLE report name-upgrade gen=%lu => %ls",
                            static_cast<unsigned long>(pending_gen), name.c_str());
                        Log::Write(udbg);
                    }
                } else {
                    announce(pending_actor, pending_cmd, ok ? &name : nullptr);
                }
                pending = false;
            } else if (timed_out) {
                // No flash and the struct still describes something else:
                // fall back to the generic label rather than risk a wrong
                // name. In combine mode the report already carries the
                // generic label — nothing to do.
                if (!(Config::Get().speak_battle_damage ||
                      Config::Get().speak_battle_status))
                    announce(pending_actor, pending_cmd, nullptr);
                pending = false;
            }
            // While pending and not resolved, fall through only to detect a
            // NEW actor turn below (which resolves the pending state).
        }

        // â”€â”€ Phase 1: new turn detection â”€â”€
        if (actor_id == last_actor_id)
            continue;
        last_actor_id = actor_id;

        // A newer turn started while the previous one was still waiting for
        // its flash. Combine mode: that report is already open with its
        // generic label and will move to the linger slot when the new one
        // opens — only the name upgrade is abandoned. Legacy mode: announce
        // the old turn generically now so it isn't lost.
        if (pending) {
            if (!(Config::Get().speak_battle_damage ||
                  Config::Get().speak_battle_status))
                announce(pending_actor, pending_cmd, nullptr);
            pending = false;
        }

        // Build the actor label.  Slots 0-2 = the party member's real savemap
        // name (v2.19 â€” renames respected, "ally N" only as fallback);
        // slots 4â€“9 = the real scene.bin enemy name with duplicate-letter
        // suffix (v2.10), or "enemy" if unresolvable.
        wchar_t actor_label[64] = {};
        if (is_party) {
            PartySlotLabel(actor_id, actor_label, _countof(actor_label));
        } else {
            std::wstring ename;
            if (EnemySlotName(actor_id, ename))
                _snwprintf_s(actor_label, _countof(actor_label), _TRUNCATE,
                             L"%ls", ename.c_str());
            else
                wcscpy_s(actor_label, L"enemy");
        }

        // Lazily locate the kernel2 sections on first use; retry at most
        // once per minute while any is missing (non-English installs never
        // succeed â€” the rate limit keeps the scans from wasting cycles).
        // urgent=true (v2.30.43): battle scans bypass the fruitless-scan
        // backoff that field-menu retries may have armed â€” see the
        // ScanKernel2Sections header.
        if ((!g_k2.magic || !g_k2.item || !g_k2.weapon) &&
            GetTickCount64() >= next_scan_tick) {
            ScanKernel2Sections(/*urgent=*/true);
            next_scan_tick = GetTickCount64() + 60000;
        }

        // Does this command have flash text at all?  Branch 9 commands
        // (plain Attack, Steal, â€¦) never write the flash struct â€” they
        // carry their generic label with no wait.
        uint8_t branch = 9;
        if (command_id <= FF7Addr::BATTLE_DISPATCH_MAX_CMD)
            branch = *reinterpret_cast<const uint8_t*>(
                FF7Addr::BATTLE_DISPATCH_BYTE_TABLE + command_id);
        const bool name_possible = (branch != 9) &&
            (g_k2.magic != nullptr || branch == 8 || branch == 4);

        // v2.30.90, combine mode: the report opens NOW, at turn detection,
        // with the generic label — the 2026-08-05 logs showed enemy and
        // limit damage routinely settling while the old flash-time open
        // was still waiting, which orphaned ~28% of all fragments (and
        // misattributed some). The flash, when it resolves in Phase 2,
        // upgrades the name in place; until then "MP 1, attacks" /
        // "Tifa, Limit Break" is both honest and correctly attributed.
        const bool combine = Config::Get().speak_battle_damage ||
                             Config::Get().speak_battle_status;
        if (combine)
            announce(actor_label, command_id, nullptr);   // opens the report

        if (!name_possible) {
            if (!combine)
                announce(actor_label, command_id, nullptr);
            continue;
        }

        // Arm Phase 2: legacy mode defers the announce until the flash
        // text appears; combine mode defers only the NAME upgrade.
        pending          = true;
        pending_cmd      = command_id;
        pending_s0_cmd   = flash_cmd;
        pending_s0_idx   = flash_idx;
        pending_deadline = GetTickCount64() + 2500;
        pending_gen      = report.gen;
        wcscpy_s(pending_actor, actor_label);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Battle COMMAND MENU navigation TTS thread (v2.9).
//
// Speaks the battle menu as the player navigates it: the command under the
// cursor (Attack/Magic/Item/Limit...), magic and item list entries BY NAME,
// and the target selection cursor. This was the single largest accessibility
// gap left in the mod â€” battles were playable only by memorizing menu
// layouts and counting presses.
//
// Addresses: ff7_addresses.h SECTION 1c2. Solved by static disassembly
// 2026-07-12 (three failed live-scan sessions prior), live-confirmed the
// same day by investigate/ff7_battle_menu_cursor_live_verify.py.
//
// WHY POLLING (not hooks): same reason as BattleActionThread â€” FFNx
// trampolines battle menu functions (battle_menu_update's dispatcher call
// site is one of its replace_call_function targets), so entry-point hooks
// would intercept FFNx, not the game. Polling at 50ms reads the same state
// the draw code reads, with zero patching. Cursor repeat-rate in FF7 is
// ~8/s at the fastest; 50ms polling cannot skip a resting position, only
// intermediate positions mid-repeat (which a sighted player also ignores).
//
// LIST NAME RESOLUTION: a list entry's u16 id packs the action index in
// the LOW byte (high byte = flag bits â€” live: Ice showed 0x41E = spell 30
// + flag 0x04). Which name section that index refers to depends on which
// COMMAND opened the list, so we reuse the v2.7 dispatch machinery:
// BATTLE_ISSUED_CMD holds the opening command (written at list-open,
// live-verified), its dispatch branch (BATTLE_DISPATCH_BYTE_TABLE) picks
// the section, and ResolveActionName does the lookup. This also keeps the
// item/weapon namespace split (ids 128+ = thrown weapons) working without
// duplicating it. For magic-family branches (0/1/2/6/7) the index is the
// low byte; for the item branch the u16 is the id (kept whole so thrown
// weapons at 128-255 resolve).
//
// TARGETING: after Confirm, the game returns BATTLE_MENU_STATE to 0 and
// runs target selection there (prev state 0x91EF98 keeps the menu it came
// from) â€” state 0 is ALSO the idle ATB-wait state, so raw "state == 0"
// cannot gate target announcements. We announce target changes only while
// `targeting` is set, which we arm on a menu-state -> 0 transition and
// disarm on 0xFFFF (turn executing), a new menu opening, or leaving
// battle. The initial target is announced on arming (the game always
// writes TARGET_INDEX at Confirm time â€” live: it landed the same 50ms
// poll as the state transition).
//
// Target labels: party slots 0-2, enemy slots 4-9 (same actor-slot space
// BattleActionThread uses). Party slots 0-2 = the member's real savemap
// name via PartySlotLabel (v2.19 â€” pre-v2.19 only slot 0 was named and
// slots 1-2 were positional "ally 2"/"ally 3"); slots 4-9 = the real
// scene.bin enemy name with duplicate-letter suffix (v2.10, EnemySlotName
// above), falling back to "enemy N". v2.11 appends "HP <cur> of <max>" to
// the label whenever the sighted target window would show HP (TargetHPText
// above: party always, enemies once Sensed).
//
// Gated by Config::Get().speak_battle_menu (separate from speak_battle so
// menu narration and action narration can be toggled independently).
// ---------------------------------------------------------------------------

// Resolve a battle COMMAND id to its display name.
// Priority: (1) hardcoded names for ids the kernel command-name table does
// not cover 1:1 â€” the Defend/Change-row pseudo-commands and Limit (which
// keeps its unshifted kernel id, live-confirmed); (2) the kernel2 command-
// name section at entry id-1 (ids are 1-based, table is 0-based); (3) the
// v2.7 generic label ("command N" worst case). Returns via `out`.
static void CommandMenuName(uint8_t id, std::wstring& out)
{
    switch (id) {
    case 0x12: out = L"Defend";     return;  // Left at column edge
    case 0x13: out = L"Change row"; return;  // Right at column edge
    case 0x14: out = L"Limit";      return;  // replaces Attack at full gauge
    default:
        break;
    }
    // v2.22.1: the command section is a TRANSIENT battle allocation (the
    // 2026-07-16 session log caught a reused copy speaking binary garbage
    // on menu open) â€” revalidate its head signature before every lookup.
    if (id != 0 &&
        SectionEntryText(ValidatedSection(&g_k2.command, g_k2_command_sig),
                         static_cast<uint32_t>(id) - 1, out))
        return;
    wchar_t generic_buf[32];
    out = GenericActionLabel(id, generic_buf, _countof(generic_buf));
}

static DWORD WINAPI BattleMenuThread(LPVOID /*unused*/)
{
    uint16_t  last_state    = FF7Addr::BMENU_STATE_CLOSED;
    uint32_t  last_cmd_key  = 0xFFFFFFFF;  // slot<<16 | col<<8 | row
    uint32_t  last_list_key = 0xFFFFFFFF;  // state<<16 | index
    bool      targeting     = false;
    uint8_t   last_target   = 0xFF;
    ULONGLONG next_scan_tick = 0;
    // v2.37: whose-turn-is-it announce. A "turn session" spans the command
    // menu and its submenus/targeting; turn_announced is cleared between
    // sessions so cancelling among submenus never re-announces, but a
    // genuinely new turn (even for the same character) does.
    bool      turn_announced = false;
    uint8_t   turn_slot      = 0xFF;

    const auto reset_all = [&]() {
        last_state    = FF7Addr::BMENU_STATE_CLOSED;
        last_cmd_key  = 0xFFFFFFFF;
        last_list_key = 0xFFFFFFFF;
        targeting     = false;
        last_target   = 0xFF;
        turn_announced = false;
        turn_slot      = 0xFF;
    };

    // Label an actor slot for target announcements (see header comment).
    // Party slots 0-2: real savemap names via PartySlotLabel (v2.19).
    const auto target_label = [&](uint8_t slot, wchar_t* buf, size_t buf_count) {
        if (slot <= 2) {
            PartySlotLabel(slot, buf, buf_count);
        } else if (slot >= 4 && slot <= 9) {
            std::wstring ename;
            if (EnemySlotName(slot, ename))
                _snwprintf_s(buf, buf_count, _TRUNCATE, L"%ls", ename.c_str());
            else
                _snwprintf_s(buf, buf_count, _TRUNCATE, L"enemy %u",
                             static_cast<unsigned>(slot - 3u));
        } else {
            _snwprintf_s(buf, buf_count, _TRUNCATE, L"target %u",
                         static_cast<unsigned>(slot));
        }
    };

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_battle_menu) {
            reset_all();
            continue;
        }

        // Battle module active? (GAME_MODE live values: 2 = battle.)
        const uint8_t mode =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE);
        if (mode != 2) {
            reset_all();
            continue;
        }

        const uint16_t state =
            *reinterpret_cast<const volatile uint16_t*>(FF7Addr::BATTLE_MENU_STATE);
        const uint8_t slot =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::BATTLE_ACTIVE_SLOT);

        if (state != last_state) {
            // Arm targeting on any menu-widget -> 0 transition; disarm on
            // anything else. (0 also = plain ATB wait, but we only ARM when
            // coming FROM a menu, so idle state-0 stretches stay silent.)
            const bool from_menu =
                last_state == FF7Addr::BMENU_STATE_COMMAND     ||
                last_state == FF7Addr::BMENU_STATE_ITEM_LIST   ||
                last_state == FF7Addr::BMENU_STATE_MAGIC_LIST  ||
                last_state == FF7Addr::BMENU_STATE_SUMMON_LIST;
            targeting   = (state == FF7Addr::BMENU_STATE_TARGETING) && from_menu;
            last_target = 0xFF;   // re-announce the first target when armed

            // Force a fresh announce of whatever widget we landed in â€” this
            // is also what announces "the menu opened" (the command under
            // the cursor speaks immediately on the state-1 entry poll).
            last_cmd_key  = 0xFFFFFFFF;
            last_list_key = 0xFFFFFFFF;

            if (Config::Get().debug_log) {
                char dbg[96];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] BMENU state %u -> %u (slot %u)",
                    static_cast<unsigned>(last_state),
                    static_cast<unsigned>(state),
                    static_cast<unsigned>(slot));
                Log::Write(dbg);
            }

            // v2.30.49: Defend/Change are dedicated widget states, not
            // command-table entries (see BMENU_STATE_CHANGE/_DEFEND in
            // ff7_addresses.h — the handler jumps here from Left/Right at
            // the command grid's edge, which is why the table announcer
            // stayed silent and Defend was undiscoverable by ear). Speak
            // the game's own labels on the entry edge; Cancel back to
            // state 1 re-announces the command via the last_cmd_key reset
            // above, so the round trip is fully voiced.
            if (state == FF7Addr::BMENU_STATE_CHANGE &&
                Config::Get().speak_battle_menu)
                TTS::Speak(L"Change", true);
            else if (state == FF7Addr::BMENU_STATE_DEFEND &&
                     Config::Get().speak_battle_menu)
                TTS::Speak(L"Defend", true);

            last_state = state;
        }

        // All widget reads index by party slot; anything else means the
        // block is mid-update or we're between menus.
        if (slot > 2)
            continue;

        // v2.37: a turn session spans the command menu + its submenus +
        // targeting. Ending it (menu closed, or ATB idle = state 0 with
        // targeting NOT armed â€” the same 0-is-ambiguous resolver the
        // targeting logic uses) rearms the whose-turn announce.
        const bool in_turn_session =
            state == FF7Addr::BMENU_STATE_COMMAND     ||
            state == FF7Addr::BMENU_STATE_CHANGE      ||   // v2.30.49
            state == FF7Addr::BMENU_STATE_DEFEND      ||   // v2.30.49
            state == FF7Addr::BMENU_STATE_ITEM_LIST   ||
            state == FF7Addr::BMENU_STATE_MAGIC_LIST  ||
            state == FF7Addr::BMENU_STATE_SUMMON_LIST ||
            state == FF7Addr::BMENU_STATE_LIMIT       ||
            targeting;
        if (!in_turn_session) {
            turn_announced = false;
            turn_slot      = 0xFF;
        }

        // Lazily locate the kernel2 sections (shared with BattleActionThread;
        // the scan guard makes concurrent triggers harmless). The command
        // section is the one this thread depends on most â€” without it the
        // command menu still speaks via the hardcoded/generic fallbacks.
        // urgent=true (v2.30.43): the command section is re-found at EVERY
        // battle start (transient allocation) â€” this scan must not be
        // deferred by backoff armed from fruitless field-menu retries.
        if ((!g_k2.magic || !g_k2.item || !g_k2.weapon || !g_k2.command) &&
            GetTickCount64() >= next_scan_tick) {
            ScanKernel2Sections(/*urgent=*/true);
            next_scan_tick = GetTickCount64() + 60000;
        }

        if (state == FF7Addr::BMENU_STATE_COMMAND) {
            // ---- command grid cursor -----------------------------------
            const uint32_t widget = FF7Addr::BATTLE_WIDGET_BASE
                + slot * FF7Addr::BATTLE_WIDGET_SLOT_STRIDE
                + FF7Addr::BWIDGET_COMMAND;
            const uint32_t col =
                *reinterpret_cast<const volatile uint32_t*>(widget + FF7Addr::BWIDGET_OFF_HORIZ);
            const uint32_t row =
                *reinterpret_cast<const volatile uint32_t*>(widget + FF7Addr::BWIDGET_OFF_VERT);
            // Grid bounds: 4 rows (AND 3 wrap in the handler), max 5 columns
            // (the 20-entry table / 4 rows). Out-of-range = mid-update; skip.
            if (col > 4 || row > 3)
                continue;

            const uint32_t key = (static_cast<uint32_t>(slot) << 16) |
                                 (col << 8) | row;
            if (key == last_cmd_key)
                goto targeting_check;
            last_cmd_key = key;

            {
                // entry index = row + col*4 (column-major grid, see 1c2)
                const uint32_t entry = FF7Addr::BATTLE_CHAR_BLOCK
                    + slot * FF7Addr::BATTLE_CHAR_SLOT_STRIDE
                    + FF7Addr::BCHAR_OFF_CMD_TABLE
                    + (row + col * 4) * 6;
                const uint8_t cmd_id =
                    *reinterpret_cast<const volatile uint8_t*>(entry);
                // 0xFF = empty cell. The game's own navigation skips these,
                // so the cursor only reads one transiently mid-move â€” stay
                // silent rather than speak "empty" for a cell the cursor
                // will have left by the next frame.
                if (cmd_id == 0xFF || cmd_id == 0)
                    continue;

                std::wstring name;
                // v2.37: prefix the character's name on the FIRST real
                // command announce of a fresh turn ("Cloud's turn. Attack.")
                // so the player knows who to command; later cursor moves and
                // submenu cancels speak the command alone. Attaching to the
                // command announce (one utterance) avoids clobbering â€” a
                // separate interrupt=true "turn" line would cut the command.
                if (!turn_announced || slot != turn_slot) {
                    wchar_t who[64];
                    PartySlotLabel(slot, who, _countof(who));
                    name = who;
                    name += L"'s turn. ";
                    turn_announced = true;
                    turn_slot      = slot;
                }
                std::wstring cmd_name;
                CommandMenuName(cmd_id, cmd_name);
                name += cmd_name;
                char dbg[128];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] BMENU cmd slot=%u col=%u row=%u id=0x%02X => %ls",
                    static_cast<unsigned>(slot), col, row,
                    static_cast<unsigned>(cmd_id), name.c_str());
                Log::Write(dbg);
                TTS::Speak(name, /*interrupt=*/true);
            }
        } else if (state == FF7Addr::BMENU_STATE_ITEM_LIST   ||
                   state == FF7Addr::BMENU_STATE_MAGIC_LIST  ||
                   state == FF7Addr::BMENU_STATE_SUMMON_LIST) {
            // ---- list widget cursor (magic / item / summon) -------------
            // v2.36: the three lists have DIFFERENT layouts (Confirm-path
            // disasm â€” see the LIST WIDGETS note in ff7_addresses.h). ITEM
            // is a single-column stride-6 u16 list; MAGIC/SUMMON are
            // 3-column stride-8 u8 grids. The v2.9 single formula was right
            // only for items and for a <=3-spell single row.
            bool     list_is_item;
            uint32_t woff, table;
            if (state == FF7Addr::BMENU_STATE_MAGIC_LIST) {
                list_is_item = false;
                woff  = FF7Addr::BWIDGET_MAGIC_LIST;
                table = FF7Addr::BATTLE_CHAR_BLOCK
                      + slot * FF7Addr::BATTLE_CHAR_SLOT_STRIDE
                      + FF7Addr::BCHAR_OFF_MAGIC_LIST;
            } else if (state == FF7Addr::BMENU_STATE_SUMMON_LIST) {
                list_is_item = false;
                woff  = FF7Addr::BWIDGET_SUMMON_LIST;
                table = FF7Addr::BATTLE_CHAR_BLOCK
                      + slot * FF7Addr::BATTLE_CHAR_SLOT_STRIDE
                      + FF7Addr::BCHAR_OFF_SUMMON_LIST;
            } else {
                list_is_item = true;
                woff  = FF7Addr::BWIDGET_ITEM_LIST;
                table = FF7Addr::BATTLE_ITEM_LIST_TABLE;
            }
            const uint32_t widget = FF7Addr::BATTLE_WIDGET_BASE
                + slot * FF7Addr::BATTLE_WIDGET_SLOT_STRIDE + woff;
            const uint32_t w0 =     // horizontal cursor (column for grids)
                *reinterpret_cast<const volatile uint32_t*>(widget + FF7Addr::BWIDGET_OFF_HORIZ);
            const uint32_t w4 =     // vertical cursor (row within window)
                *reinterpret_cast<const volatile uint32_t*>(widget + FF7Addr::BWIDGET_OFF_VERT);
            const uint32_t scroll = // scroll offset (top row)
                *reinterpret_cast<const volatile uint32_t*>(widget + FF7Addr::BWIDGET_OFF_SCROLL);
            // Item = linear; magic/summon = 3-column grid (row*3 + col).
            const uint32_t index = list_is_item
                ? (w0 + w4 + scroll)
                : (w0 + (w4 + scroll) * FF7Addr::BLIST_MAGIC_NCOLS);
            // Battle lists are small (magic <= 96 entries, inventory shows
            // <= 320); a huge sum means the widget is mid-initialization.
            if (index > 0x200)
                continue;

            const uint32_t key = (static_cast<uint32_t>(state) << 16) | index;
            if (key == last_list_key)
                goto targeting_check;
            last_list_key = key;

            {
                // Read the id with the list's own stride/width/empty-marker.
                uint32_t entry_id;
                bool     empty;
                if (list_is_item) {
                    const uint16_t id16 = *reinterpret_cast<const volatile uint16_t*>(
                        table + index * FF7Addr::BLIST_ITEM_STRIDE);
                    empty = (id16 == 0xFFFF);   // NOT 0 â€” id 0 = Potion (v2.36)
                    entry_id = id16;
                } else {
                    const uint8_t id8 = *reinterpret_cast<const volatile uint8_t*>(
                        table + index * FF7Addr::BLIST_MAGIC_STRIDE);
                    empty = (id8 == 0xFF);      // magic/summon empty marker
                    entry_id = id8;
                }
                if (empty)
                    continue;   // empty row â€” silent

                // Pick the name section via the command that OPENED the list
                // (see header comment). Branches 0/1/2/6/7 are magic-family:
                // the index is the low byte (high byte = flags). Branch 3/5
                // (item) uses the id whole so thrown weapons (128+) resolve.
                const uint8_t open_cmd =
                    *reinterpret_cast<const volatile uint8_t*>(FF7Addr::BATTLE_ISSUED_CMD);
                uint8_t branch = 0xFF;
                if (open_cmd <= FF7Addr::BATTLE_DISPATCH_MAX_CMD)
                    branch = *reinterpret_cast<const uint8_t*>(
                        FF7Addr::BATTLE_DISPATCH_BYTE_TABLE + open_cmd);
                const uint32_t idx =
                    (branch == 3 || branch == 5) ? entry_id : (entry_id & 0xFFu);

                std::wstring name;
                bool ok = ResolveActionName(open_cmd, idx, name);
                if (!ok) {
                    // Unknown command/section: still give positional feedback
                    // so the list is navigable by count.
                    wchar_t rowbuf[32];
                    _snwprintf_s(rowbuf, _countof(rowbuf), _TRUNCATE,
                                 L"row %u", index + 1u);
                    name = rowbuf;
                }
                char dbg[160];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] BMENU list state=%u idx=%u(w0=%u w4=%u sc=%u) "
                    "id=0x%02X cmd=0x%02X => %ls",
                    static_cast<unsigned>(state), index, w0, w4, scroll,
                    static_cast<unsigned>(entry_id),
                    static_cast<unsigned>(open_cmd), name.c_str());
                Log::Write(dbg);
                TTS::Speak(name, /*interrupt=*/true);
            }
        }

targeting_check:
        // ---- target selection cursor ------------------------------------
        if (targeting) {
            const uint8_t target =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::BATTLE_TARGET_INDEX);
            if (target != last_target) {
                last_target = target;
                wchar_t label[64];   // 64: fits a 32-char enemy name + " A" suffix
                target_label(target, label, _countof(label));
                // v2.11: append the HP readout when the game would show it
                // (party always; enemies once Sensed).
                std::wstring spoken = label;
                std::wstring hp;
                if (TargetHPText(target, hp)) {
                    spoken += L", ";
                    spoken += hp;
                }
                char dbg[192];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] BMENU target=%u => %ls",
                    static_cast<unsigned>(target), spoken.c_str());
                Log::Write(dbg);
                TTS::Speak(spoken.c_str(), /*interrupt=*/true);
            }
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// What blocks the player -- the corrected model (v2.30.83, 2026-08-04).
//
// A tester's domain statement ("on screen characters should never block
// any path unless there's a story reason") forced a ground-up
// re-derivation of the engine's movement pipeline
// (ff7_player_blocking_ground_truth.py -- full annotated disasm of the
// per-frame movement step 0x636F18, walkmesh try-move 0x6367B7, and
// model-overlap test 0x637724). Instruction-proven results:
//
//   - The USER-CONTROLLED PLAYER IS NEVER BLOCKED BY CHARACTERS. The
//     movement step probes straight + two 45-degree feelers, each against
//     the walkmesh AND against other models -- but the decision branch at
//     0x63732F throws the model answer away for the player while
//     FIELD_UC_LOCK == 0: any probe failing ONLY on a model commits the
//     move anyway (the player walks straight through people). The
//     model-overlap test's sole player-path side effect, the +0x5E
//     "player is bumping me" flag, has NO reader anywhere in the exe.
//   - Wall failures instead run the slide loop (facing +/-8/256ths,
//     up to 16 retries) -- the familiar wall slide; a head-on dead end
//     is the pin.
//   - Character collision exists only for NPC-vs-NPC steering and for
//     the player while a script has control (UC lock) -- i.e. exactly
//     "a story reason", during which input is ignored anyway.
//   - Paths are therefore blocked by exactly three things: walkmesh
//     boundaries (walls/furniture -- edges with no neighbor), IDLCK
//     triangle locks (0xCC0E3A -- the scripted STORY GATES, tested at
//     edge crossing inside the try-move), and disabled gateways/lines.
//     A "guard blocking a door" is set dressing standing on a locked
//     edge or a mesh gap.
//
// This RETIRES the v2.30.22-.82 solid-body machinery (CollectBodies /
// BodyInDirection / BodyOnRay, the route reroute + "X is in the way"
// cautions): its founding evidence -- the 2026-07-25 hideout pins at
// 64.0/81.0 units matching radius sums -- was a coincidence; the pins
// were mesh edges at the furniture chokes the NPCs were parked in, the
// exact wall-vs-person misattribution the user later reported. What
// replaced it: the wall-bump thread now DISCRIMINATES wall vs story
// gate (locked edge ahead => "The way is closed for now."), and route
// NO_PATH checks whether ignoring locks would make the target
// reachable (=> "closed for now" instead of "no walkable path").
//
// FIELD_EVENT_COLLISION_RADIUS (+0x72) remains real and mapped -- it
// feeds NPC steering, the engine's talk-target selector (nearest model
// within talk_radius + player_radius, 0x63640x), and this mod's
// proximity semantics. It just never gated the player's movement.
// ---------------------------------------------------------------------------
static bool IsReadableSpan(const void* p, size_t len);
static float PlayerCollisionRadius();
static bool LockedEdgeAhead(float world_deg);
// Held direction bits -> screen/d-pad angle (0=up, 90=right...), or -1
// when no direction (or a contradictory pair) is held.
static float HeldDirInputDeg(uint32_t keys);

// ---------------------------------------------------------------------------
// Wall-bump tone polling thread.
//
// Vanilla FF7 has no footstep sounds, so a blind player gets zero audio
// feedback about whether the character is actually moving. This thread plays
// a short low tone whenever the player is PUSHING AGAINST A WALL: a movement
// direction is held but the character's world position is not changing.
//
// THE SIGNAL (verified live by ff7_wall_nav_verify.py, 2026-07-09):
//   - current_key_input_status (0xCC0DF0) carries the digested directional
//     input (0xF000 mask) the field engine consumes each frame.
//   - The player model's world position is field_event_data array element
//     [FIELD_PLAYER_MODEL_ID], model_pos at +0x0C (3 consecutive int32).
//   - Predicate "direction held AND position unchanged for 3 consecutive
//     50ms polls" fired 98.4% of samples while pushing a wall, 0.0% while
//     walking freely, and 0.0% while idle. Walking moves the position every
//     engine frame (33ms at 30fps, faster under FFNx's 60fps interpolation),
//     so at a 50ms poll interval free movement always changes the position
//     between polls; three consecutive frozen polls (150ms) cannot happen
//     while actually moving.
//
// FALSE-POSITIVE GATES (states where direction-held + frozen-position does
// NOT mean "blocked by wall"; the first three were added after 2026-07-09
// live testing found false tones in battles, FMVs, and scripted scenes):
//   - GAME_MODE != 0: the field module is not the active engine module.
//     Live-observed values (do NOT trust FFNx's enum here â€” see the
//     GAME_MODE note in ff7_addresses.h): 0 = field play, 2 = battle,
//     9 = menu. Battle is the critical case: entering a random battle
//     while holding a direction freezes the field module with that
//     direction stuck in current_key_input_status and the position frozen
//     â€” without this gate the tone plays through the entire battle.
//   - FIELD_UC_LOCK != 0: a field script locked player control (opcode UC)
//     for a scripted scene; input is ignored so a frozen position is not
//     a wall. Address derived from the PSX decomp's exact struct match â€”
//     see ff7_addresses.h FIELD_UC_LOCK provenance note.
//   - FIELD_MOVIE_PLAYING && !BGMOVIE: a full-screen movie (FMV) is
//     playing. Background movies (BGMOVIE set â€” e.g. scenery outside a
//     train window) leave the player walkable and stay tone-enabled.
//   - FIELD_ID == 0: title screen / world map. (NOT sufficient for battle,
//     despite earlier belief â€” live-tested: it keeps its field value while
//     a battle runs on top. Kept as defense in depth.)
//   - MENU_OPEN != 0: main menu overlay open; arrow keys navigate the menu
//     while the character is frozen underneath it.
//   - Dialog/choice recently active (Hooks::LastDialogActivityTick within
//     250ms): the MESSAGE/ASK hooks run every frame while any dialog window
//     is open. Holding a direction there (habit, or navigating an ASK
//     choice) must not beep. 250ms = several frames of slack past the last
//     hook call, so the gate also covers the frame gap between dialog pages.
//
// THE TONE:
//   Tones::Play(220 Hz, 60 ms) â€” a waveOut sine on the default audio
//   device (v2.30.41; formerly kernel32 Beep(), whose system-beep route is
//   silent on some systems â€” VMs and remote sessions â€” see tones.h).
//   Chosen over TTS because a tone is instant, language-free, and doesn't
//   interrupt any speech in progress. 220 Hz sits well below both the cue
//   beeps used by investigation scripts (800/1400 Hz) and typical screen
//   reader speech fundamentals, so it reads as a distinct "thud". Play()
//   blocks this thread for the 60ms duration exactly as Beep() did â€”
//   acceptable, since the next poll simply happens a frame later. Repeats
//   every 300ms for as long as contact continues (continuous-but-not-
//   frantic feedback).
//
// MEMORY SAFETY:
//   Every poll re-reads the array pointer (the engine owns it; on this
//   build it points into static BSS at 0xCC1670, but a field could in
//   principle relocate it) and bounds-checks the player index against
//   FIELD_N_MODELS. The computed element range is then verified readable
//   via VirtualQuery before dereferencing â€” during field transitions the
//   array contents are torn down and rebuilt, and a polling thread can
//   catch any intermediate state.
//
// Gated by Config::Get().wall_bump_tone.
// ---------------------------------------------------------------------------
static DWORD WINAPI WallBumpThread(LPVOID /*unused*/)
{
    // 50ms polling: fast enough that a wall bump is reported within ~200ms
    // (3 polls + tone start), slow enough to be free (5 memory reads/poll).
    constexpr DWORD    kPollMs        = 50;
    // 3 consecutive frozen-while-pushing polls (150ms) before the first tone.
    // 1 would false-fire on the single frame between direction-press and the
    // engine's first position update; 3 never fired during free walking in
    // live verification.
    constexpr uint32_t kConsecBlocked = 3;
    constexpr DWORD    kBeepPeriodMs  = 300; // repeat rate while contact holds
    constexpr DWORD    kBeepFreqHz    = 220; // low "thud", distinct from speech
    constexpr DWORD    kBeepDurMs     = 60;
    constexpr DWORD    kDialogQuietMs = 250; // dialog-hook recency window

    int32_t  last_x = 0, last_y = 0, last_z = 0;
    bool     have_last      = false;  // last_* hold a real previous sample
    uint32_t blocked_streak = 0;      // consecutive dir-held+frozen polls
    DWORD    last_beep_tick = 0;
    // v2.30.1: the tone is DISARMED until real movement is observed in the
    // current gate-open episode (re-disarmed whenever any gate closes).
    // Play report 2026-07-18: a party wipe loops the tone through the whole
    // game-over screen â€” that state reads as field mode with the input
    // status frozen at whatever direction was held when the fatal battle
    // triggered, i.e. exactly the Gate-2 stale-input scenario, but with no
    // mode change for Gate 2 to catch. No gate on module state can be
    // trusted to close there, so gate on the one thing a frozen module can
    // never fake: the player actually walking. Reaching a wall always takes
    // at least one step first, so the cost is only a missed tone in the
    // rare "battle ended flush against a wall, direction never released"
    // case â€” and that clears the moment the player moves.
    bool     armed          = false;
    // v2.30.22: one body-naming attempt per contact episode. Reset when the
    // player moves or releases the direction (the natural "bump, hear the
    // name, adjust" loop); NOT reset by gate closures alone, so a dialog
    // opening mid-contact can't re-trigger the same name.
    bool     episode_named  = false;
    // Packed snapshot of the gate values from the previous poll, logged on
    // change (debug_log only). Live testing is the only way to validate gate
    // behavior across battles/FMVs/cutscenes, and this trail lets a bug
    // report's log show exactly which gate opened or failed to close.
    uint32_t last_gates     = 0xFFFFFFFF;

    for (;;) {
        // Sleep kPollMs, or wake immediately if Proxy::Shutdown() signals.
        if (WaitForSingleObject(g_cursor_stop_event, kPollMs) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().wall_bump_tone) {
            have_last = false;
            blocked_streak = 0;
            armed = false;
            continue;
        }

        // Gate 1: must be on a named field map. FIELD_ID is 0 on the title
        // screen and world map. NOTE (live-tested 2026-07-09): FIELD_ID does
        // NOT reliably zero during battle â€” the field stays loaded behind the
        // battle module â€” so this gate alone is insufficient; see Gate 2.
        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);

        // Gate 2: the FIELD module must be the ACTIVE engine module.
        // When a random battle starts, the field module freezes with
        // current_key_input_status stuck at the direction the player was
        // holding and the position frozen â€” the wall predicate would stay
        // true for the entire battle (observed live: continuous tone until
        // the victory screen). Live-observed values: 0 = field play,
        // 2 = battle, 9 = menu (FFNx's enum does not apply to this byte).
        const uint8_t game_mode =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE);

        // Gate 3: main menu overlay closed. Arrow keys navigate the menu
        // while the character stands frozen underneath â€” not a wall.
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);

        // Gate 4: player control not locked by a field script (opcode UC).
        // Scripted scenes freeze the player while ignoring input; holding a
        // direction there is not a wall. Offset provenance: PSX decomp
        // struct match â€” see FIELD_UC_LOCK in ff7_addresses.h.
        const uint8_t uc_lock =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::FIELD_UC_LOCK);

        // Gate 5: no full-screen movie playing. FFNx's own test: movie word
        // set AND BGMOVIE flag clear. A BACKGROUND movie (BGMOVIE set, e.g.
        // scenery scrolling past a train window) leaves the player walkable,
        // so wall tones stay enabled for those.
        const uint16_t movie_word = *reinterpret_cast<const volatile uint16_t*>(
            FF7Addr::FIELD_MOVIE_PLAYING);
        const uint8_t bgmovie =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::FIELD_BGMOVIE_FLAG);
        const bool movie_playing = (movie_word != 0) && (bgmovie == 0);

        // Log gate transitions (debug_log builds only â€” Log::Write is a
        // no-op otherwise). One line per change, never per poll.
        const uint32_t gates =
            (static_cast<uint32_t>(game_mode) << 24) |
            (static_cast<uint32_t>(uc_lock)   << 16) |
            (static_cast<uint32_t>(menu_open) <<  8) |
            (movie_playing ? 2u : 0u) |
            (field_id != 0 ? 1u : 0u);
        if (gates != last_gates) {
            last_gates = gates;
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] WALL gates: mode=%u uc_lock=%u menu=%u movie=%u field=%d",
                game_mode, uc_lock, menu_open,
                movie_playing ? 1 : 0, static_cast<int>(field_id));
            Log::Write(dbg);
        }

        // v2.30.37: GameOverTitleContext â€” the GAME OVER film reel reads as
        // frozen field play in every byte above (mode=0, menu=0, movie=0,
        // stale FIELD_ID). The movement-arming below already kept the tone
        // quiet there (v2.30.1's whole point), but the latch is positive
        // knowledge â€” use it.
        if (field_id == 0 || game_mode != FF7Addr::GAME_MODE_FIELD ||
            menu_open != 0 || uc_lock != 0 || movie_playing ||
            GameOverTitleContext()) {
            have_last = false;
            blocked_streak = 0;
            armed = false;
            continue;
        }

        // Gate 6: no dialog/choice window active within the last 250ms.
        // Unsigned subtraction handles GetTickCount()'s 49.7-day wrap.
        const DWORD now = GetTickCount();
        if (now - Hooks::LastDialogActivityTick() < kDialogQuietMs) {
            have_last = false;
            blocked_streak = 0;
            armed = false;
            continue;
        }

        // Read the digested input; any of the four direction bits counts.
        const uint32_t keys = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::FIELD_KEY_INPUT_STATUS);
        const bool dir_held = (keys & FF7Addr::KEY_DIR_ANY) != 0;

        // Locate the player's field_event_data element for this poll.
        const uint32_t arr = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::FIELD_EVENT_DATA_PTR);
        const uint16_t pmid = *reinterpret_cast<const volatile uint16_t*>(
            FF7Addr::FIELD_PLAYER_MODEL_ID);
        const uint16_t nmod = *reinterpret_cast<const volatile uint16_t*>(
            FF7Addr::FIELD_N_MODELS);
        // 0x401000 = below any mapped game data; pmid sanity-capped at 0x20
        // (FF7 fields never approach 32 models) in case nmod itself is torn.
        if (arr < 0x401000 || pmid >= nmod || pmid > 0x20) {
            have_last = false;
            blocked_streak = 0;
            armed = false;
            continue;
        }
        const uint8_t* elem = reinterpret_cast<const uint8_t*>(
            arr + pmid * FF7Addr::FIELD_EVENT_DATA_STRIDE);

        // Verify the whole element is committed readable memory before
        // dereferencing â€” a field transition can tear the array down between
        // our pointer read and here. Check both ends: the 0x88-byte struct
        // can straddle a page boundary.
        MEMORY_BASIC_INFORMATION mbi = {};
        const uint8_t* elem_end = elem + FF7Addr::FIELD_EVENT_DATA_STRIDE - 1;
        bool readable = true;
        for (const uint8_t* probe : { elem, elem_end }) {
            if (VirtualQuery(probe, &mbi, sizeof(mbi)) == 0 ||
                mbi.State != MEM_COMMIT ||
                (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                readable = false;
                break;
            }
        }
        if (!readable) {
            have_last = false;
            blocked_streak = 0;
            armed = false;
            continue;
        }

        // model_pos: 3 consecutive int32 (x, y, z) at +0x0C.
        const int32_t* pos = reinterpret_cast<const int32_t*>(
            elem + FF7Addr::FIELD_EVENT_MODEL_POS);
        const int32_t x = pos[0], y = pos[1], z = pos[2];

        // "Moved" on the very first valid sample: with no previous position
        // to compare, assume motion so the streak stays at zero rather than
        // beeping off one stale coordinate. Only a change between two REAL
        // samples counts as movement for arming (v2.30.1) â€” the first-sample
        // "assume motion" must not arm off one stale coordinate either.
        const bool real_move = have_last &&
            (x != last_x || y != last_y || z != last_z);
        const bool moved = !have_last || real_move;
        if (real_move)
            armed = true;
        last_x = x; last_y = y; last_z = z;
        have_last = true;

        if (dir_held && !moved) {
            blocked_streak++;
        } else {
            blocked_streak = 0;
            episode_named  = false;   // v2.30.22: contact episode over
        }

        // One line at the moment a would-be tone is swallowed (== not >=,
        // so a suppressed episode logs once, not 20Ã—/second).
        if (!armed && blocked_streak == kConsecBlocked) {
            Log::Write("[FF7Access] WALL tone suppressed: dir held + frozen "
                       "but no movement seen this episode (frozen module?)");
        }

        if (armed && blocked_streak >= kConsecBlocked &&
            now - last_beep_tick >= kBeepPeriodMs) {
            last_beep_tick = now;
            // One-time log per contact episode would require more state; log
            // nothing here â€” at 3+ beeps/second even debug logging would spam.
            Tones::Play(kBeepFreqHz, kBeepDurMs);

            // v2.30.83: WALL vs STORY GATE. Characters never stop the
            // user-controlled player (the movement step commits through
            // model contacts while FIELD_UC_LOCK==0 -- see the corrected
            // model block above), so a proven freeze has exactly two
            // causes: real geometry (walls/furniture = mesh boundary)
            // or an IDLCK-locked edge (a script gate that will open at
            // a story beat). Geometry gets the thud alone -- it speaks
            // for itself. A locked edge gets ONE spoken line per
            // contact episode, because "come back later" is knowledge a
            // sighted player gets from context and a blind player
            // otherwise can't distinguish from a dead end.
            // (This replaces the v2.30.22-.82 "<Name> is in the way"
            // body naming -- the misattribution machine that blamed
            // whoever stood near the wall that actually stopped you.)
            // interrupt=false: queue behind any route announcement in
            // progress rather than clobbering it.
            if (!episode_named) {
                episode_named = true;
                const float held_input = HeldDirInputDeg(keys);
                const uint32_t hdr = *reinterpret_cast<const volatile uint32_t*>(
                    FF7Addr::FIELD_TRIGGERS_HEADER_PTR);
                if (held_input >= 0.0f && hdr >= 0x401000 &&
                    IsReadableSpan(reinterpret_cast<const void*>(hdr),
                                   FF7Addr::FTRIG_OFF_CONTROL_DIR + 1)) {
                    const uint8_t control_dir = *reinterpret_cast<const uint8_t*>(
                        hdr + FF7Addr::FTRIG_OFF_CONTROL_DIR);
                    // input = world + control - 180  =>  world = input - control + 180
                    const float world = held_input -
                        control_dir * (360.0f / 256.0f) + 180.0f;
                    if (LockedEdgeAhead(world)) {
                        TTS::Speak(L"The way is closed for now.",
                                   /*interrupt=*/false);
                        if (Config::Get().debug_log) {
                            char dbg[160];
                            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                                "[FF7Access] WALL gate: locked edge ahead "
                                "held_input=%.0f world=%.1f player=(%ld,%ld)",
                                held_input, world,
                                static_cast<long>(x >> 12),
                                static_cast<long>(y >> 12));
                            Log::Write(dbg);
                        }
                    }
                }
            }
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// DialogToneThread (v2.30.5): plays the two story-dialog audio cues.
//
// hook_message/hook_ask (hooks.cpp) run on the GAME's main thread every
// frame and can only SET edge-triggered flags â€” Tones::Play() blocks for
// the tone's whole duration (as Beep() did before v2.30.41), so calling it
// directly from an opcode hook would stall the game itself every time it
// fires (the same reasoning behind every other tone in this file:
// WallBumpThread above, and the proximity/wander chirps further down, all
// poll a background thread instead of beeping inline from a hook). This
// thread just polls Hooks::ConsumeDialogWaitTone/ConsumeDialogChoiceTone
// and does the actual (blocking, but only THIS thread blocks) Tones::Play
// calls.
//
// Both cues use the SAME pitch (1568 Hz, distinct from every other tone in
// this mod: 220 Hz wall thud, 880 Hz wandering cue, 1175 Hz proximity
// chirp) and differ only in COUNT â€” one beep for "waiting for the confirm
// button", two quick beeps for "a choice was just presented" â€” matching
// the player's request verbatim (a plain high tone vs. a high double-tone).
// ---------------------------------------------------------------------------
static DWORD WINAPI DialogToneThread(LPVOID /*unused*/)
{
    constexpr DWORD kPollMs      = 50;   // matches WallBumpThread/TimerThread's
                                          // cadence -- fast enough the tone
                                          // feels immediate, cheap enough to
                                          // be free (two flag reads per poll)
    constexpr WORD  kToneHz      = 1568; // G6
    constexpr WORD  kToneMs      = 50;   // "short" per the request
    constexpr DWORD kDoubleGapMs = 60;   // gap between the choice tone's two beeps

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, kPollMs) == WAIT_OBJECT_0)
            break;

        if (Hooks::ConsumeDialogWaitTone())
            Tones::Play(kToneHz, kToneMs);

        if (Hooks::ConsumeDialogChoiceTone()) {
            // Play() blocks until the first beep finishes (like Beep()
            // did), so the Sleep is purely the audible gap between the two.
            Tones::Play(kToneHz, kToneMs);
            Sleep(kDoubleGapMs);
            Tones::Play(kToneHz, kToneMs);
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Field navigation â€” PATHFINDER BROWSER thread (v2.14, reworked to the
// FF1-6 accessibility key scheme the same day). First interactable-tracking
// feature of the navigation system.
//
// KEY BINDINGS follow accessiblity_keys.txt (repo root) â€” the FF4 Pixel
// Remaster screen-reader scheme â€” so users of the FF1-6 accessibility mods
// can transfer their muscle memory directly (user requirement, 2026-07-13):
//   J / L   (or [ / ])  cycle destinations in the current category
//   Shift+J / Shift+L (or - / =)  cycle destination categories
//   K                  announce the selected destination's name
//   Shift+K            reset category to All
//   \ or P             directions to the selected destination
//   M                  announce the current map's name
// Categories: All, Exits, People (v2.15 â€” every non-player model on the
// walkmesh, named from the model-loader section's dev names in v2.16),
// Save points (v2.16 â€” "save" labels; CONFIRMED game-wide by the v2.18
// flevel catalog: "fieldbg saveicn" is the only save label in all 720
// fields), Triggers (v2.17 â€” script-created LINE zones: ladders,
// elevators, touch/cross zones, named by owning entity's dev name), and
// Items (v2.18 â€” chests/materia/pickups/keys classified by the
// catalog-confirmed "fieldbg" prop labels; collected floor pickups
// despawn off-mesh and drop out of the list automatically, which IS the
// taken/remaining state for them â€” chest open/closed state is a live
// investigation TODO). Unimplemented FF4 keys
// (Ctrl+arrows teleport, Shift+M exit filter) are silently ignored; listed
// in TODO.txt for when prerequisites exist. (Shift+\ valid-path filter
// shipped v2.30.87; the layer filter shipped v2.30.88 on Shift+; -- the
// keys file rebound it from the FF4 scheme's Ctrl+\ on 2026-08-05.)
//
// DATA SOURCE (ff7_addresses.h SECTION 1e): the engine's parsed field-file
// section 8 behind FIELD_TRIGGERS_HEADER_PTR (0xCFF454, resolved statically
// via FFNx's chain with three name-embedded cross-checks). Each of the 12
// gateway slots holds an exit LINE (two walkmesh-coord vertices) and the
// destination field id (0x7FFF = unused slot). Destinations are numbered by
// gateway SLOT order ("Exit 1".."Exit n") so a destination keeps its name
// while the player moves â€” never renumbered by distance.
//
// GEOMETRY: player walkmesh position = field_event_data model_pos >> 12
// (FFNx: "model_pos.x / 4096.f"). Distance = player to the NEAREST POINT of
// the exit line segment, in the XY plane (Z left out: fields are drawn from
// a fixed camera and exits are reached by 2D walking; a stacked-walkway
// field could understate distance, acceptable for v1). Walking covers ~160
// walkmesh units/sec (v2.6 measurement), so seconds = distance / 160.
//
// DIRECTION: world angle of (player -> nearest point), then rotated by the
// header's control_direction byte â€” the SAME per-field value the engine
// uses to rotate d-pad input to match the camera â€” and mapped to 8 d-pad
// sectors. CONVENTION FULLY CONFIRMED 2026-07-13: the calibration
// walkabout fixed the rotation (control_direction is the world bearing of
// screen-DOWN, screen angle = world + controlâˆ’180), and the user's
// follow-up play test confirmed left/right land correctly too â€” the
// mapping is a pure rotation, no mirror.
//
// DIRECTION STYLES (v2.22): the above single-bearing announcement is now
// the "line" style (direction_style=line, and the automatic fallback).
// The default "turns" style routes over the field's WALKMESH instead â€”
// A* + funnel over the triangle graph, spoken as d-pad moves: "Exit 2:
// up 4 seconds, then right 2 seconds" â€” see the WALKMESH pathfinding
// block above for the full pipeline and its fail-closed guards.
//
// HOTKEYS use GetAsyncKeyState edges, gated on the game window being
// focused (GetForegroundWindow's process == ours) so typing in another app
// can't trigger them, and on normal field control (GAME_MODE==0,
// FIELD_ID!=0, MENU_OPEN==0) so they can't talk over battles/menus.
// Config::Get().pathfinder_keys turns the whole set off.
//
// GAMEPAD (v2.21): the RIGHT ANALOG STICK is a second trigger path for the
// same browser â€” up/down = category, left/right = destination, R3 click =
// directions. Identical gates (focus + field control + pathfinder_keys);
// gamepad_nav=false switches just the stick off. The stick and R3 carry no
// native game function, so nothing is stolen from gameplay â€” full evidence
// trail in gamepad.h.
// ---------------------------------------------------------------------------

// Map an input-relative angle (degrees, 0 = the Up d-pad, clockwise) to an
// 8-way d-pad sector. Split into index + name (v2.22) because the
// turn-by-turn route builder merges consecutive same-SECTOR legs â€” it
// compares indices, not strings.
// Diagonals are spoken "up and left", not "up-left" (v2.23): the user
// found the hyphenated forms confusing; "and" says directly that the move
// is BOTH arrows held together.
static const wchar_t* const kDpadSectors[8] = {
    L"up", L"up and right", L"right", L"down and right",
    L"down", L"down and left", L"left", L"up and left",
};

static int DpadSectorIndex(float deg)
{
    // Normalize to [0, 360), offset by half a sector so each name is
    // centered on its axis (up = [-22.5, +22.5)).
    float norm = fmodf(deg + 22.5f, 360.0f);
    if (norm < 0.0f) norm += 360.0f;
    int sector = static_cast<int>(norm / 45.0f);
    if (sector < 0)  sector = 0;
    if (sector > 7)  sector = 7;
    return sector;
}

static const wchar_t* DpadSectorName(float deg)
{
    return kDpadSectors[DpadSectorIndex(deg)];
}

// One browsable destination: a gateway/exit (line), a person/save point
// (point, stored as a degenerate line so the distance math is shared), or a
// LINE trigger zone (v2.17 â€” script-created lines: ladders, elevators,
// touch/cross zones â€” a real segment, exactly like an exit).
struct NavDest {
    wchar_t name[96];      // spoken name, e.g. "To Platform" / "shinra
                           // guard 3, talk disabled" (widened 32â†’48 in
                           // v2.26 for the talk suffix on long labels;
                           // 48â†’64 in v2.30.23 for trigger-behavior
                           // suffixes like ", exit to Seventh Heaven";
                           // 64â†’96 in v2.30.66: journey-wrapped leg names
                           // truncated LIVE in both run-1/run-2 logs --
                           // "Journey to Sector 1,Statio")
    int16_t line_x1, line_y1, line_x2, line_y2;   // exit line (walkmesh)
    int16_t line_z1, line_z2;   // line endpoint HEIGHTS (v2.23) â€” lets the
                                // route builder locate the target on the
                                // correct STACKED layer when no triangle
                                // hint exists (exits/triggers on walkways)
    int     model_slot;    // field model index for people; -1 for exits
    int16_t target_tri;    // walkmesh triangle the target stands on (models:
                           // their live +0x78 id â€” exact even on stacked
                           // layers); -1 = unknown, turn-by-turn locates the
                           // target point geometrically instead (v2.22)
    int16_t place_field;   // CAT_PLACES only (v2.30.65): the destination
                           // FIELD id this entry names; meaningless (and
                           // unread) in every other category, which is why
                           // the other builders leave it unset
};

// ---------------------------------------------------------------------------
// Readability probe for an arbitrary byte span (v2.18.2).
//
// Replaces the per-site VirtualQuery idiom that had accumulated many inline
// copies (2026-07-14 code review): walks the regions covering [p, p+len) and
// requires every one committed and readable â€” strictly stronger than the
// old copies, which probed only one or two single bytes of a span and could
// pass while a MIDDLE page was decommitted (realistic during a field
// transition, when the game frees one buffer while another stays live).
// ---------------------------------------------------------------------------
static bool IsReadableSpan(const void* p, size_t len)
{
    const uint8_t* cur = static_cast<const uint8_t*>(p);
    const uint8_t* const end = cur + len;
    while (cur < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(cur, &mbi, sizeof(mbi)) == 0 ||
            mbi.State != MEM_COMMIT ||
            (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            return false;
        cur = static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Model-slot -> point NavDest (v2.30.73, from the review's duplication
// finding): ONE construction for "route to this field model", shared by
// the journey last-mile scan and the \-key last-mile branch so they
// cannot drift apart (the two hand-rolled copies already had -- the scan
// lacked the browser's placement filter). Fills the degenerate-line
// point shape every model destination uses; the caller sets .name.
// Returns false on any of the reasons the destination browser would not
// list the model: slot out of range, element unreadable, or parked at
// the origin (bound but never placed on the mesh -- pos (0,0) with
// triangle 0 is the browser's own eligibility tell).
// ---------------------------------------------------------------------------
static bool BuildModelPointDest(uint32_t arr, uint16_t nmod, int slot,
                                NavDest& out)
{
    if (slot < 0 || slot >= static_cast<int>(nmod) || slot > 0x20)
        return false;
    const uint8_t* me = reinterpret_cast<const uint8_t*>(
        arr + slot * FF7Addr::FIELD_EVENT_DATA_STRIDE);
    if (!IsReadableSpan(me, FF7Addr::FIELD_EVENT_DATA_STRIDE))
        return false;
    const int32_t* mp = reinterpret_cast<const int32_t*>(
        me + FF7Addr::FIELD_EVENT_MODEL_POS);
    const int16_t tri = *reinterpret_cast<const int16_t*>(
        me + FF7Addr::FIELD_EVENT_TRIANGLE_ID);
    const int16_t mx = static_cast<int16_t>(mp[0] >> 12);
    const int16_t my = static_cast<int16_t>(mp[1] >> 12);
    if (mx == 0 && my == 0 && tri == 0)
        return false;   // parked/unplaced
    out.name[0] = L'\0';
    out.line_x1 = out.line_x2 = mx;
    out.line_y1 = out.line_y2 = my;
    out.line_z1 = out.line_z2 = static_cast<int16_t>(mp[2] >> 12);
    out.model_slot  = slot;
    out.target_tri  = tri;
    out.place_field = 0;
    return true;
}

// ---------------------------------------------------------------------------
// WALKMESH pathfinding â€” turn-by-turn directions (v2.22).
//
// WHY: the v2.14 directions are one straight-line bearing, which happily
// points through walls and pits. Turn-by-turn plans a real route over the
// field's WALKMESH â€” the triangle mesh the engine itself moves characters
// on â€” and speaks it as a sequence of d-pad moves with walking times:
// "Exit 2: up 4 seconds, then right 2 seconds." The straight-line style
// remains available (direction_style=line) and is the automatic fallback
// whenever a route cannot be computed.
//
// DATA: field-file section 5 behind FIELD_FILE_BUFFER â€” layout, sources,
// and the access-pool confidence caveat are documented at ff7_addresses.h
// SECTION 1h. Everything runs on the directions keypress, nothing is
// cached: a field mesh is at most a few hundred triangles, and per-press
// rebuilding is the same simplicity/freshness tradeoff the destination
// list itself makes.
//
// PIPELINE:
//   1. LoadWalkmesh    â€” snapshot triangles + adjacency, SELF-GUARDED
//                        (id-range + reciprocity checks) because the
//                        access pool is the one layout fact FFNx's code
//                        does not confirm â€” a wrong guess must fail the
//                        parse, never route the player into a wall
//   2. locate ends     â€” player: live triangle id (+0x78); target: its
//                        model's triangle id, else point-location
//   3. WalkmeshAStar   â€” A* over the adjacency graph, centroid costs
//   4. BuildPortals    â€” the crossed edges, endpoints recovered by
//                        GEOMETRIC shared-vertex match (never by the
//                        access pool's edge-order convention, which is
//                        not runtime-verifiable)
//   5. FunnelPath      â€” string-pulling: the taut path through the
//                        corridor, so corners exist only where the route
//                        actually bends around geometry
//   6. RouteToSpeech   â€” legs quantized to the 8 d-pad sectors,
//                        same-direction legs merged, sub-step jogs folded
//                        into their predecessor
// ---------------------------------------------------------------------------

// One walkmesh triangle, snapshot form. Routing is 2D (the same
// convention as exits/distance since v2.14) â€” adjacency routes stacked
// layers correctly because two overlapping walkways are far apart in the
// GRAPH even when they overlap in XY. The centroid HEIGHT is kept
// (v2.23) so point-location can resolve WHICH stacked layer a target
// with a known Z is on (ladder endpoints, exits on walkways).
struct WalkTri {
    float    vx[3], vy[3];  // vertex XY, walkmesh units
    uint16_t nbr[3];        // triangle across edge slot e; 0xFFFF = wall
    float    cx, cy;        // centroid â€” the triangle's A* node position
    float    cz;            // centroid height â€” layer disambiguation only
};

// A 2D point on the route (funnel corners, portal midpoints).
struct NavPt { float x, y; };

// Snapshot and validate the current field's walkmesh. False = caller must
// fall back to straight-line directions (buffer mid-transition, count
// implausible, or the access pool failed its self-guard).
// apply_locks (v2.30.83): true = overlay the IDLCK story-lock cuts (the
// graph the player can walk RIGHT NOW -- what routing wants); false =
// the raw geometric mesh (what the field would allow if scripts opened
// every gate). Loading both and comparing reachability is how NO_PATH
// distinguishes "closed for now" (story gate) from "genuinely
// unreachable"; the raw mesh is also what the wall-bump thread probes
// to tell a locked edge from a plain wall.
static bool LoadWalkmesh(std::vector<WalkTri>& out, bool apply_locks = true)
{
    const uint32_t buf = *reinterpret_cast<const volatile uint32_t*>(
        FF7Addr::FIELD_FILE_BUFFER);
    if (buf < 0x401000)
        return false;
    if (!IsReadableSpan(reinterpret_cast<const void*>(buf),
                        FF7Addr::FIELD_SECTION_TABLE_OFF + 9 * 4))
        return false;
    const uint32_t sec_off = *reinterpret_cast<const uint32_t*>(
        buf + FF7Addr::FIELD_SECTION_TABLE_OFF +
        4 * FF7Addr::FIELD_WALKMESH_SECTION_INDEX);
    if (sec_off == 0)
        return false;
    const uint8_t* sec = reinterpret_cast<const uint8_t*>(buf) + sec_off;
    if (!IsReadableSpan(sec, FF7Addr::FWMESH_OFF_TRIS))
        return false;
    const uint32_t ntris = *reinterpret_cast<const uint32_t*>(
        sec + FF7Addr::FWMESH_OFF_NTRIS);
    if (ntris == 0 || ntris > FF7Addr::FWMESH_MAX_TRIS)
        return false;
    const uint8_t* tris = sec + FF7Addr::FWMESH_OFF_TRIS;
    if (!IsReadableSpan(tris, ntris * (FF7Addr::FWMESH_TRI_SIZE +
                                       FF7Addr::FWMESH_ACCESS_SIZE)))
        return false;
    const uint8_t* access = tris + ntris * FF7Addr::FWMESH_TRI_SIZE;

    out.resize(ntris);
    for (uint32_t t = 0; t < ntris; ++t) {
        const int16_t* v = reinterpret_cast<const int16_t*>(
            tris + t * FF7Addr::FWMESH_TRI_SIZE);
        const uint16_t* a = reinterpret_cast<const uint16_t*>(
            access + t * FF7Addr::FWMESH_ACCESS_SIZE);
        WalkTri& w = out[t];
        float zsum = 0.0f;
        for (int i = 0; i < 3; ++i) {
            w.vx[i]  = static_cast<float>(v[i * 4 + 0]);  // s16 x,y,z,res
            w.vy[i]  = static_cast<float>(v[i * 4 + 1]);
            zsum    += static_cast<float>(v[i * 4 + 2]);
            w.nbr[i] = a[i];
        }
        w.cx = (w.vx[0] + w.vx[1] + w.vx[2]) / 3.0f;
        w.cy = (w.vy[0] + w.vy[1] + w.vy[2]) / 3.0f;
        w.cz = zsum / 3.0f;
    }

    // SELF-GUARD for the access pool (see SECTION 1h): if its documented
    // location were wrong, these bytes would be triangle coordinates or
    // padding â€” out-of-range ids and broken reciprocity â€” not a mostly
    // mutual graph. Requiring every id in range AND >= 90% of directed
    // links reciprocal makes "wrong layout" fail closed into the
    // straight-line fallback. (Not 100%: tolerate a few genuinely odd
    // one-way links in hand-built meshes without giving up the feature.)
    uint32_t links = 0, mutual = 0;
    for (uint32_t t = 0; t < ntris; ++t) {
        for (int e = 0; e < 3; ++e) {
            const uint16_t nb = out[t].nbr[e];
            if (nb == FF7Addr::FWMESH_NO_NEIGHBOR)
                continue;
            if (nb >= ntris)
                return false;
            ++links;
            for (int k = 0; k < 3; ++k) {
                if (out[nb].nbr[k] == t) { ++mutual; break; }
            }
        }
    }
    if (ntris > 1 && (links == 0 || mutual * 10 < links * 9))
        return false;

    // v2.30.21: overlay the IDLCK triangle-lock bitfield (see
    // TRIANGLE_LOCK_BITS in ff7_addresses.h for the full derivation).
    // Field scripts mark counters/doorways impassable at runtime; the
    // static access pool doesn't know, so A* was routing THROUGH them
    // and walking the player into invisible walls (2026-07-23: the route
    // to Tifa led into the bar counter â€” her triangle is mesh-connected
    // but script-locked). Cut every edge INTO a locked triangle â€” the
    // exact test the game's own movement code performs per crossing
    // (destination-side only, so leaving a locked triangle stays
    // possible, mirroring the game). Applied AFTER the reciprocity
    // self-guard above: locks legitimately make the graph asymmetric,
    // and the guard validates the RAW pool's layout, not the overlay.
    // A route target standing on a locked triangle (Tifa) becomes
    // unreachable â€” A* fails and the caller falls back to the
    // straight-line announce, which walks the player TO the counter,
    // where the talk radius already reaches across (matching how a
    // sighted player interacts).
    uint32_t locked = 0;
    for (uint32_t t = 0; apply_locks && t < ntris; ++t) {
        for (int e = 0; e < 3; ++e) {
            const uint16_t nb = out[t].nbr[e];
            if (nb == FF7Addr::FWMESH_NO_NEIGHBOR)
                continue;
            if (FF7Addr::is_triangle_locked(nb)) {
                out[t].nbr[e] = FF7Addr::FWMESH_NO_NEIGHBOR;
                ++locked;
            }
        }
    }
    if (locked > 0 && Config::Get().debug_log) {
        char dbg[96];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] NAV walkmesh: %lu edge(s) cut by triangle locks",
            static_cast<unsigned long>(locked));
        Log::Write(dbg);
    }
    return true;
}

// Squared distance from point (px,py) to segment (x1,y1)-(x2,y2) â€” the
// nearest-point projection the directions math has used since v2.14.
static float PointSegDist2(float px, float py,
                           float x1, float y1, float x2, float y2)
{
    const float ex = x2 - x1, ey = y2 - y1;
    const float len2 = ex * ex + ey * ey;
    float t = (len2 > 0.0f) ? ((px - x1) * ex + (py - y1) * ey) / len2 : 0.0f;
    if (t < 0.0f) t = 0.0f;
    if (t > 1.0f) t = 1.0f;
    const float dx = (x1 + t * ex) - px;
    const float dy = (y1 + t * ey) - py;
    return dx * dx + dy * dy;
}

// Twice the signed area of triangle (a,b,c) â€” the funnel algorithm's
// orientation primitive. Sign says which side of a->b the point c is on:
// POSITIVE = the side BuildPortals labels "left". âš  This is cross(ab,ac),
// the NEGATIVE of Recast's triArea2D (cross(ac,ab)) â€” every comparison in
// FunnelPath is therefore sign-FLIPPED relative to the classic listing.
// The 2026-07-16 offline dry run (ff7_walkmesh_route_dryrun.py) caught
// exactly this: the unflipped signs emitted a corner at nearly every
// portal (zigzag routes longer than the midpoint path).
static float Tri2(float ax, float ay, float bx, float by, float cx, float cy)
{
    return (bx - ax) * (cy - ay) - (by - ay) * (cx - ax);
}

// Distance from a point to a walkmesh triangle: 0 inside, else nearest
// edge distance. Used by the v2.30.24 body-aware reroute to find the
// triangles a body's contact circle overlaps.
static float TriangleDistance(const struct WalkTri& w, float x, float y)
{
    const float s0 = Tri2(w.vx[0], w.vy[0], w.vx[1], w.vy[1], x, y);
    const float s1 = Tri2(w.vx[1], w.vy[1], w.vx[2], w.vy[2], x, y);
    const float s2 = Tri2(w.vx[2], w.vy[2], w.vx[0], w.vy[0], x, y);
    if ((s0 >= 0.0f && s1 >= 0.0f && s2 >= 0.0f) ||
        (s0 <= 0.0f && s1 <= 0.0f && s2 <= 0.0f))
        return 0.0f;   // inside (either winding â€” field meshes vary)
    float best = FLT_MAX;
    for (int e = 0; e < 3; ++e) {
        const int f = (e + 1) % 3;
        const float d2 = PointSegDist2(x, y, w.vx[e], w.vy[e],
                                       w.vx[f], w.vy[f]);
        if (d2 < best) best = d2;
    }
    return sqrtf(best);
}

// Triangle for point (x,y,z): the one whose XY projection contains the
// point (or whose boundary is nearest â€” target points sit exactly ON
// portal edges; point targets can be a hair off-mesh), with the HEIGHT
// difference to the triangle's centroid as a tie-breaker term so a field
// with STACKED walkways resolves to the layer the point is actually on
// (v2.23 â€” ladder endpoints made this matter; before that the 2D pick
// was an accepted limitation). The score sums XY boundary distanceÂ² and
// height differenceÂ²: zero for "inside, same height", and a triangle
// directly underfoot always beats the same spot on another layer.
static int WalkmeshLocate(const std::vector<WalkTri>& m,
                          float x, float y, float z);

// A model's live triangle id (+0x78) is only a HINT (v2.30.25): scripted
// idle models never update it â€” the hideout's Biggs stood at (-191,46)
// while his field still read triangle 0 from the bottom corridor, so
// every route to him planned to the wrong corner and then "spoke" a
// straight line through walls (the 2026-07-25 evening log's
// `start=0 goal=0 'left 2 seconds'` line is the smoking gun; Jessie's
// routes carried the same stale 0). Trust a hint ONLY when the hinted
// triangle actually contains (within a small slack) the position it
// claims to locate; otherwise geometry-locate from the position, which
// also handles off-mesh targets (nearest triangle + height score).
// Known residual: on STACKED layers a stale hint that happens to name
// the other layer's triangle under the same 2D point would pass â€” a
// far smaller lie than the cross-room one this catches, and the
// height-aware locate still corrects the no-hint path.
static int ResolveTriHint(const std::vector<WalkTri>& m, int hint,
                          float x, float y, float z)
{
    const int n = static_cast<int>(m.size());
    if (hint >= 0 && hint < n && TriangleDistance(m[hint], x, y) <= 8.0f)
        return hint;
    return WalkmeshLocate(m, x, y, z);
}

static int WalkmeshLocate(const std::vector<WalkTri>& m,
                          float x, float y, float z)
{
    int   best = -1;
    float best_score = FLT_MAX;
    for (size_t t = 0; t < m.size(); ++t) {
        const WalkTri& w = m[t];
        const float s0 = Tri2(w.vx[0], w.vy[0], w.vx[1], w.vy[1], x, y);
        const float s1 = Tri2(w.vx[1], w.vy[1], w.vx[2], w.vy[2], x, y);
        const float s2 = Tri2(w.vx[2], w.vy[2], w.vx[0], w.vy[0], x, y);
        // Inside = same side of all three edges. Field meshes are not
        // consistently wound, so accept either orientation; the epsilon
        // admits points sitting exactly on an edge.
        constexpr float eps = 0.01f;
        float xy2 = 0.0f;
        if (!((s0 >= -eps && s1 >= -eps && s2 >= -eps) ||
              (s0 <= eps && s1 <= eps && s2 <= eps))) {
            xy2 = FLT_MAX;
            for (int e = 0; e < 3; ++e) {
                const int f = (e + 1) % 3;
                const float d2 = PointSegDist2(x, y, w.vx[e], w.vy[e],
                                               w.vx[f], w.vy[f]);
                if (d2 < xy2) xy2 = d2;
            }
        }
        const float dz = z - w.cz;
        const float score = xy2 + dz * dz;
        if (score < best_score) { best_score = score; best = static_cast<int>(t); }
    }
    return best;
}

// A* over the triangle adjacency graph, centroid-to-centroid costs and a
// straight-line heuristic (admissible: no shortcut is shorter than the
// crow's flight). Linear-scan open "list" â€” n is a few hundred, and this
// runs once per keypress; a heap would be pure ceremony. Returns the
// triangle sequence start..goal, or false when the goal is in a region
// the graph cannot reach (locked-off area, different layer group).
static bool WalkmeshAStar(const std::vector<WalkTri>& m, int start, int goal,
                          std::vector<uint16_t>& out_path,
                          const std::vector<uint8_t>* avoid = nullptr)
{
    // avoid (v2.30.24): optional per-triangle mask â€” crossings INTO
    // masked triangles are refused, the same overlay shape as the IDLCK
    // lock cut. Used by the body-aware reroute; never set for the
    // start/goal triangles.
    const size_t n = m.size();
    std::vector<float>   g(n, FLT_MAX);      // best known cost from start
    std::vector<float>   f(n, FLT_MAX);      // g + heuristic
    std::vector<int32_t> parent(n, -1);
    std::vector<uint8_t> st(n, 0);           // 0 new, 1 open, 2 closed
    const auto heur = [&](int t) {
        const float dx = m[goal].cx - m[t].cx;
        const float dy = m[goal].cy - m[t].cy;
        return sqrtf(dx * dx + dy * dy);
    };
    g[start] = 0.0f;
    f[start] = heur(start);
    st[start] = 1;
    for (;;) {
        int   cur = -1;
        float fbest = FLT_MAX;
        for (size_t i = 0; i < n; ++i)
            if (st[i] == 1 && f[i] < fbest) { fbest = f[i]; cur = static_cast<int>(i); }
        if (cur < 0)
            return false;                    // open set empty: unreachable
        if (cur == goal)
            break;
        st[cur] = 2;
        for (int e = 0; e < 3; ++e) {
            const uint16_t nb = m[cur].nbr[e];
            if (nb == FF7Addr::FWMESH_NO_NEIGHBOR || st[nb] == 2)
                continue;
            if (avoid != nullptr && (*avoid)[nb])
                continue;
            const float dx = m[nb].cx - m[cur].cx;
            const float dy = m[nb].cy - m[cur].cy;
            const float ng = g[cur] + sqrtf(dx * dx + dy * dy);
            if (ng < g[nb]) {
                g[nb] = ng;
                f[nb] = ng + heur(nb);
                parent[nb] = cur;
                st[nb] = 1;
            }
        }
    }
    out_path.clear();
    for (int t = goal; t != -1; t = parent[t])
        out_path.push_back(static_cast<uint16_t>(t));
    for (size_t i = 0, j = out_path.size() - 1; i < j; ++i, --j) {
        const uint16_t tmp = out_path[i];
        out_path[i] = out_path[j];
        out_path[j] = tmp;
    }
    return true;
}

// The doorway between two consecutive path triangles: the shared edge,
// endpoints ordered left/right of the direction of travel.
struct PathPortal { float lx, ly, rx, ry; };

// Portals for a triangle path. The shared edge is recovered by EXACT
// vertex-coordinate match between the two triangles (s16 grid, so shared
// vertices compare equal) â€” deliberately NOT via the access pool's
// edge-order convention, the one layout fact nothing at runtime can
// verify; geometry is self-evident. Left/right orientation comes from the
// centroid-to-centroid crossing direction, which by construction passes
// through the shared edge, so the assignment is stable regardless of how
// the route approached.
static void BuildPortals(const std::vector<WalkTri>& m,
                         const std::vector<uint16_t>& path,
                         std::vector<PathPortal>& out)
{
    out.clear();
    for (size_t i = 0; i + 1 < path.size(); ++i) {
        const WalkTri& A = m[path[i]];
        const WalkTri& B = m[path[i + 1]];
        float sx[2] = {}, sy[2] = {};
        int   found = 0;
        for (int a = 0; a < 3 && found < 2; ++a) {
            for (int b = 0; b < 3 && found < 2; ++b) {
                if (A.vx[a] == B.vx[b] && A.vy[a] == B.vy[b]) {
                    // A degenerate triangle can repeat a coordinate;
                    // don't record the same point as both endpoints.
                    if (found == 1 && sx[0] == A.vx[a] && sy[0] == A.vy[a])
                        continue;
                    sx[found] = A.vx[a];
                    sy[found] = A.vy[a];
                    ++found;
                    break;
                }
            }
        }
        PathPortal p;
        if (found == 2) {
            const float side = Tri2(A.cx, A.cy, B.cx, B.cy, sx[0], sy[0]);
            if (side >= 0.0f) { p.lx = sx[0]; p.ly = sy[0]; p.rx = sx[1]; p.ry = sy[1]; }
            else              { p.lx = sx[1]; p.ly = sy[1]; p.rx = sx[0]; p.ry = sy[0]; }
        } else {
            // No 2-vertex match (T-junction or exotic geometry): collapse
            // the portal to B's centroid. The funnel then treats it as a
            // must-pass point â€” the route stays walkable, just less taut.
            p.lx = p.rx = B.cx;
            p.ly = p.ry = B.cy;
        }
        out.push_back(p);
    }
}

// String-pulling (the "simple stupid funnel" algorithm): tighten the
// route through the portal corridor so corners appear only where it
// actually wraps around geometry. Emits the corner points (start
// excluded, end included). On the internal-guard bailout corners comes
// back EMPTY and the caller degrades to portal midpoints â€” a valid,
// just less taut, route.
static void FunnelPath(float sx, float sy, float endx, float endy,
                       const std::vector<PathPortal>& portals,
                       std::vector<NavPt>& corners)
{
    corners.clear();
    std::vector<PathPortal> p = portals;
    p.push_back({ endx, endy, endx, endy });  // end = a zero-width portal

    float ax = sx, ay = sy;                   // funnel apex
    float lx = p[0].lx, ly = p[0].ly;         // current left boundary
    float rx = p[0].rx, ry = p[0].ry;         // current right boundary
    size_t li = 0, ri = 0;                    // portals those came from

    // The classic algorithm rescans from the apex portal after emitting a
    // corner, making it O(n^2) worst case â€” fine at field sizes, but a
    // subtle orientation bug could in principle cycle, so a hard guard
    // converts "cannot happen" into "falls back audibly correct".
    int guard = static_cast<int>(p.size()) * 16 + 64;

    for (size_t i = 1; i < p.size(); ++i) {
        if (--guard < 0) { corners.clear(); return; }

        // Tighten the RIGHT side: the new right endpoint narrows the
        // funnel if it lies left of (or on) the current right boundary.
        // (Signs flipped vs. the classic Recast listing â€” see Tri2.)
        if (Tri2(ax, ay, rx, ry, p[i].rx, p[i].ry) >= 0.0f) {
            if ((ax == rx && ay == ry) ||
                Tri2(ax, ay, lx, ly, p[i].rx, p[i].ry) < 0.0f) {
                rx = p[i].rx; ry = p[i].ry; ri = i;
            } else {
                // New right crossed the LEFT boundary: the left point is
                // a real corner. Emit it, restart the funnel there.
                corners.push_back({ lx, ly });
                ax = lx; ay = ly;
                lx = rx = ax; ly = ry = ay;
                ri = li;
                i = li;                       // loop ++ resumes at li+1
                continue;
            }
        }
        // Tighten the LEFT side (mirror image).
        if (Tri2(ax, ay, lx, ly, p[i].lx, p[i].ly) <= 0.0f) {
            if ((ax == lx && ay == ly) ||
                Tri2(ax, ay, rx, ry, p[i].lx, p[i].ly) > 0.0f) {
                lx = p[i].lx; ly = p[i].ly; li = i;
            } else {
                corners.push_back({ rx, ry });
                ax = rx; ay = ry;
                lx = rx = ax; ly = ry = ay;
                li = ri;
                i = ri;
                continue;
            }
        }
    }
    corners.push_back({ endx, endy });
}

// Corners -> speech: "up 4 seconds, then right 2 seconds". Legs are
// quantized to the 8 d-pad sectors through the SAME world->input rotation
// the straight-line style uses (world + control_direction - 180, the
// fully play-test-confirmed v2.14 mapping); consecutive same-sector legs
// merge; a sub-step jog (under ~0.75 s of walking) folds into its
// predecessor rather than being spoken â€” "then left 1 second" for a
// two-tile kink is noise, and the player re-queries en route anyway. The
// FIRST leg is never folded away: it is the move the player makes right
// now. At most five moves are spoken (routes rarely need more than
// three); a longer tail is summarized so the message stays holdable.
static std::wstring RouteToSpeech(float sx, float sy,
                                  const std::vector<NavPt>& corners,
                                  float control_deg,
                                  int* out_first_sector = nullptr,
                                  float* out_first_len = nullptr)
{
    // v2.30.22: callers may ask for the first FOLDED leg (the move the
    // player will actually make) so the body-caution check can test the
    // exact quantized ray that gets spoken. -1 = no leg ("very close").
    if (out_first_sector) *out_first_sector = -1;
    if (out_first_len)    *out_first_len    = 0.0f;
    struct Seg { int sector; float len; };
    std::vector<Seg> segs;
    float cx = sx, cy = sy;
    for (const NavPt& c : corners) {
        const float dx = c.x - cx, dy = c.y - cy;
        const float len = sqrtf(dx * dx + dy * dy);
        cx = c.x; cy = c.y;
        if (len < 1.0f)
            continue;                        // duplicate/joint point
        const float world_deg = atan2f(dx, dy) * (180.0f / 3.14159265f);
        const int sector = DpadSectorIndex(world_deg + control_deg - 180.0f);
        if (!segs.empty() && segs.back().sector == sector)
            segs.back().len += len;
        else
            segs.push_back({ sector, len });
    }

    // Fold sub-step legs into their predecessor, re-merging neighbors the
    // fold makes adjacent. (Folding into the PREDECESSOR keeps the first
    // spoken move truthful; the jogged distance still counts.)
    constexpr float kMinSegLen = 120.0f;     // 0.75 s x 160 units/s
    std::vector<Seg> folded;
    for (const Seg& s : segs) {
        if (!folded.empty() &&
            (s.len < kMinSegLen || folded.back().sector == s.sector))
            folded.back().len += s.len;
        else
            folded.push_back(s);
    }

    float total = 0.0f;
    for (const Seg& s : folded)
        total += s.len;
    if (total < FF7Addr::WALKMESH_UNITS_PER_SEC * 0.5f) {
        // v2.30.71 (user request): "very close" must still say WHICH
        // WAY -- half a second of walking is a real direction, and for
        // a blind player an interactable one step the WRONG way is a
        // missed OK press. v2.30.72: user-specified word order --
        // proximity first, then the facing: "very close to the up and
        // left" (applies to EVERY pathfinder selection; the
        // straight-line fallback uses the same phrasing). v2.30.73
        // (review, two fixes): (1) the spoken sector is the FIRST
        // FOLDED LEG when one exists -- a multi-corner route exists
        // because the straight line is blocked, so the net bearing to
        // the target can point through the very wall the route walks
        // around; the net bearing is only the fallback when folding
        // consumed every micro-segment. (2) The first-leg outputs stay
        // -1/0 (the documented contract above): sub-half-second routes
        // never fired the body caution, and a probe here would flag
        // bodies BEYOND a target that is reached first.
        int vc_sector = -1;
        if (!folded.empty()) {
            vc_sector = folded[0].sector;
        } else if (!corners.empty()) {
            const float tdx = corners.back().x - sx;
            const float tdy = corners.back().y - sy;
            if (tdx * tdx + tdy * tdy >= 1.0f)
                vc_sector = DpadSectorIndex(
                    atan2f(tdx, tdy) * (180.0f / 3.14159265f)
                    + control_deg - 180.0f);
        }
        if (vc_sector >= 0) {
            std::wstring out = L"very close to the ";
            out += kDpadSectors[vc_sector];
            return out;
        }
        return L"very close";
    }

    if (!folded.empty()) {
        if (out_first_sector) *out_first_sector = folded[0].sector;
        if (out_first_len)    *out_first_len    = folded[0].len;
    }

    std::wstring out;
    constexpr size_t kMaxSpoken = 5;
    for (size_t i = 0; i < folded.size() && i < kMaxSpoken; ++i) {
        int secs = static_cast<int>(
            folded[i].len / FF7Addr::WALKMESH_UNITS_PER_SEC + 0.5f);
        if (secs < 1) secs = 1;
        if (i > 0)
            out += L", then ";
        out += kDpadSectors[folded[i].sector];
        out += L' ';
        out += std::to_wstring(secs);
        out += (secs == 1) ? L" second" : L" seconds";
    }
    if (folded.size() > kMaxSpoken)
        out += L", and more after that";
    return out;
}

// Outcome of a turn-by-turn attempt â€” the caller's fallback decision.
enum class RouteOutcome {
    SPOKEN_ROUTE,   // out_route holds the spoken route body
    NO_PATH,        // mesh fine, target genuinely unreachable: say so
    UNAVAILABLE,    // mesh unreadable/failed guards: silent fallback
};

// Full pipeline for one directions request. (px,py,pz) player, (tx,ty,tz)
// the target point (nearest point of the destination's line â€” the same
// point the straight-line style aims at; z interpolated along the line),
// *_hint = live triangle ids when known (heights only matter when a hint
// is missing and the field has stacked layers).
static RouteOutcome BuildTurnByTurnRoute(float px, float py, float pz,
                                         int start_hint,
                                         float tx, float ty, float tz,
                                         int goal_hint,
                                         float control_deg,
                                         int exclude_model_slot,
                                         float target_reach,
                                         std::wstring& out_route,
                                         int* out_first_sector = nullptr,
                                         float* out_first_len = nullptr,
                                         bool to_nearest = false)
{
    // v2.30.83: routes IGNORE characters entirely. The engine's movement
    // step walks the user-controlled player straight through models (see
    // the corrected-model block above WallBumpThread), so the
    // v2.30.24-.82 body-aware reroute and "sealed corridor" verdict --
    // built on the belief that people block like walls -- computed
    // detours around obstacles that do not exist and named blockers
    // that never blocked. The route is walkmesh truth alone: geometry
    // plus IDLCK story locks (cut in LoadWalkmesh).
    // to_nearest (v2.30.25): when the target is graph-unreachable
    // (off the walkable floor â€” Biggs sitting on the hideout crates,
    // Tifa behind the locked bar counter), route to the REACHABLE
    // triangle nearest the target instead of giving up, aiming the walk
    // at that triangle's closest point. The caller words the result as
    // "off the walkable area" and the talk radius covers the last gap.
    // exclude_model_slot: kept for signature stability (the destination
    // model's slot when routing to a person) -- no longer consulted.
    // target_reach (v2.30.25): how far short of the target the walk may
    // END and still succeed â€” a person is "reached" at their talk
    // radius.
    (void)exclude_model_slot;
    std::vector<WalkTri> mesh;
    if (!LoadWalkmesh(mesh)) {
        Log::Write("[FF7Access] NAV route: walkmesh unavailable, "
                   "falling back to straight-line");
        return RouteOutcome::UNAVAILABLE;
    }
    const int n = static_cast<int>(mesh.size());
    // v2.30.25: hints validated against their positions (stale-triangle
    // fix â€” see ResolveTriHint).
    const int start = ResolveTriHint(mesh, start_hint, px, py, pz);
    int       goal  = ResolveTriHint(mesh, goal_hint, tx, ty, tz);
    if (start < 0 || goal < 0)
        return RouteOutcome::UNAVAILABLE;

    std::vector<uint16_t> path;
    if (!WalkmeshAStar(mesh, start, goal, path)) {
        if (!to_nearest)
            return RouteOutcome::NO_PATH;
        // Nearest-reachable recovery: flood the start's component over
        // the (lock-cut) graph, pick the triangle nearest the target,
        // and aim the walk at its closest point to the target. Offline-
        // validated 2026-07-25: Biggs on the crates resolves to a stand
        // point 6 units from him â€” well inside talk radius.
        std::vector<uint8_t> comp(n, 0);
        std::vector<int> bfs{ start };
        comp[start] = 1;
        while (!bfs.empty()) {
            const int t = bfs.back();
            bfs.pop_back();
            for (int e = 0; e < 3; ++e) {
                const uint16_t nb = mesh[t].nbr[e];
                if (nb != FF7Addr::FWMESH_NO_NEIGHBOR && !comp[nb]) {
                    comp[nb] = 1;
                    bfs.push_back(nb);
                }
            }
        }
        int   best   = -1;
        float best_d = FLT_MAX;
        for (int t = 0; t < n; ++t) {
            if (!comp[t])
                continue;
            const float dd = TriangleDistance(mesh[t], tx, ty);
            if (dd < best_d) {
                best_d = dd;
                best   = t;
            }
        }
        if (best < 0)
            return RouteOutcome::NO_PATH;
        if (best_d > 0.0f) {
            // redirect the walk endpoint to the best triangle's closest
            // point (tx/ty are by-value â€” safe to overwrite)
            float bpd = FLT_MAX, bx = tx, by = ty;
            for (int e = 0; e < 3; ++e) {
                const int f = (e + 1) % 3;
                const float ex = mesh[best].vx[f] - mesh[best].vx[e];
                const float ey = mesh[best].vy[f] - mesh[best].vy[e];
                const float l2 = ex * ex + ey * ey;
                float t2 = (l2 > 0.0f)
                    ? ((tx - mesh[best].vx[e]) * ex +
                       (ty - mesh[best].vy[e]) * ey) / l2
                    : 0.0f;
                if (t2 < 0.0f) t2 = 0.0f;
                if (t2 > 1.0f) t2 = 1.0f;
                const float cx2 = mesh[best].vx[e] + t2 * ex;
                const float cy2 = mesh[best].vy[e] + t2 * ey;
                const float d2  = (cx2 - tx) * (cx2 - tx) +
                                  (cy2 - ty) * (cy2 - ty);
                if (d2 < bpd) {
                    bpd = d2;
                    bx  = cx2;
                    by  = cy2;
                }
            }
            tx = bx;
            ty = by;
        }
        goal = best;
        path.clear();
        if (!WalkmeshAStar(mesh, start, goal, path))
            return RouteOutcome::NO_PATH;   // cannot happen (same comp)
    }

    std::vector<PathPortal> portals;
    BuildPortals(mesh, path, portals);
    std::vector<NavPt> corners;
    FunnelPath(px, py, tx, ty, portals, corners);
    if (corners.empty()) {
        // Funnel guard tripped â€” degrade to portal midpoints: every
        // doorway on the route in order, so still a walkable description.
        for (const PathPortal& p : portals)
            corners.push_back({ (p.lx + p.rx) * 0.5f, (p.ly + p.ry) * 0.5f });
        corners.push_back({ tx, ty });
    }

    // (v2.30.83: the body-aware reroute + sealed-corridor verdict that
    // lived here were removed with the corrected blocking model --
    // characters do not block the player, so there is nothing to
    // reroute around and nobody to name. See the block above
    // WallBumpThread for the derivation.)

    out_route = RouteToSpeech(px, py, corners, control_deg,
                              out_first_sector, out_first_len);

    if (Config::Get().debug_log) {
        char dbg[224];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] NAV route tris=%d start=%d goal=%d path=%u "
            "corners=%u '%ls'",
            n, start, goal, static_cast<unsigned>(path.size()),
            static_cast<unsigned>(corners.size()), out_route.c_str());
        Log::Write(dbg);
    }
    return RouteOutcome::SPOKEN_ROUTE;
}

// ---------------------------------------------------------------------------
// Pathfinder categories and field-model classification (v2.18.2).
//
// The Shift+J/L category ring. File-scope so the classifier below can map a
// model class to its category â€” previously the enum lived inside the key
// handler and classification knowledge was spread across three sites (the
// 2026-07-14 code review's altitude finding).
// ---------------------------------------------------------------------------
enum { CAT_ALL = 0, CAT_EXITS = 1, CAT_PEOPLE = 2, CAT_SAVE = 3,
       CAT_TRIGGERS = 4, CAT_ITEMS = 5, CAT_PLACES = 6 };

// What a field model IS, decided in exactly one place from its dev label.
enum ModelClass : uint8_t {
    MC_PERSON = 0,   // any other model â€” browsable under People
    MC_SAVE,         // save point icon
    MC_CHEST,        // treasure box (lid state tracked via lastFrame)
    MC_ITEM,         // materia orb / pickup bottle / sparkle / key item
    MC_SCENERY,      // background prop â€” not browsable under ANY category
                     // (v2.30.18: unknown "fieldbg" labels + a small list
                     // of observed non-fieldbg props; see ClassifyModelLabel)
    MC_PROP,         // v2.30.45: a SCENERY model whose script entity has a
                     // real talk script (offline game-wide walk â€”
                     // ff7_prop_catalog.h): a button/lever/valve style
                     // DEVICE. The v2.30.36 review's deliberately deferred
                     // whitelist, delivered after the tester asked for the
                     // reactor switches. Browses under Triggers, spoken
                     // with a ", device" suffix. Promotion happens AFTER
                     // ClassifyModelLabel (one classifier, one place â€”
                     // the catalog only ever RESURRECTS filtered scenery,
                     // never reclassifies people/chests/items/saves).
};

// Classify a model's speakable label and pick its spoken base name.
// Evidence (offline catalog of ALL 720 fields' model labels,
// ff7_flevel_models_catalog.py, 2026-07-14): the devs prefixed every
// interactable prop "fieldbg" and named item props consistently â€” "trb *" =
// treasure boxes (wood/mety/glow/metb/trbox k), "mtra*" = materia orbs
// (incl. hmtra/kuromtra), "potion *" = pickup bottles (color variants; the
// BOTTLE is the visual, the script decides the actual item, hence generic
// "Item"), "sparkle" = sparkle pickups, "key"/"coralkey" = key items,
// "saveicn" = save points. No other label in the game contains these
// substrings, so fieldbg+substring is exact, not heuristic. *friendly
// stays null for MC_PERSON (callers speak the label itself).
static ModelClass ClassifyModelLabel(const std::wstring& lbl,
                                     const wchar_t** friendly)
{
    *friendly = nullptr;
    if (lbl.find(L"save") != std::wstring::npos) {
        *friendly = L"Save point";
        return MC_SAVE;
    }
    if (lbl.find(L"fieldbg") == std::wstring::npos) {
        // v2.30.18: a few scene props carry NO "fieldbg" prefix but are
        // clearly not people â€” observed listed as "People" with no
        // walkable path in 7th Heaven (player report 2026-07-23):
        // "camera" (cutscene camera dummy, 1 occurrence game-wide in the
        // flevel catalog) and "swordc"/"swordc00"/"swordc09" (sword
        // props, 3 occurrences). v2.30.19: CONTAINS-matched, not
        // exact/prefix â€” the .char labels arrive with location-word
        // prefixes ("nible camera", "modify swordc", same-day log), which
        // the first attempt's exact match silently missed. Both tokens
        // are unique in the catalog (no "cameraman"-style collisions), so
        // contains is still evidence-tight. This list only grows from
        // played evidence, never guesses.
        if (lbl.find(L"camera") != std::wstring::npos ||
            lbl.find(L"swordc") != std::wstring::npos)
            return MC_SCENERY;
        return MC_PERSON;
    }
    if (lbl.find(L"trb") != std::wstring::npos) {
        *friendly = L"Chest";
        return MC_CHEST;
    }
    if (lbl.find(L"mtra") != std::wstring::npos) {
        *friendly = L"Materia";
        return MC_ITEM;
    }
    if (lbl.find(L"potion")  != std::wstring::npos ||
        lbl.find(L"sparkle") != std::wstring::npos) {
        *friendly = L"Item";
        return MC_ITEM;
    }
    if (lbl.find(L"key") != std::wstring::npos) {
        *friendly = L"Key";
        return MC_ITEM;
    }
    // v2.30.18: a "fieldbg" label that matched NONE of the interactable
    // substrings above is background scenery, not a person. The offline
    // flevel catalog shows dozens of these game-wide (doors "â€¦dr", the
    // train "kisya", cosmetics "cos"/"props"/"v2"/"zuta"â€¦), and the
    // 2026-07-23 player report caught three of them listed as unreachable
    // "People" in 7th Heaven alone (hana = flower vase, cash = register,
    // pinbl = pinball machine). The pinball elevator's INTERACTION is a
    // separate line trigger (Triggers category) â€” the model is just its
    // picture. Previously fell through to MC_PERSON.
    return MC_SCENERY;
}

// Which category (besides All) a model class browses under. One mapping,
// so the emit filter is a single comparison that cannot drift out of
// mutual exclusion as classes are added.
static int CategoryForModelClass(ModelClass c)
{
    switch (c) {
        case MC_SAVE:  return CAT_SAVE;
        case MC_CHEST:
        case MC_ITEM:  return CAT_ITEMS;
        case MC_PROP:  return CAT_TRIGGERS;  // devices sit with the other
                                             // "things you operate" (v2.30.45)
        default:       return CAT_PEOPLE;
    }
}

// ---------------------------------------------------------------------------
// Dev-label translation: romaji/shorthand -> speakable English (v2.20).
//
// The v2.16 People names and v2.17 Trigger names are the developers' own
// dev names â€” terse romaji ("hei" = soldier, "ballet" = Barret, "ladd0" =
// a ladder line) that a blind player would have to memorize. This block
// translates them, word by word, into plain English, and resolves party-
// character words to the character's LIVE savemap name (v2.19 machinery,
// so player renames carry through to the field browser too).
//
// EVIDENCE (both TODO.txt residuals planned this table "from the complete
// label list, no play collection needed"):
//   - models:   investigate/flevel_models_catalog_20260714_130007.log â€”
//     all 557 distinct model labels in the game's 720 fields.
//   - entities: investigate/flevel_entity_names_20260715_122652.log â€”
//     all 2412 distinct script entity names (new game-wide catalog,
//     2026-07-15; nmkin_2 validation showed the reactor ladder lines
//     themselves: 'ladu0'/'ladd0'/'slp0', with Jessie as 'av j').
//   - per-field context for the short stems (v2.28 second pass):
//     investigate/short_entity_context_20260717 log â€” the COMPLETE
//     entity list of every field where each cryptic 2-3 letter stem
//     occurs; the neighbouring names are the identification evidence
//     (e.g. 'dr' beside 'door1..door6' in the same field = door).
// Every entry below appears in those catalogs; words NOT in the tables
// are spoken unchanged (parity: better to hear the dev word than nothing,
// and a wrong translation is worse than a terse one â€” same principle as
// the v2.18.2 stale-name guard).
//
// MECHANICS: a label is split on spaces; each token is stripped of
// leading/trailing digits ("man401" -> "man", "22main" -> "main"), then
// looked up. Single-character stems are dropped (the "n" in "main n
// cloud", stray "l"/"r" side markers). Digit suffixes are deliberately
// discarded â€” the browser's own duplicate ordinals ("man 2") number
// things in stable slot order, which digits in dev names do not.
// Identity stability holds: translation is a pure function of the label,
// so a model/line keeps its spoken name while the player moves.
// ---------------------------------------------------------------------------

// Current display name for a character id: live savemap name (renames
// respected), else the default English name, else empty.
static std::wstring CharDisplayName(uint8_t char_id)
{
    std::wstring n;
    if (SavemapCharName(char_id, n))
        return n;
    const wchar_t* def = FF7Text::DefaultCharName(char_id);
    return def ? std::wstring(def) : std::wstring();
}

// Party-character word stems -> character id (spoken via CharDisplayName).
// Sources: model catalog ("main ballet", "midgal ptifa", "nible cloud8",
// "market cloudw"...) + entity catalog ("cait" x40, "vince", "fearith",
// "ycl" = young Cloud on the Mt. Nibel flashback fields).
// v2.28 adds the devs' two/three-letter party shorthands, grounded by the
// per-field context catalog (short_entity_context_20260717 log): fields
// like loslake1 list the whole roster in slot order as
// 'cl ti cid ba ea re ket vin yuf', and blin69_1 shows 'rd' beside
// 'cl ba ea ti' (Red XIII). The full-catalog dry run confirmed no other
// entity or model label contains these as a stray token â€” except 'op cl'
// and 'cl a', which kDevEntityNames intercepts BEFORE the word pass.
struct DevCharWord { const wchar_t* stem; uint8_t char_id; };
static const DevCharWord kDevCharWords[] = {
    { L"cloud", 0 }, { L"cloudup", 0 }, { L"cloudw", 0 }, { L"pcloud", 0 },
    { L"ycl", 0 }, { L"cl", 0 },
    { L"ballet", 1 }, { L"yballet", 1 }, { L"pballet", 1 }, { L"ba", 1 },
    { L"tifa", 2 }, { L"tifas", 2 }, { L"ptifa", 2 }, { L"ti", 2 },
    { L"earith", 3 }, { L"earithf", 3 }, { L"fearith", 3 }, { L"ea", 3 },
    { L"red", 4 }, { L"pred", 4 }, { L"re", 4 }, { L"rd", 4 },
    { L"yufi", 5 }, { L"pyufi", 5 }, { L"yuf", 5 },
    { L"ketcy", 6 }, { L"cait", 6 }, { L"ket", 6 },
    { L"vincent", 7 }, { L"vince", 7 }, { L"vinsen", 7 }, { L"yvin", 7 },
    { L"vin", 7 },
    { L"cid", 8 }, { L"pcid", 8 },
};

// Word stems -> English. out == L"" means DROP the word (category prefixes
// like "main"/"std"/"midgal" carry no information a blind player needs â€”
// the browser's category already says "person"). Named NPCs are romaji or
// misspellings of their localized names (lude=Rude, hyde=Heidegger,
// esto=Ester, siera=Shera, irena=Elena, tuon=Tseng, korneo=Don Corneo...).
// avaman/avawoman/avafat = Biggs/Jessie/Wedge: the entity catalog shows
// 'av j/av b/av w' (AVALANCHE Jessie/Biggs/Wedge) on the exact bombing-
// mission fields where those three models stand (md1stin/md1_1/nmkin/
// elevtr1) â€” watch item in TODO.txt for the cargo-ship model reuse.
struct DevWord { const wchar_t* stem; const wchar_t* out; };
static const DevWord kDevWords[] = {
    // -- dropped category/location prefixes --
    { L"main", L"" }, { L"sub", L"" }, { L"std", L"" }, { L"another", L"" },
    { L"weapon", L"" }, { L"modify", L"" }, { L"animal", L"" },
    { L"midgal", L"" }, { L"korel", L"" }, { L"nible", L"" },
    { L"utai", L"" }, { L"kosta", L"" }, { L"cosmo", L"" }, { L"gold", L"" },
    { L"market", L"" }, { L"snow", L"" }, { L"farm", L"" }, { L"bone", L"" },
    { L"cf", L"" }, { L"island", L"" }, { L"gon", L"" }, { L"rocket", L"" },
    { L"junon", L"" }, { L"towerutai", L"" }, { L"sbwy", L"" },
    { L"min", L"" }, { L"md", L"" },
    // -- devices (v2.30.45; 'evb' = the No.1 reactor elevator button
    //    line, ff7_reactor_button_probe.py 2026-07-31 â€” the tester's
    //    "wall switches" report; 'switch' itself already passes through
    //    unchanged, 11 occurrences game-wide in the entity catalog) --
    { L"evb", L"elevator button" },
    // -- named NPCs (romaji / dev spellings of localized names) --
    { L"sefiro", L"Sephiroth" }, { L"cefiro", L"Sephiroth" },
    { L"cefiros", L"Sephiroth" }, { L"cefi", L"Sephiroth" },
    { L"cef", L"Sephiroth" },
    { L"avaman", L"Biggs" }, { L"avawoman", L"Jessie" },
    { L"avafat", L"Wedge" },
    { L"boo", L"Bugenhagen" }, { L"bugen", L"Bugenhagen" },
    { L"godoh", L"Godo" }, { L"korneo", L"Don Corneo" },
    { L"lude", L"Rude" }, { L"lufas", L"Rufus" }, { L"lufus", L"Rufus" },
    { L"hyde", L"Heidegger" },
    { L"hojyo", L"Hojo" }, { L"yhojo", L"Hojo" }, { L"hojo", L"Hojo" },
    { L"esto", L"Ester" }, { L"dio", L"Dio" },
    { L"pricilla", L"Priscilla" }, { L"prisl", L"Priscilla" },
    { L"ifarna", L"Ifalna" }, { L"siera", L"Shera" },
    { L"irena", L"Elena" }, { L"tuon", L"Tseng" },
    { L"zangan", L"Zangan" }, { L"emother", L"Elmyra" },
    // marine = Marlene (JP name "Marin"); exactly 1 occurrence game-wide
    // in the flevel model catalog â€” the 7th Heaven bar (player report
    // 2026-07-23 listed her raw dev name among the unreachable "people";
    // she IS a person, standing behind the bar counter off the walkmesh).
    { L"marine", L"Marlene" }, { L"marin", L"Marlene" },
    { L"cmother", L"Cloud's mother" }, { L"tfather", L"Tifa's father" },
    { L"zacks", L"Zack" }, { L"lzacks", L"Zack" }, { L"szacks", L"Zack" },
    { L"zax", L"Zack" },
    // -- creatures --
    { L"choko", L"chocobo" },
    { L"mogrif", L"moogle" }, { L"mogrim", L"moogle" },
    { L"mogrip", L"moogle" }, { L"mogriw", L"moogle" },
    { L"mogriy", L"moogle" },
    { L"iruka", L"dolphin" }, { L"ultima", L"Ultimate Weapon" },
    { L"robo", L"robot" },
    // -- role words (romaji -> English) --
    { L"hei", L"soldier" }, { L"reifuku", L"executive" },
    { L"ippan", L"employee" }, { L"onna", L"woman" },
    { L"obasan", L"woman" }, { L"oyaji", L"old man" },
    { L"oldm", L"old man" }, { L"oldman", L"old man" },
    { L"oldw", L"old woman" },
    { L"narazu", L"thug" }, { L"nara", L"thug" },
    { L"bou", L"boy" }, { L"gaki", L"kid" },
    { L"kaku", L"customer" }, { L"kakul", L"customer" },
    { L"kyaku", L"customer" }, { L"hito", L"person" },
    { L"panpi", L"civilian" }, { L"taityo", L"captain" },
    { L"noppo", L"tall man" }, { L"semusi", L"hunched man" },
    { L"muki", L"muscle man" }, { L"buka", L"henchman" },
    { L"youjin", L"bodyguard" }, { L"usan", L"shady man" },
    { L"guid", L"guide" }, { L"heli", L"helicopter" },
    { L"shinra", L"Shinra" }, { L"old", L"elder" },
    { L"fatman", L"big man" }, { L"nman", L"man" },
    // fw/fm = generic field woman/man crowd models (v2.30.91). Grounded per
    // the played-evidence rule ([WALLMKT2CH]): flevel model catalog has
    // 'std fw1' (DSBC.HRC) only on elmpb+mrkt1 and 'std fm1' (DMIA.HRC) on
    // corelin/mrkt2/mtcrl_7/ncorel -- generic-crowd fields; the 2026-08-06
    // v2.30.90 log.6 spoke bare "fm" (field 195, Wall Market main street,
    // the wandering Member's Card man) and "fw" (field 205, north street,
    // the woman by the Honey Bee Inn approach), and the user's same-night
    // screen captures show exactly those two NPCs: a man in overalls and a
    // white-capped woman. Digit suffixes strip in the word pass, so the
    // stems cover fw1/fm1/fm2/... everywhere the models recur.
    { L"fw", L"woman" }, { L"fm", L"man" },
    { L"mech", L"mechanic" }, { L"meca", L"mechanic" },
    { L"fstaff", L"attendant" }, { L"mstaff", L"attendant" },
    { L"cgirl", L"chocobo girl" },
    { L"dirver", L"driver" },
    { L"rgirl", L"girl" }, { L"sboy", L"boy" }, { L"sgirl", L"girl" },
    { L"sman", L"man" }, { L"swoman", L"woman" },
    { L"report", L"reporter" }, { L"shinobi", L"ninja" },
    { L"cloak", L"cloaked man" }, { L"mant", L"cloaked man" },
    { L"sitai", L"body" },
    { L"shain", L"employee" }, { L"baba", L"old woman" },
    { L"oldwm", L"old woman" }, { L"mihari", L"lookout" },
    { L"innman", L"innkeeper" }, { L"peo", L"person" },
    { L"sinrah", L"Shinra" }, { L"niku", L"meat" },
    // -- trigger/object words (mostly seen as entity names on lines) --
    // v2.30.67 (user request): ALL ladder stems translate to plain
    // "ladder" -- the old "ladder up"/"ladder down" outputs collided
    // with the push-direction wording ("take ladder up, down 3
    // seconds" reads as two conflicting instructions). Duplicate
    // ladders are numbered by the Triggers ordinal rule ("ladder 1",
    // "ladder 2") and TriggerLineSpokenName mirrors it for
    // journeys/proximity, so every voice says the same thing.
    { L"ladd", L"ladder" }, { L"ladu", L"ladder" },
    { L"lad", L"ladder" },
    { L"slip", L"slide" }, { L"slp", L"slide" },
    { L"tobira", L"door" },
    { L"esca", L"escalator" }, { L"ele", L"elevator" },
    { L"elinel", L"elevator" }, { L"eliner", L"elevator" },
    { L"save", L"save point" }, { L"savel", L"save point" },
    { L"takara", L"treasure" }, { L"takaraa", L"treasure" },
    { L"tre", L"treasure" }, { L"tbox", L"treasure" },
    { L"hako", L"box" },
    { L"mtr", L"materia" }, { L"po", L"potion" },
    { L"kiken", L"danger" }, { L"bunki", L"junction" },
    { L"time", L"timer" }, { L"timeo", L"timer" },
    { L"hata", L"flag" }, { L"utubo", L"pitcher plant" },
    { L"mizu", L"water" }, { L"turara", L"icicle" },
    { L"moni", L"monitor" },
    { L"evjump", L"jump" }, { L"evjp", L"jump" }, { L"evline", L"line" },
    // -- v2.28 second pass: the two/three-letter trigger shorthands the
    // player still heard raw ("ev", "dr", "jp"...). Every entry grounded
    // by the per-field context catalog (short_entity_context_20260717
    // log = full entity list of every field each stem occurs in):
    //   dr  = door  (blin671b/blin67_1 list dr1..dr6 BESIDE door1..door6;
    //                crcin_2 dr1..dr5 beside 'door')
    //   jp  = jump  (nmkin_3/mds6_1/elevtr1; colne_b1 has jp0 beside the
    //                ldu/ldd ladder lines; matches existing evjp)
    //   ev  = event (used interchangeably with 'event1/event2' â€” rcktin6
    //                names them event*, ealin_1/gldst/mds6_1 say ev)
    { L"dr", L"door" }, { L"ev", L"event" },
    { L"jp", L"jump" }, { L"ujp", L"jump" }, { L"mjp", L"jump" },
    { L"sjp", L"jump" }, { L"jpj", L"jump" }, { L"jpr", L"jump" },
    // mes/meskun ("message-kun") = MESSAGE lines, checkun/chekun the
    // matching check lines (ealin_1 pairs 'meskun'/'checkun'; gldgate
    // 'meskun'/'chekun'); bmes = loslake1's message line.
    { L"mes", L"message" }, { L"bmes", L"message" },
    { L"meskun", L"message" },
    { L"checkun", L"check" }, { L"chekun", L"check" },
    // ln0/lin0 are used exactly like the (already-English) 'line' lines
    // (blin66_1 'ln0 ln1', sandun_1 'lin4..lin19').
    { L"ln", L"line" }, { L"lin", L"line" },
    // ldu/ldd = ladu/ladd contractions (colne_b1: 'ldu0 ldd0 ldu2 ldd2',
    // the Corel-reactor ladder lines); esc = esca contraction (blin68_1
    // and blin69_1 list 'esc0' beside 'esca'/'esca2').
    { L"ldu", L"ladder" }, { L"ldd", L"ladder" },   // v2.30.67: plain
                                                    // "ladder" (see above)
    { L"esc", L"escalator" },
    // Shinra-HQ elevator family: eleu/eled = up/down call lines (blin1),
    // elel/eler = left/right car (blin69_1), *dr = the car doors
    // (blin66_1 'eleldr elerdr', blin68_1 'eledr0').
    { L"eleu", L"elevator" }, { L"eled", L"elevator" },
    { L"elel", L"elevator" }, { L"eler", L"elevator" },
    { L"eledr", L"elevator door" }, { L"eleldr", L"elevator door" },
    { L"elerdr", L"elevator door" },
};

// Entity FULL-NAME table, checked before the word pass (names whose words
// are too short/ambiguous to translate in isolation). Matched against the
// whole entity name after trailing digits/spaces are stripped.
static const DevWord kDevEntityNames[] = {
    { L"av j", L"Jessie" }, { L"av b", L"Biggs" }, { L"av w", L"Wedge" },
    { L"av m", L"AVALANCHE member" }, { L"av l", L"AVALANCHE member" },
    { L"av s", L"AVALANCHE member" }, { L"av c", L"AVALANCHE member" },
    { L"mk save", L"save point" }, { L"save l", L"save point" },
    // (bare "dr3" now handled by the v2.28 word-level 'dr' entry.)
    // v2.28 multi-word names whose words would mistranslate in isolation
    // (context catalog evidence, short_entity_context_20260717 log):
    // train-car fields tin_1..4 pair 'dr an'/'tr an' = door/train
    // animation lines; blin60_2 pairs 'op cl1/op cl2' (open-close) with
    // 'door1/door2' â€” 'cl' there is NOT Cloud, so intercept before the
    // word pass turns it into his name.
    { L"dr an", L"door" }, { L"tr an", L"train" },
    { L"op cl", L"door" },
    // fship_22/24 'cl a' is also NOT Cloud (both fields carry a separate
    // 'cloud' entity; 'cl a' sits among the drctr/ad cutscene
    // controllers). Meaning unknown -> map to itself so the word pass
    // cannot invent a wrong name (wrong is worse than terse).
    { L"cl a", L"cl a" },
};

// Translate one dev label ("shinra hei 2" style, space-separated) into its
// speakable form. Unknown words pass through; if everything drops, the raw
// label is returned so a destination can never become nameless.
static std::wstring TranslateDevLabel(const std::wstring& raw)
{
    std::wstring out;
    size_t pos = 0;
    while (pos <= raw.size()) {
        const size_t sp = raw.find(L' ', pos);
        const size_t end = (sp == std::wstring::npos) ? raw.size() : sp;
        std::wstring tok = raw.substr(pos, end - pos);
        pos = end + 1;
        if (tok.empty())
            continue;

        // Stem = token minus leading/trailing digits ("22main"/"man401").
        size_t b = 0, e = tok.size();
        while (b < e && iswdigit(tok[b])) ++b;
        while (e > b && iswdigit(tok[e - 1])) --e;
        const std::wstring stem = tok.substr(b, e - b);

        // Single-character stems are connective noise ("n", side markers).
        if (stem.size() <= 1)
            continue;

        const wchar_t* repl = nullptr;
        std::wstring char_name;
        for (const DevCharWord& cw : kDevCharWords) {
            if (stem == cw.stem) {
                char_name = CharDisplayName(cw.char_id);
                break;
            }
        }
        if (char_name.empty()) {
            for (const DevWord& w : kDevWords) {
                if (stem == w.stem) {
                    repl = w.out;
                    break;
                }
            }
        }
        if (repl && repl[0] == L'\0')
            continue;                        // explicit drop word

        if (!out.empty())
            out += L' ';
        if (!char_name.empty())
            out += char_name;
        else
            // Unknown words speak their STEM, not the raw token: dev digit
            // suffixes are arbitrary ("man6"/"man401" are just distinct
            // .char files) â€” the browser's slot-order ordinals are the
            // numbering a listener can actually use ("man", "man 2").
            // (Caught by the catalog dry run: the first draft appended the
            // raw token, so "std man6" spoke as "man6".)
            out += repl ? repl : stem.c_str();
    }
    return out.empty() ? raw : out;
}

// Translate a script entity name (trigger lines): whole-name table first
// (multi-word/ambiguous names like "av j" or bare "dr3"), then the shared
// word pass.
static std::wstring TranslateEntityName(const std::wstring& raw)
{
    std::wstring stem = raw;
    while (!stem.empty() &&
           (iswdigit(stem.back()) || stem.back() == L' '))
        stem.pop_back();
    for (const DevWord& n : kDevEntityNames) {
        if (stem == n.stem)
            return n.out;
    }
    return TranslateDevLabel(raw);
}

// ---------------------------------------------------------------------------
// Field model label from the raw MODEL LOADER section (v2.16).
//
// Walks section 2 of the field file buffer (format decoded live 2026-07-13,
// see ff7_addresses.h) to the requested model index and converts its .char
// name into a speakable label: "md1stinshinra_hei.char" -> "shinra hei"
// (strip the current field-name prefix and the ".char" suffix, lowercase,
// underscores to spaces). Every step is bounds-checked against the
// section's size prefix â€” a torn buffer mid field-transition returns false
// (callers fall back to "Person N") rather than reading garbage.
// ---------------------------------------------------------------------------
static bool FieldModelLabel(int model_idx, const char* field_name,
                            std::wstring& out)
{
    const uint32_t buf = *reinterpret_cast<const volatile uint32_t*>(
        FF7Addr::FIELD_FILE_BUFFER);
    if (buf < 0x401000)
        return false;
    if (!IsReadableSpan(reinterpret_cast<const void*>(buf),
                        FF7Addr::FIELD_SECTION_TABLE_OFF + 9 * 4))
        return false;

    const uint32_t sec_off = *reinterpret_cast<const uint32_t*>(
        buf + FF7Addr::FIELD_SECTION_TABLE_OFF +
        FF7Addr::FIELD_MODEL_SECTION_INDEX * 4);
    if (sec_off < FF7Addr::FIELD_SECTION_TABLE_OFF || sec_off > 0x200000)
        return false;
    const uint8_t* sec = reinterpret_cast<const uint8_t*>(buf + sec_off);
    if (!IsReadableSpan(sec, 4))
        return false;
    const uint32_t sec_size = *reinterpret_cast<const uint32_t*>(sec);
    if (sec_size < 8 || sec_size > 0x10000)
        return false;
    const uint8_t* p   = sec + 4;
    const uint8_t* end = p + sec_size;
    if (!IsReadableSpan(p, sec_size))
        return false;

    const auto rd16 = [](const uint8_t* q) {
        return static_cast<uint16_t>(q[0] | (q[1] << 8));
    };
    const uint16_t n_models = rd16(p + 2);
    if (n_models > 64 || model_idx >= static_cast<int>(n_models))
        return false;
    p += 6;

    for (int m = 0; m < static_cast<int>(n_models); ++m) {
        if (p + 2 > end) return false;
        const uint16_t nlen = rd16(p);
        p += 2;
        if (nlen == 0 || nlen > 64 || p + nlen > end)
            return false;

        if (m == model_idx) {
            // Build the label: lowercase, strip field-name prefix and
            // ".char" suffix, underscores become spaces. Any non-ASCII
            // byte inside the name means we're reading the wrong data â€”
            // REJECT the whole name (callers fall back to "Person N").
            // Policy unified with the entity-name reader 2026-07-14: this
            // used to truncate at the first bad byte and speak the prefix,
            // which could voice a misleading fragment; the 720-field
            // catalog shows every real label is pure ASCII, so rejection
            // never fires on genuine data.
            char raw[65] = {};
            memcpy(raw, p, nlen);
            for (char& c : raw) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                else if (c != '\0' && (c < 0x20 || c > 0x7E)) return false;
            }
            size_t len = strlen(raw);
            if (len > 5 && memcmp(raw + len - 5, ".char", 5) == 0) {
                raw[len - 5] = '\0';
                len -= 5;
            }
            if (field_name && field_name[0]) {
                char fn[16] = {};
                for (size_t i = 0; i < 9 && field_name[i]; ++i)
                    fn[i] = (field_name[i] >= 'A' && field_name[i] <= 'Z')
                        ? static_cast<char>(field_name[i] - 'A' + 'a')
                        : field_name[i];
                const size_t fl = strlen(fn);
                if (fl > 0 && len > fl && memcmp(raw, fn, fl) == 0) {
                    memmove(raw, raw + fl, len - fl + 1);
                    len -= fl;
                }
            }
            out.clear();
            for (size_t i = 0; raw[i]; ++i)
                out += (raw[i] == '_') ? L' ' : static_cast<wchar_t>(raw[i]);
            while (!out.empty() && out.front() == L' ')
                out.erase(out.begin());
            while (!out.empty() && out.back() == L' ')
                out.pop_back();
            return !out.empty();
        }

        p += nlen;
        p += 2 + 8 + 4;               // unknown, HRC name, scale string
        if (p + 2 > end) return false;
        const uint16_t nanim = rd16(p);
        p += 2;
        if (nanim > 64) return false;
        p += FF7Addr::FMODEL_LIGHT_BLOCK_SIZE;
        for (uint16_t a = 0; a < nanim; ++a) {
            if (p + 2 > end) return false;
            const uint16_t alen = rd16(p);
            p += 2;
            if (alen > 64 || p + alen + 2 > end) return false;
            p += alen + 2;            // name + trailing u16
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Solid-body helpers (v2.30.22) â€” implementations for the declarations
// above WallBumpThread; the derivation and constants live in that block.
//
// All of this is self-contained reading (event array, triggers header,
// model-loader labels) so it can be called from BOTH the wall-bump thread
// and the pathfinder thread without shared state: FieldModelLabel /
// ClassifyModelLabel / TranslateDevLabel are pure per-call parsers over
// the (engine-owned, read-only to us) field file buffer. Cost is one
// section-2 parse per model per call â€” called once per contact episode or
// once per directions keypress, both far off any hot path.
// ---------------------------------------------------------------------------
static float HeldDirInputDeg(uint32_t keys)
{
    const bool u = (keys & FF7Addr::KEY_DIR_UP)    != 0;
    const bool r = (keys & FF7Addr::KEY_DIR_RIGHT) != 0;
    const bool d = (keys & FF7Addr::KEY_DIR_DOWN)  != 0;
    const bool l = (keys & FF7Addr::KEY_DIR_LEFT)  != 0;
    if (u && !d) return r ? 45.0f  : (l ? 315.0f : 0.0f);
    if (d && !u) return r ? 135.0f : (l ? 225.0f : 180.0f);
    if (r && !l) return 90.0f;
    if (l && !r) return 270.0f;
    return -1.0f;
}

// The player's own live collision radius (same +0x72 field on the player's
// element). Falls back to 32 when the element is unreadable or the value
// implausible. Used for PROXIMITY semantics only (reach bubbles, journey
// completion) â€” the field the engine itself initializes from the field
// scale at arrival (0x633FBC: 34 Â· scale >> 9) and consults for talk
// targeting and NPC steering, never to block the player (v2.30.83).
static float PlayerCollisionRadius()
{
    const uint32_t arr = *reinterpret_cast<const volatile uint32_t*>(
        FF7Addr::FIELD_EVENT_DATA_PTR);
    const uint16_t pmid = *reinterpret_cast<const volatile uint16_t*>(
        FF7Addr::FIELD_PLAYER_MODEL_ID);
    if (arr < 0x401000 || pmid > 0x20)
        return 32.0f;
    const uint8_t* me = reinterpret_cast<const uint8_t*>(
        arr + pmid * FF7Addr::FIELD_EVENT_DATA_STRIDE);
    if (!IsReadableSpan(me, FF7Addr::FIELD_EVENT_DATA_STRIDE))
        return 32.0f;
    const int16_t rr = *reinterpret_cast<const int16_t*>(
        me + FF7Addr::FIELD_EVENT_COLLISION_RADIUS);
    return (rr >= 8 && rr <= 120) ? static_cast<float>(rr) : 32.0f;
}

// Is the player pinned against a STORY-LOCKED edge in the pushed
// direction? (v2.30.83 -- the wall-vs-story-gate discriminator.)
//
// Called by the wall-bump thread once per contact episode, when the
// player is provably frozen pushing a direction. The engine refuses a
// crossing when the DESTINATION triangle's IDLCK bit is set (edge tests
// 0x6369E8/0x636AAF/0x636B76 inside the try-move); mirroring that:
// load the RAW mesh (locks NOT cut, so locked neighbors are still
// visible as neighbors), take the player's triangle, and look for an
// edge whose neighbor is locked, whose outward normal roughly matches
// the push direction, and which the player is standing close to (a
// frozen player rests against the refusing edge). Any such edge means
// the "wall" is a script gate that will open later -- worth saying,
// because walking elsewhere WON'T help a player who is expected to
// come back here after a story beat.
static bool LockedEdgeAhead(float world_deg)
{
    const uint32_t arr = *reinterpret_cast<const volatile uint32_t*>(
        FF7Addr::FIELD_EVENT_DATA_PTR);
    const uint16_t pmid = *reinterpret_cast<const volatile uint16_t*>(
        FF7Addr::FIELD_PLAYER_MODEL_ID);
    if (arr < 0x401000 || pmid > 0x20)
        return false;
    const uint8_t* me = reinterpret_cast<const uint8_t*>(
        arr + pmid * FF7Addr::FIELD_EVENT_DATA_STRIDE);
    if (!IsReadableSpan(me, FF7Addr::FIELD_EVENT_DATA_STRIDE))
        return false;
    const int16_t tri = *reinterpret_cast<const int16_t*>(
        me + FF7Addr::FIELD_EVENT_TRIANGLE_ID);
    if (tri < 0)
        return false;
    const int32_t* mpos = reinterpret_cast<const int32_t*>(
        me + FF7Addr::FIELD_EVENT_MODEL_POS);
    const float px = static_cast<float>(mpos[0] >> 12);
    const float py = static_cast<float>(mpos[1] >> 12);

    std::vector<WalkTri> mesh;
    if (!LoadWalkmesh(mesh, /*apply_locks=*/false))
        return false;
    if (static_cast<size_t>(tri) >= mesh.size())
        return false;

    const float rad = world_deg * (3.14159265f / 180.0f);
    const float ux = sinf(rad), uy = cosf(rad);
    const WalkTri& w = mesh[tri];
    for (int e = 0; e < 3; ++e) {
        const uint16_t nb = w.nbr[e];
        if (nb == FF7Addr::FWMESH_NO_NEIGHBOR ||
            !FF7Addr::is_triangle_locked(nb))
            continue;
        const int f = (e + 1) % 3, o = (e + 2) % 3;
        // Outward edge normal = perpendicular pointing away from the
        // third vertex (i.e. out of the triangle through this edge).
        float nx = w.vy[f] - w.vy[e];
        float ny = -(w.vx[f] - w.vx[e]);
        const float ox = w.vx[o] - w.vx[e];
        const float oy = w.vy[o] - w.vy[e];
        if (nx * ox + ny * oy > 0.0f) { nx = -nx; ny = -ny; }
        const float nlen = sqrtf(nx * nx + ny * ny);
        if (nlen <= 0.0f)
            continue;
        // Pushing roughly INTO the locked edge (within ~72 degrees --
        // generous because the freeze predicate already proved the
        // held direction produces no movement)...
        if ((ux * nx + uy * ny) / nlen < 0.3f)
            continue;
        // ...while standing against it (a pinned player rests at the
        // refusing edge; 48 covers every field-scale player radius).
        if (PointSegDist2(px, py, w.vx[e], w.vy[e],
                          w.vx[f], w.vy[f]) > 48.0f * 48.0f)
            continue;
        return true;
    }
    return false;
}

// Would the route target be reachable if every IDLCK story lock were
// open? (v2.30.83.) Called only after routing on the lock-cut graph
// returned NO_PATH: true = the target is walled off by SCRIPT locks,
// not geometry -- a "closed for now" story gate the player should
// expect to open later; false = genuinely disconnected (another level,
// off-mesh) and the existing fallbacks (connector journeys, nearest-
// reachable) apply.
static bool ReachableIgnoringLocks(float px, float py, float pz,
                                   int start_hint,
                                   float tx, float ty, float tz,
                                   int goal_hint)
{
    std::vector<WalkTri> mesh;
    if (!LoadWalkmesh(mesh, /*apply_locks=*/false))
        return false;
    const int start = ResolveTriHint(mesh, start_hint, px, py, pz);
    const int goal  = ResolveTriHint(mesh, goal_hint, tx, ty, tz);
    if (start < 0 || goal < 0)
        return false;
    std::vector<uint16_t> path;
    return WalkmeshAStar(mesh, start, goal, path);
}

// ---------------------------------------------------------------------------
// Script entity dev-names from field-file section 0 (v2.17, reworked
// 2026-07-14 after code review).
//
// The script section header carries an 8-char ASCII name per entity at
// +0x20 + id*8 ("cloud", "svisen1", "yubiwa"...) â€” the same
// developer-naming trick that labels people (v2.16), applied to the entity
// that OWNS a LINE trigger zone.
//
// Split into resolve-once + read-per-entity so the trigger build validates
// the WHOLE name table span exactly once per keypress instead of
// re-reading the script pointer and re-probing pages for every line (the
// review's efficiency finding), and so the validation actually covers
// every byte that gets read â€” the old single function probed only the
// header page and the LAST byte of one name, leaving the nEntities byte
// and name[0..6] unguarded when they fell on a different page (the
// review's crash-risk finding).
// ---------------------------------------------------------------------------
static bool FieldEntityNameTable(const uint8_t** table_out,
                                 uint8_t* count_out)
{
    const uint32_t script = *reinterpret_cast<const volatile uint32_t*>(
        FF7Addr::FIELD_SCRIPT_PTR);
    if (script < 0x401000)
        return false;
    // Header span covers nEntities at +2 up through the name table start.
    if (!IsReadableSpan(reinterpret_cast<const void*>(script),
                        FF7Addr::FSCRIPT_ENTITY_NAMES_OFF))
        return false;
    const uint8_t n = *reinterpret_cast<const uint8_t*>(
        script + FF7Addr::FSCRIPT_NENTITIES_OFF);
    if (n == 0)
        return false;
    const uint8_t* table = reinterpret_cast<const uint8_t*>(
        script + FF7Addr::FSCRIPT_ENTITY_NAMES_OFF);
    if (!IsReadableSpan(table, static_cast<size_t>(n) * 8))
        return false;
    *table_out = table;
    *count_out = n;
    return true;
}

// Speakable name for one entity from a table validated by the call above.
// Underscores become spaces. Returns false (caller falls back to
// "Trigger N") when the id is out of range or the bytes aren't printable
// ASCII â€” same reject-garbage policy as FieldModelLabel.
static bool EntityNameFromTable(const uint8_t* table, uint8_t n_entities,
                                int entity_id, std::wstring& out)
{
    if (entity_id < 0 || entity_id >= n_entities)
        return false;
    const uint8_t* name = table + entity_id * 8;
    out.clear();
    for (int i = 0; i < 8 && name[i] != 0; ++i) {
        if (name[i] < 0x20 || name[i] > 0x7E)
            return false;   // not ASCII = wrong data, don't speak garbage
        out += (name[i] == '_') ? L' ' : static_cast<wchar_t>(name[i]);
    }
    while (!out.empty() && out.back() == L' ')
        out.pop_back();
    return !out.empty();
}

// ---------------------------------------------------------------------------
// Cross-layer JOURNEY planning (v2.23) â€” "which ladder first?"
//
// User request 2026-07-16: when a destination sits on another walkmesh
// LEVEL, "No walkable path found" says WHAT but not HOW â€” the player wants
// the connector sequence: which ladder/slide to take FIRST, then next, in
// order.
//
// The walkmesh alone cannot answer: levels are DISCONNECTED graph
// components by design, and the join is a scripted LINE trigger (ladder,
// slide, elevator) that MOVES the player. The script's destination is not
// readable statically â€” but the geometry is: a ladder's bottom zone and
// top zone are XY-PROXIMATE lines on different components. Live nmkin_2
// data (2026-07-16 session log): 'ladder up' bottom line midpoint sits
// 134 XY units from 'ladder down' top line midpoint, 217 units apart in
// height. Hence:
//
//   connector = a PAIR of enabled LINE triggers on different components
//   whose XY midpoints are within JOURNEY_PAIR_DIST (300 = the measured
//   134 with slack), plus any single line whose own endpoints span two
//   components (a line drawn up a wall).
//
// BFS over components along connectors yields the trigger SEQUENCE; the
// spoken result is a walking route to the FIRST connector plus the
// ordered names of the rest: "Exit 1: on another level. First take
// ladder up, up 3 seconds. Then slide. Then ask again." Re-querying after
// each connector recomputes from the new level â€” the same re-query flow
// the pathfinder already teaches.
//
// A false pairing (two unrelated triggers stacked in XY) would give a
// wrong-but-harmless hint: the journey only runs AFTER a direct route
// failed, every hop is spoken BY NAME so the player can judge it, and the
// fallback ("No walkable path found" + straight line) still exists when
// no connector chain is found.
// ---------------------------------------------------------------------------

// Connected components of the walkmesh adjacency graph â€” each component is
// one "level"/region reachable by plain walking. Iterative flood fill.
static int WalkmeshComponents(const std::vector<WalkTri>& m,
                              std::vector<int>& comp)
{
    comp.assign(m.size(), -1);
    std::vector<uint16_t> stack;
    int n_comps = 0;
    for (size_t seed = 0; seed < m.size(); ++seed) {
        if (comp[seed] != -1)
            continue;
        comp[seed] = n_comps;
        stack.push_back(static_cast<uint16_t>(seed));
        while (!stack.empty()) {
            const uint16_t t = stack.back();
            stack.pop_back();
            for (int e = 0; e < 3; ++e) {
                const uint16_t nb = m[t].nbr[e];
                if (nb != FF7Addr::FWMESH_NO_NEIGHBOR && comp[nb] == -1) {
                    comp[nb] = n_comps;
                    stack.push_back(nb);
                }
            }
        }
        ++n_comps;
    }
    return n_comps;
}

// Spoken name for a LINE trigger â€” the same naming rules as the Triggers
// category (owning entity's dev name, translated; stale-guarded by the
// entityâ†’slot map; "Trigger N" fallback), INCLUDING the duplicate
// ordinal since v2.30.67: with all ladder stems now translating to plain
// "ladder", a two-ladder field must say "ladder 1"/"ladder 2" here too
// (journeys, proximity announce) or the browser and the journey would
// name the same rung differently â€” the one-vocabulary rule (v2.30.62).
static void TriggerLineSpokenName(uint32_t line_idx, uint8_t ent,
                                  std::wstring& out)
{
    const uint8_t mapped = *reinterpret_cast<const volatile uint8_t*>(
        FF7Addr::FIELD_ENTITY_LINE_SLOT + ent);
    const uint8_t* tbl = nullptr;
    uint8_t n = 0;
    std::wstring ename;
    if (FieldEntityNameTable(&tbl, &n) && mapped == line_idx &&
        EntityNameFromTable(tbl, n, ent, ename)) {
        out = TranslateEntityName(ename);
        // Ordinal among ENABLED same-named lines in live-array slot
        // order â€” the exact rule the Triggers category applies to its
        // gathered list, so both paths produce identical numbers.
        const uint16_t n_lines =
            *reinterpret_cast<const volatile uint16_t*>(
                FF7Addr::FIELD_LINE_COUNT);
        int ordinal = 1, total = 0;
        for (uint32_t i = 0; i < n_lines && i < FF7Addr::FLINE_MAX; ++i) {
            const uint8_t* le = reinterpret_cast<const uint8_t*>(
                FF7Addr::FIELD_LINE_ARRAY + i * FF7Addr::FLINE_STRIDE);
            if (le[FF7Addr::FLINE_OFF_ENABLED] == 0)
                continue;
            const uint8_t oent = le[FF7Addr::FLINE_OFF_ENTITY];
            const uint8_t omap = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::FIELD_ENTITY_LINE_SLOT + oent);
            std::wstring oname;
            if (omap != i || !EntityNameFromTable(tbl, n, oent, oname))
                continue;   // unnamed lines fall back to "Trigger N" in
                            // the browser -- never a duplicate of a name
            if (TranslateEntityName(oname) == out) {
                ++total;
                if (i < line_idx)
                    ++ordinal;
            }
        }
        if (total > 1) {
            wchar_t obuf[8];
            _snwprintf_s(obuf, _countof(obuf), _TRUNCATE, L" %d", ordinal);
            out += obuf;
        }
        return;
    }
    wchar_t buf[24];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"Trigger %u", line_idx + 1u);
    out = buf;
}

// ---------------------------------------------------------------------------
// Journey connector graph (v2.30.87) â€” the line snapshot, connector-edge
// rules, and component BFS factored out of BuildJourneySpeech so the
// Shift+\ path filter can ask "is that LEVEL reachable at all?" for every
// destination from ONE snapshot instead of re-planning per entry. One code
// path for the reachability verdict means the filter and the spoken
// journey can never disagree (the one-vocabulary rule applied to routes).
// ---------------------------------------------------------------------------
struct JourneyLine {
    float   mx, my, mz;   // line midpoint â€” the standing point
    int     tri, comp;    // midpoint's triangle and component
    int     comp2;        // component of the SECOND endpoint (a line
                          // drawn up a wall spans levels by itself)
    uint8_t idx, ent;     // live array slot + owning entity (naming)
};
struct JourneyEdge { int ca, cb; int via; };   // stand on jl[via] (in ca)
struct JourneyGraph {
    JourneyLine jl[FF7Addr::FLINE_MAX];
    int         n_jl = 0;
    std::vector<JourneyEdge> edges;
    std::vector<uint8_t> seen;        // per component: connector-reachable
                                      // from the start component
    std::vector<int>     prev_edge;   // BFS tree (index into edges) â€” the
                                      // hop sequence reconstructs from it
};

// Snapshot enabled LINE triggers, build connector edges, and BFS the
// component graph from start_comp to EXHAUSTION â€” not to one goal,
// because the filter asks about many goals (component counts are tiny,
// so the extra breadth costs nothing). False = no connector edges exist.
static bool BuildJourneyGraph(const std::vector<WalkTri>& mesh,
                              const std::vector<int>& comp, int n_comps,
                              int start_comp, JourneyGraph& g)
{
    // Snapshot enabled LINE triggers: standing point (line midpoint, with
    // height), its component, and identity. Same array and enabled-guard
    // as the Triggers category.
    const uint16_t n_lines = *reinterpret_cast<const volatile uint16_t*>(
        FF7Addr::FIELD_LINE_COUNT);
    for (uint32_t i = 0; i < n_lines && i < FF7Addr::FLINE_MAX; ++i) {
        const uint8_t* le = reinterpret_cast<const uint8_t*>(
            FF7Addr::FIELD_LINE_ARRAY + i * FF7Addr::FLINE_STRIDE);
        if (le[FF7Addr::FLINE_OFF_ENABLED] == 0)
            continue;
        const int16_t* v = reinterpret_cast<const int16_t*>(le);
        JourneyLine& j = g.jl[g.n_jl];
        j.mx = (v[0] + v[3]) * 0.5f;
        j.my = (v[1] + v[4]) * 0.5f;
        j.mz = (v[2] + v[5]) * 0.5f;
        j.tri = WalkmeshLocate(mesh, j.mx, j.my, j.mz);
        if (j.tri < 0)
            continue;
        j.comp  = comp[j.tri];
        const int t2 = WalkmeshLocate(mesh,
                                      static_cast<float>(v[3]),
                                      static_cast<float>(v[4]),
                                      static_cast<float>(v[5]));
        j.comp2 = (t2 >= 0) ? comp[t2] : j.comp;
        j.idx = static_cast<uint8_t>(i);
        j.ent = le[FF7Addr::FLINE_OFF_ENTITY];
        ++g.n_jl;
    }

    // Connector edges between components (see the journey header comment):
    //   pair rule â€” two triggers on different components, XY-close;
    //   span rule â€” one trigger whose own endpoints are on two components.
    constexpr float JOURNEY_PAIR_DIST = 300.0f;
    for (int a = 0; a < g.n_jl; ++a) {
        if (g.jl[a].comp2 != g.jl[a].comp) {
            g.edges.push_back({ g.jl[a].comp,  g.jl[a].comp2, a });
            g.edges.push_back({ g.jl[a].comp2, g.jl[a].comp,  a });
        }
        for (int b = a + 1; b < g.n_jl; ++b) {
            if (g.jl[a].comp == g.jl[b].comp)
                continue;
            const float dx = g.jl[a].mx - g.jl[b].mx;
            const float dy = g.jl[a].my - g.jl[b].my;
            if (dx * dx + dy * dy >
                JOURNEY_PAIR_DIST * JOURNEY_PAIR_DIST)
                continue;
            g.edges.push_back({ g.jl[a].comp, g.jl[b].comp, a });
            g.edges.push_back({ g.jl[b].comp, g.jl[a].comp, b });
        }
    }
    if (g.edges.empty())
        return false;

    // BFS over components: fewest connectors from the start's level
    // outward. prev_edge reconstructs any trigger sequence.
    g.prev_edge.assign(n_comps, -1);
    g.seen.assign(n_comps, 0);
    std::vector<int> queue;
    g.seen[start_comp] = 1;
    queue.push_back(start_comp);
    for (size_t qi = 0; qi < queue.size(); ++qi) {
        const int c = queue[qi];
        for (size_t e = 0; e < g.edges.size(); ++e) {
            if (g.edges[e].ca != c || g.seen[g.edges[e].cb])
                continue;
            g.seen[g.edges[e].cb] = 1;
            g.prev_edge[g.edges[e].cb] = static_cast<int>(e);
            queue.push_back(g.edges[e].cb);
        }
    }
    return true;
}

// Journey plan for a target on another component. True = `out` holds the
// full spoken message (destination name included); false = no connector
// chain found (caller speaks the no-path fallback).
static bool BuildJourneySpeech(float px, float py, float pz, int start_hint,
                               float tx, float ty, float tz, int goal_hint,
                               float control_deg, const wchar_t* dest_name,
                               std::wstring& out)
{
    std::vector<WalkTri> mesh;
    if (!LoadWalkmesh(mesh))
        return false;
    const int start = ResolveTriHint(mesh, start_hint, px, py, pz);
    const int goal  = ResolveTriHint(mesh, goal_hint, tx, ty, tz);
    if (start < 0 || goal < 0)
        return false;

    std::vector<int> comp;
    const int n_comps = WalkmeshComponents(mesh, comp);
    if (n_comps < 2 || comp[start] == comp[goal])
        return false;   // same level â€” not a journey problem

    JourneyGraph g;
    if (!BuildJourneyGraph(mesh, comp, n_comps, comp[start], g))
        return false;
    if (!g.seen[comp[goal]])
        return false;   // levels exist but nothing connects them

    // Trigger sequence, player's level first.
    std::vector<int> hops;   // g.jl indices to take, in order
    for (int c = comp[goal]; c != comp[start]; ) {
        const JourneyEdge& e = g.edges[g.prev_edge[c]];
        hops.push_back(e.via);
        c = e.ca;
    }
    for (size_t i = 0, j = hops.size() - 1; i < j; ++i, --j) {
        const int t = hops[i]; hops[i] = hops[j]; hops[j] = t;
    }

    // Walking route to the FIRST connector (same pipeline as a direct
    // route; the connector is in the player's own component by
    // construction, so A* cannot fail â€” guarded anyway).
    std::wstring route;
    {
        const JourneyLine& first = g.jl[hops[0]];
        std::vector<uint16_t> path;
        if (WalkmeshAStar(mesh, start, first.tri, path)) {
            std::vector<PathPortal> portals;
            BuildPortals(mesh, path, portals);
            std::vector<NavPt> corners;
            FunnelPath(px, py, first.mx, first.my, portals, corners);
            if (corners.empty()) {
                for (const PathPortal& p : portals)
                    corners.push_back({ (p.lx + p.rx) * 0.5f,
                                        (p.ly + p.ry) * 0.5f });
                corners.push_back({ first.mx, first.my });
            }
            route = RouteToSpeech(px, py, corners, control_deg);
        }
    }

    // "Exit 1: on another level. First take ladder up, up 3 seconds.
    //  Then slide. Then ask again."
    out = dest_name;
    out += L": on another level. First take ";
    std::wstring nm;
    TriggerLineSpokenName(g.jl[hops[0]].idx, g.jl[hops[0]].ent, nm);
    out += nm;
    if (!route.empty()) {
        out += L", ";
        out += route;
    }
    for (size_t h = 1; h < hops.size(); ++h) {
        TriggerLineSpokenName(g.jl[hops[h]].idx, g.jl[hops[h]].ent, nm);
        out += L". Then ";
        out += nm;
    }
    out += L". Then ask again.";

    if (Config::Get().debug_log) {
        char dbg[224];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] NAV journey comps=%d hops=%u first_line=%u '%ls'",
            n_comps, static_cast<unsigned>(hops.size()),
            static_cast<unsigned>(g.jl[hops[0]].idx), out.c_str());
        Log::Write(dbg);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Interaction reach for a model destination (v2.30.25/.26 rules, factored
// out of the directions handler in v2.30.87 so the path filter applies the
// SAME reach): how far short of the model a walk may stop and still
// interact â€” max(talk radius clamped to [20, 90], body contact =
// player_col + model_col + 8). The talk radius is read LIVE per call
// because scripts change both radii at runtime (v2.30.24 lesson: never
// cache). Non-model destinations (exits, LINE zones, hotspots) return 0:
// those must be stepped on.
// ---------------------------------------------------------------------------
static float ModelTargetReach(uint32_t arr, int model_slot)
{
    if (model_slot < 0)
        return 0.0f;
    int16_t tr = 40;
    int16_t mc = 0;
    const uint8_t* tme = reinterpret_cast<const uint8_t*>(
        arr + model_slot * FF7Addr::FIELD_EVENT_DATA_STRIDE);
    if (IsReadableSpan(tme, FF7Addr::FIELD_EVENT_DATA_STRIDE)) {
        tr = *reinterpret_cast<const int16_t*>(
            tme + FF7Addr::FIELD_EVENT_TALK_RADIUS);
        mc = *reinterpret_cast<const int16_t*>(
            tme + FF7Addr::FIELD_EVENT_COLLISION_RADIUS);
    }
    if (tr < 20) tr = 20;
    if (tr > 90) tr = 90;
    float reach = static_cast<float>(tr);
    if (mc > 0 && mc <= 200) {
        const float contact = PlayerCollisionRadius()
                              + static_cast<float>(mc) + 8.0f;
        if (contact > reach)
            reach = contact;
    }
    return reach;
}

// ---------------------------------------------------------------------------
// Path filter (v2.30.87, Shift+\ or Shift+P): drop every destination the
// player has NO valid path to right now, so J/L cycles only things a
// directions request would actually route to. "Valid path" mirrors the
// \-key outcome ladder exactly, in the same order:
//   1. same walkmesh component (locks applied)         -> KEEP (a route);
//   2. raw-mesh-connected but lock-cut                 -> HIDE ("the way
//      there is closed for now" is not a path â€” hiding story-locked
//      doors is the point of the filter);
//   3. another level with a connector-chain journey    -> KEEP (ladders);
//   4. model off the walkable floor whose gap from the nearest reachable
//      triangle is within its interaction reach        -> KEEP (Biggs on
//      the crates: the walk ends at the crates, talk radius covers the
//      last step). Beyond reach                        -> HIDE â€” this is
//      deliberately STRICTER than \, which always speaks an "off the
//      walkable area" route to the nearest point; a filter that never
//      hides anything would be a no-op for people/items.
// FAIL-OPEN: mesh unreadable or the player unlocatable leaves the list
// untouched â€” never hide destinations on a transient read failure (the
// same honesty rule as the route builder's UNAVAILABLE fallback).
// Names/ordinals were assigned at build time, BEFORE this pass, so
// filtering never renumbers anything ("Exit 2" stays "Exit 2" while
// "Exit 1" is hidden â€” the identity-stability rule).
// Runs per keypress like everything else in the browser: one locked mesh
// + one component flood + one journey graph answer ALL destinations; the
// raw (lock-ignoring) mesh loads lazily only when something is
// unreachable. out_hidden reports how many entries were dropped so the
// announcements can say the list is filtered.
// ---------------------------------------------------------------------------
static void FilterReachableDests(NavDest* dests, int& n_dests,
                                 float px, float py, float pz,
                                 int player_tri, uint32_t arr,
                                 int& out_hidden)
{
    out_hidden = 0;
    std::vector<WalkTri> mesh;
    if (!LoadWalkmesh(mesh))
        return;   // fail-open
    const int start = ResolveTriHint(mesh, player_tri, px, py, pz);
    if (start < 0)
        return;   // fail-open
    std::vector<int> comp;
    const int n_comps = WalkmeshComponents(mesh, comp);

    // Connector journeys can only exist when there are other levels.
    JourneyGraph jg;
    const bool jg_ok = n_comps > 1 &&
        BuildJourneyGraph(mesh, comp, n_comps, comp[start], jg);

    // Raw mesh for the lock discrimination, loaded at most once (see
    // rule 2 above). rstart == -2 marks "not tried yet".
    std::vector<WalkTri> raw;
    std::vector<int>     rcomp;
    int rstart = -2;

    int kept = 0;
    for (int i = 0; i < n_dests; ++i) {
        const NavDest& d = dests[i];

        // The exact target point a directions request would aim at: the
        // nearest point of the destination's line to the player, height
        // interpolated along the line.
        const float ex = static_cast<float>(d.line_x2 - d.line_x1);
        const float ey = static_cast<float>(d.line_y2 - d.line_y1);
        const float wx = px - static_cast<float>(d.line_x1);
        const float wy = py - static_cast<float>(d.line_y1);
        const float len2 = ex * ex + ey * ey;
        float t = (len2 > 0.0f) ? ((wx * ex + wy * ey) / len2) : 0.0f;
        if (t < 0.0f) t = 0.0f;
        if (t > 1.0f) t = 1.0f;
        const float tx = d.line_x1 + t * ex;
        const float ty = d.line_y1 + t * ey;
        const float tz = d.line_z1 + t * (d.line_z2 - d.line_z1);

        bool keep = true;
        const int goal = ResolveTriHint(mesh, d.target_tri, tx, ty, tz);
        if (goal >= 0 && comp[goal] != comp[start]) {
            keep = false;
            // Rule 2: reachable with every lock open = a story gate.
            // Component equality on the raw mesh is the same verdict
            // ReachableIgnoringLocks' A* reaches (A* succeeds exactly
            // within a component), computed once instead of per call.
            bool lock_blocked = false;
            if (rstart == -2) {
                rstart = -1;
                if (LoadWalkmesh(raw, /*apply_locks=*/false)) {
                    WalkmeshComponents(raw, rcomp);
                    rstart = ResolveTriHint(raw, player_tri, px, py, pz);
                }
            }
            if (rstart >= 0) {
                const int rgoal = ResolveTriHint(raw, d.target_tri,
                                                 tx, ty, tz);
                lock_blocked = rgoal >= 0 && rcomp[rgoal] == rcomp[rstart];
            }
            if (!lock_blocked) {
                if (jg_ok && jg.seen[comp[goal]]) {
                    keep = true;   // rule 3: a ladder chain gets there
                } else if (d.model_slot >= 0) {
                    // Rule 4: nearest reachable triangle vs interaction
                    // reach â€” the to_nearest walk ends there and the talk
                    // radius must cover what remains.
                    float best = FLT_MAX;
                    for (size_t k = 0; k < mesh.size(); ++k) {
                        if (comp[k] != comp[start])
                            continue;
                        const float dd = TriangleDistance(mesh[k], tx, ty);
                        if (dd < best)
                            best = dd;
                    }
                    keep = best <= ModelTargetReach(arr, d.model_slot);
                }
            }
        }

        if (keep) {
            if (kept != i)
                dests[kept] = dests[i];
            ++kept;
        } else {
            ++out_hidden;
            if (Config::Get().debug_log) {
                char dbg[160];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] NAV filter hides '%ls' goal=%d "
                    "comp=%d/%d",
                    d.name, goal, (goal >= 0) ? comp[goal] : -1,
                    comp[start]);
                Log::Write(dbg);
            }
        }
    }
    n_dests = kept;
}

// ---------------------------------------------------------------------------
// Layer filter (v2.30.88, Shift+;): drop every destination that is not on
// the player's current LEVEL, so J/L on a stacked-walkway field (catwalks
// over a save room, the reactor ladder shafts) cycles only what is actually
// around the player, not things a screen-height above or below them.
//
// "Same layer" is a HEIGHT verdict, deliberately not a walkmesh-component
// one: a story-locked door across a flat floor is a different component but
// the same layer (the PATH filter owns reachability; this filter owns
// geometry -- the two compose orthogonally, and running both means "things
// I can reach on my level"). The gate is |dz| < 150 walkmesh units -- the
// SAME constant the journey last-mile completion and the level-aware
// save-point hints ship with (v2.30.69/.73: catwalk-over-pad measured
// dz~825, same-room targets well under 150), so "on another level" means
// one thing across every feature that says it.
//
// The verdict takes the NEARER endpoint of the destination's line segment:
// ladder LINE zones span levels by construction (their two endpoints ARE
// the bottom and top of the climb), and a ladder whose foot stands on the
// player's level is exactly how the player LEAVES that level -- it must
// stay listed from either end. Point destinations (models, hotspots) carry
// the same z in both endpoints, so the min degenerates to plain |dz|.
//
// Names/ordinals were assigned at build time, BEFORE this pass, so
// filtering never renumbers anything (the identity-stability rule shared
// with the path filter). No fail-open branch is needed: line_z1/z2 are
// filled by every builder from data already read (never a live probe that
// can transiently fail), and the player z comes from the same model_pos
// read the whole browser keyed on this poll.
// ---------------------------------------------------------------------------
// One meaning of "another level" across the mod -- see the comment above.
static constexpr float kLayerGate = 150.0f;

static void FilterSameLayerDests(NavDest* dests, int& n_dests,
                                 float pz, int& out_hidden)
{
    out_hidden = 0;
    int kept = 0;
    for (int i = 0; i < n_dests; ++i) {
        const NavDest& d = dests[i];
        const float dz1 = static_cast<float>(d.line_z1) - pz;
        const float dz2 = static_cast<float>(d.line_z2) - pz;
        const float a1 = dz1 < 0.0f ? -dz1 : dz1;
        const float a2 = dz2 < 0.0f ? -dz2 : dz2;
        const bool keep = (a1 < kLayerGate) || (a2 < kLayerGate);
        if (keep) {
            if (kept != i)
                dests[kept] = dests[i];
            ++kept;
        } else {
            ++out_hidden;
            if (Config::Get().debug_log) {
                char dbg[160];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] NAV layer filter hides '%ls' z=%d/%d pz=%d",
                    d.name, static_cast<int>(d.line_z1),
                    static_cast<int>(d.line_z2), static_cast<int>(pz));
                Log::Write(dbg);
            }
        }
    }
    n_dests = kept;
}

// ---------------------------------------------------------------------------
// Friendly location name (v2.24): the game's own menu caption ("Sector 1
// Station"), read from the MPNAM buffer â€” full derivation and the live
// verification at ff7_addresses.h LOCATION_NAME_BUFFER. Returns false when
// the buffer is empty/blank (before the first MPNAM of a new game) or
// undecodable; callers fall back to the internal field name.
// ---------------------------------------------------------------------------
static bool FriendlyLocationName(std::wstring& out)
{
    const uint8_t* p = reinterpret_cast<const uint8_t*>(
        FF7Addr::LOCATION_NAME_BUFFER);
    if (!IsReadableSpan(p, FF7Addr::LOCATION_NAME_MAX))
        return false;
    out.clear();
    for (uint32_t i = 0; i < FF7Addr::LOCATION_NAME_MAX; ++i) {
        const uint8_t b = p[i];
        if (b == 0xFF)
            break;   // âš  bytes past the terminator hold the PREVIOUS
                     // name's tail (live-observed) â€” never read on
        const wchar_t c = FF7Text::DecodeChar(b);
        if (c != L'\0')
            out += c;
    }
    const std::wstring::size_type first = out.find_first_not_of(L' ');
    if (first == std::wstring::npos) {
        out.clear();
        return false;
    }
    const std::wstring::size_type last = out.find_last_not_of(L' ');
    out = out.substr(first, last - first + 1);
    return true;
}

// ---------------------------------------------------------------------------
// Visited-places cache (v2.25) â€” friendly captions BY FIELD ID, learned
// from the v2.24 MPNAM buffer as the player travels and persisted to
// ffvii_accessibility_places.txt next to the DLL.
//
// WHY: gateways know their destination FIELD ID, and the maplist gives
// every id an internal name ("nmkin_2") -- but the FRIENDLY caption
// ("No.1 Reactor") for another field cannot be read at runtime (each
// field's caption lives in its own script). It CAN be remembered: while
// the player stands on field X, the mod sees both X and X's caption.
// New games start with what previous sessions learned -- the file is the
// player's own map knowledge, growing as they explore.
//
// Since v2.30.86 this cache is no longer the ONLY caption source: the
// offline MPNAM harvest (ff7_field_captions.h) names unvisited fields
// too. The cache keeps two jobs the harvest cannot do: (1) it is the
// EXPLORED-vs-unexplored tracker (", unexplored" hangs off its absence),
// and (2) a learned caption overrides the harvested one, so text mods
// (7th Heaven retranslations) and runtime caption inheritance win over
// the vanilla-flevel harvest once the player actually goes there.
//
// INHERITANCE CAVEAT (documented, accepted): a field whose script sets no
// MPNAM keeps the PREVIOUS field's caption, and the cache records that
// inherited caption for it â€” which is exactly what the sighted menu
// displays while standing there, so parity holds.
//
// THREADING: everything here runs on FieldNavThread only (load at thread
// start, learn in its poll, lookups in its list build) â€” no locks needed.
// ---------------------------------------------------------------------------
static wchar_t g_places[FF7FieldNames::kCount][24];   // zeroed = unknown

static void PlacesFilePath(char* buf, size_t cap)
{
    // Same own-module-directory pattern as Config::Load.
    HMODULE hSelf = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&PlacesFilePath), &hSelf);
    char path[MAX_PATH] = {};
    GetModuleFileNameA(hSelf, path, MAX_PATH);
    char* sep = strrchr(path, '\\');
    if (sep) *(sep + 1) = '\0';
    _snprintf_s(buf, cap, _TRUNCATE, "%sffvii_accessibility_places.txt", path);
}

static void PlacesLoad()
{
    char path[MAX_PATH];
    PlacesFilePath(path, sizeof(path));
    std::ifstream f(path);
    if (!f.is_open())
        return;                       // first run: nothing learned yet
    std::string line;
    while (std::getline(f, line)) {
        const size_t eq = line.find('=');
        if (eq == std::string::npos)
            continue;
        const int id = atoi(line.substr(0, eq).c_str());
        if (id <= 0 || id >= FF7FieldNames::kCount)
            continue;
        const std::string val = line.substr(eq + 1);
        wchar_t wide[24] = {};
        MultiByteToWideChar(CP_UTF8, 0, val.c_str(), -1, wide, _countof(wide));
        wide[_countof(wide) - 1] = L'\0';
        wcscpy_s(g_places[id], wide);
    }
}

static void PlacesSave()
{
    char path[MAX_PATH];
    PlacesFilePath(path, sizeof(path));
    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open())
        return;                       // read-only install dir: cache stays
                                      // session-only, no error surfaced
    f << "# Learned field captions (id=name), written by the FF7 "
         "accessibility mod.\n";
    for (int id = 0; id < FF7FieldNames::kCount; ++id) {
        if (!g_places[id][0])
            continue;
        char utf8[96] = {};
        WideCharToMultiByte(CP_UTF8, 0, g_places[id], -1,
                            utf8, sizeof(utf8), nullptr, nullptr);
        f << id << '=' << utf8 << '\n';
    }
}

// Record field_id -> caption; rewrites the cache file only when something
// actually changed (a new place, or a caption correction).
static void PlacesLearn(int field_id, const std::wstring& caption)
{
    if (field_id <= 0 || field_id >= FF7FieldNames::kCount || caption.empty())
        return;
    if (wcscmp(g_places[field_id], caption.c_str()) == 0)
        return;
    wcsncpy_s(g_places[field_id], caption.c_str(), _TRUNCATE);
    PlacesSave();
    if (Config::Get().debug_log) {
        char dbg[128];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] NAV place learned %d = '%ls'",
            field_id, g_places[field_id]);
        Log::Write(dbg);
    }
}

// Spoken destination name for a gateway's target field id (v2.25,
// reworked v2.30.86):
//   1. the player's own learned caption ("No.1 Reactor") -- the game's
//      exact spelling as seen when the place was visited;
//   2. the offline MPNAM harvest (ff7_field_captions.h) -- the SAME
//      friendly name for places not yet visited. Until v2.30.86 this
//      layer did not exist and unvisited places fell through to the
//      internal map code ("nmkin 2"); testers read that as deliberate
//      name-obscuring and found it a nuisance, so the real name now
//      speaks everywhere (user decision 2026-08-04);
//   3. the maplist internal name ("nmkin 2"; underscores spoken as
//      spaces) -- only ~176 caption-less fields (their scripts set no
//      MPNAM) can still land here;
//   4. false -> caller keeps the positional "Exit N" label.
//
// explored_out (optional): false when the place is known only from the
// harvest/maplist, i.e. the player has never stood there -- callers
// append ", unexplored" so the name change stays informative without
// hiding anything. The visited-places cache remains the tracker (a
// field is "explored" once its caption was learned by standing on it).
// World-map exits count as explored: there is no per-field visit to
// track behind a "World map" label.
static bool DestinationName(int dest_id, std::wstring& out,
                            bool* explored_out = nullptr)
{
    if (explored_out)
        *explored_out = true;
    if (dest_id > 0 && dest_id < FF7FieldNames::kCount &&
        g_places[dest_id][0]) {
        out = g_places[dest_id];
        return true;
    }
    const char* nm = FF7FieldNames::Get(dest_id);
    if (nm && nm[0] == 'w' && nm[1] == 'm') {
        out = L"World map";
        return true;
    }
    if (const wchar_t* cap = FF7FieldCaptions::Get(dest_id)) {
        out = cap;
        if (explored_out)
            *explored_out = false;
        return true;
    }
    if (!nm)
        return false;
    out.clear();
    for (const char* p = nm; *p; ++p)
        out += (*p == '_') ? L' ' : static_cast<wchar_t>(*p);
    if (out.empty())
        return false;
    if (explored_out)
        *explored_out = false;
    return true;
}

// ---------------------------------------------------------------------------
// CROSS-FIELD JOURNEY GRAPH (v2.30.65) â€” "guide me back to Sector 7 slums".
//
// Nodes are maplist field ids; directed edges are the ways OUT of a field:
//   - gateway edges from the offline catalog (ff7_field_graph.h -- 1036
//     walk-across exit lines game-wide, {src, dst, slot});
//   - script-exit edges from the line catalog (ff7_line_trigger_catalog.h
//     kinds EXIT/EXIT_OK with a known unconditional MAPJUMP destination).
// Both kinds carry only their runtime IDENTITY (gateway slot / owning
// entity id) -- geometry is always re-read live at guidance time from the
// same engine structures the Exits/Triggers categories use, so guidance
// can never disagree with what the engine actually walks on. The reactor
// play-test lesson (2026-08-02) is baked in: story doors can jump by
// scripted MAPJUMP rather than their gateway record, so BOTH edge kinds
// coexist and leg building tries every edge toward the next field until
// one resolves live.
//
// World-map nodes are excluded (journeys are field-only; crossing the
// world map is its own future campaign). Story locks are the accepted v1
// honesty gap: the graph knows geometry, not progression flags -- a
// story-locked door routes normally and the door simply won't fire; the
// journey then keeps naming that exit rather than inventing a detour.
//
// THREADING: FieldNavThread only, like the places cache above.
// ---------------------------------------------------------------------------
// v2.30.46 STORY HOTSPOTS, hoisted to file scope in v2.30.66: interaction
// spots the engine exposes NOTHING for (no LINE, no prop model -- the whole
// interaction is an NPC's script reacting to the player). Curated from
// played evidence ONLY. Consumed by (a) the browser's hotspot destinations
// (original v2.30.46 use) and (b) journey legs: when a leg rides a
// CONDITIONAL exit on a hotspot field, the actuator -- not the exit line --
// is what the player must reach ("elevator switch, press OK"). The run-1
// play report proved the cost of not doing this: 2m40s stood in the
// elevator car waiting for a line that only fires after the switch.
struct StoryHotspot {
    uint16_t field_id;
    int16_t  x, y, z;
    const wchar_t* name;
};
static const StoryHotspot kStoryHotspots[] = {
    // elevtr1 (121): the No.1 reactor elevator switch. PLAY-CORRECTED
    // 2026-08-02 (third run): the original point (-140,40) sat by
    // Jessie's scripted spot and spoke "up 1 second" from the car door;
    // the player reports the BUTTON is on the FAR RIGHT wall and "right
    // 1 second" is what works. Arrival is at (-112,-8), ctrl=128 makes
    // screen-right = +X, so the curated point moves to the right wall.
    // If OK there ever fails to fire, the next report refines it again
    // -- this entry is played evidence, not a derivation.
    { 121, 60, 0, 5, L"elevator switch, press OK" },
};

struct FieldGraphEdge {
    uint16_t dst;    // destination field id
    uint8_t  kind;   // 0 = gateway, 1 = line EXIT, 2 = line EXIT_OK,
                     // 3/4 = same but CONDITIONAL (from kCondExits -- the
                     // destination depends on game state, so the exit is
                     // usually actuated by something else: a switch, a
                     // story beat; v2.30.66 pairs these with hotspots)
    uint8_t  key;    // gateway slot (kind 0) or owning entity id (1-4)
};

// Adjacency lists, built once on first use (~1,500 edges total; index =
// source field id). static-local so construction is on-demand and
// thread-confined.
static const std::vector<std::vector<FieldGraphEdge>>& FieldGraphAdjacency()
{
    static std::vector<std::vector<FieldGraphEdge>> adj;
    static bool built = false;
    if (built)
        return adj;
    built = true;
    adj.resize(FF7FieldNames::kCount);
    const auto is_wm = [](int id) {
        const char* nm = FF7FieldNames::Get(id);
        return nm && nm[0] == 'w' && nm[1] == 'm';
    };
    for (size_t i = 0; i < FF7FieldGraph::kGatewayEdgeCount; ++i) {
        const FF7FieldGraph::GatewayEdge& e = FF7FieldGraph::kGatewayEdges[i];
        if (e.src >= FF7FieldNames::kCount || e.dst >= FF7FieldNames::kCount)
            continue;
        if (is_wm(e.src) || is_wm(e.dst))
            continue;
        adj[e.src].push_back({e.dst, 0, e.slot});
    }
    const auto add_line_edge = [&](const FF7LineCatalog::LineInfo& l,
                                   bool conditional) {
        if (l.kind != FF7LineCatalog::LK_EXIT &&
            l.kind != FF7LineCatalog::LK_EXIT_OK)
            return;
        if (l.dest_field <= 0 || l.dest_field >= FF7FieldNames::kCount)
            return;
        if (l.field_id >= FF7FieldNames::kCount ||
            is_wm(l.field_id) || is_wm(l.dest_field))
            return;
        if (l.field_id == l.dest_field)
            return;
        uint8_t kind =
            static_cast<uint8_t>(l.kind == FF7LineCatalog::LK_EXIT ? 1 : 2);
        if (conditional)
            kind += 2;   // 3/4: same lookup, but actuated elsewhere
        adj[l.field_id].push_back({
            static_cast<uint16_t>(l.dest_field), kind, l.entity_id});
    };
    // Unconditional script exits (kLines rows with a real dest)...
    for (const FF7LineCatalog::LineInfo& l : FF7LineCatalog::kLines)
        add_line_edge(l, /*conditional=*/false);
    // ...plus every CANDIDATE of the conditional multi-destination exits
    // (kCondExits -- elevators, story doors). Without these the reactor's
    // halves are disconnected at elevtr1 (the 2026-08-02 dry-run finding);
    // with them, "take the lift" is a routable edge to each floor and the
    // arrival recompute self-heals if the lift went to the other one.
    for (size_t i = 0; i < FF7LineCatalog::kCondExitCount; ++i)
        add_line_edge(FF7LineCatalog::kCondExits[i], /*conditional=*/true);
    return adj;
}

// Breadth-first search from `from` over the whole graph (788 nodes --
// microseconds). dist[id] = screens between, -1 unreachable; prev[id] =
// predecessor field on a shortest path. Hop counts, not walking distance:
// a screen transition is the player-meaningful unit ("3 screens away"),
// and per-screen walk lengths are unknowable without loading every mesh.
static void FieldGraphBFS(int from, std::vector<int16_t>& dist,
                          std::vector<int16_t>& prev)
{
    const auto& adj = FieldGraphAdjacency();
    dist.assign(FF7FieldNames::kCount, -1);
    prev.assign(FF7FieldNames::kCount, -1);
    if (from <= 0 || from >= FF7FieldNames::kCount)
        return;
    std::vector<int16_t> queue;
    queue.reserve(64);
    queue.push_back(static_cast<int16_t>(from));
    dist[from] = 0;
    for (size_t head = 0; head < queue.size(); ++head) {
        const int cur = queue[head];
        for (const FieldGraphEdge& e : adj[cur]) {
            if (dist[e.dst] >= 0)
                continue;
            dist[e.dst] = static_cast<int16_t>(dist[cur] + 1);
            prev[e.dst] = static_cast<int16_t>(cur);
            queue.push_back(static_cast<int16_t>(e.dst));
        }
    }
}

// First field to head for on the shortest path from -> target, or -1.
static int FieldGraphNextHop(int from, int target,
                             const std::vector<int16_t>& prev,
                             const std::vector<int16_t>& dist)
{
    if (target <= 0 || target >= FF7FieldNames::kCount || dist[target] < 0)
        return -1;
    int n = target;
    while (prev[n] != from) {
        n = prev[n];
        if (n < 0)
            return -1;   // chain broken (cannot happen after a clean BFS,
                         // but never loop on corrupt state)
    }
    return n;
}

// Resolve the concrete thing to WALK TO for the current leg: the live
// gateway line or script LINE zone leading from field_id to next_field.
// Tries every graph edge toward next_field until one resolves against the
// live engine structures -- a script line not yet created (or disabled by
// LINON) falls through to a gateway alternative and vice versa. Returns
// false when nothing resolves (e.g. a story-gated line that does not
// exist yet AND no gateway covers that doorway).
static bool BuildJourneyLegDest(int field_id, int next_field, uint32_t hdr,
                                NavDest& out)
{
    const auto& adj = FieldGraphAdjacency();
    if (field_id <= 0 || field_id >= FF7FieldNames::kCount)
        return false;

    std::wstring dn;
    bool explored = true;
    if (!DestinationName(next_field, dn, &explored))
        dn = L"next screen";
    else if (!explored)
        dn += L", unexplored";   // v2.30.86: journeys can route THROUGH
                                 // never-visited screens now that unvisited
                                 // names speak -- same suffix vocabulary as
                                 // the Exits browser (one voice)

    for (const FieldGraphEdge& e : adj[field_id]) {
        if (e.dst != next_field)
            continue;
        if (e.kind == 0) {
            // Gateway: re-read the live record (same eligibility as the
            // Exits category -- real dest + non-degenerate line). The live
            // dest is also cross-checked against the catalog edge so a
            // modded flevel can at worst suppress a leg, never misroute it.
            const uint8_t* gw = reinterpret_cast<const uint8_t*>(
                hdr + FF7Addr::FTRIG_OFF_GATEWAYS +
                e.key * FF7Addr::FTRIG_GATEWAY_SIZE);
            const int16_t* v = reinterpret_cast<const int16_t*>(gw);
            const int16_t dest_id =
                *reinterpret_cast<const int16_t*>(gw + 0x12);
            if (dest_id != next_field)
                continue;
            if (v[0] == 0 && v[1] == 0 && v[3] == 0 && v[4] == 0)
                continue;
            _snwprintf_s(out.name, _countof(out.name), _TRUNCATE,
                         L"To %ls", dn.c_str());
            out.line_x1 = v[0]; out.line_y1 = v[1]; out.line_z1 = v[2];
            out.line_x2 = v[3]; out.line_y2 = v[4]; out.line_z2 = v[5];
            out.model_slot = -1;
            out.target_tri = -1;
            out.place_field = static_cast<int16_t>(next_field);
            return true;
        }
        // CONDITIONAL exits on a hotspot field (v2.30.66): the exit line
        // only fires after its actuator runs -- guide to the ACTUATOR.
        // The run-1 elevator report is the defining case: the journey
        // pointed at the lift's exit line and the player stood 2m40s
        // waiting; the thing to reach was the switch. Curated hotspots
        // only (played-evidence rule) -- conditional legs on fields
        // without one keep the line target below.
        if (e.kind >= 3) {
            for (const StoryHotspot& h : kStoryHotspots) {
                if (h.field_id != static_cast<uint16_t>(field_id))
                    continue;
                _snwprintf_s(out.name, _countof(out.name), _TRUNCATE,
                             L"%ls, toward %ls", h.name, dn.c_str());
                out.line_x1 = out.line_x2 = h.x;
                out.line_y1 = out.line_y2 = h.y;
                out.line_z1 = out.line_z2 = h.z;
                out.model_slot = -1;
                out.target_tri = -1;
                out.place_field = static_cast<int16_t>(next_field);
                return true;
            }
        }
        // Script line: find the ENABLED live line owned by that entity
        // (same identity the Triggers category uses; SLINE moves and
        // LINON disables are honored by construction because the live
        // array is the source).
        const uint16_t n_lines = *reinterpret_cast<const volatile uint16_t*>(
            FF7Addr::FIELD_LINE_COUNT);
        for (uint32_t i = 0; i < n_lines && i < FF7Addr::FLINE_MAX; ++i) {
            const uint8_t* le = reinterpret_cast<const uint8_t*>(
                FF7Addr::FIELD_LINE_ARRAY + i * FF7Addr::FLINE_STRIDE);
            if (le[FF7Addr::FLINE_OFF_ENABLED] == 0)
                continue;
            if (le[FF7Addr::FLINE_OFF_ENTITY] != e.key)
                continue;
            const int16_t* v = reinterpret_cast<const int16_t*>(le);
            _snwprintf_s(out.name, _countof(out.name), _TRUNCATE,
                         (e.kind == 2 || e.kind == 4)
                             ? L"To %ls, press OK" : L"To %ls",
                         dn.c_str());
            out.line_x1 = v[0]; out.line_y1 = v[1]; out.line_z1 = v[2];
            out.line_x2 = v[3]; out.line_y2 = v[4]; out.line_z2 = v[5];
            out.model_slot = -1;
            out.target_tri = -1;
            out.place_field = static_cast<int16_t>(next_field);
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Full route text for an AUTOMATIC journey announcement (v2.30.74).
//
// WHY: v2.30.65 deliberately spoke only a straight-line hint at each leg
// arrival ("a multi-sentence route every screen would drown the
// transition") with the real route on \. Play disproved the tradeoff --
// the player reported ALWAYS having to press \ after every transition
// because the straight line is not walkable often enough. Automatic
// announcements now speak the same turn-by-turn (or level-journey) text
// the \ key produces; straight-line remains the FALLBACK when routing is
// unavailable, exactly like the keypress path. The body caution stays a
// \-only feature: NPC positions move, so a caution is only honest at the
// moment the player asks.
//
// Returns the full "Next" clause INCLUDING the destination name ("To
// Mako Reactor 1: up 4 seconds, then left 2 seconds." / "Save point: on
// another level. First take ladder 1, ..."). false = caller keeps its
// straight-line wording.
// ---------------------------------------------------------------------------
static bool JourneyAutoRoute(const NavDest& d, float fpx, float fpy,
                             float fpz, int16_t player_tri,
                             float control_deg, float target_reach,
                             std::wstring& out)
{
    if (!Config::Get().turn_by_turn)
        return false;
    // Nearest point on the target segment -- the same aim point the
    // keypress path computes (degenerate lines collapse to the point).
    const float ex = static_cast<float>(d.line_x2 - d.line_x1);
    const float ey = static_cast<float>(d.line_y2 - d.line_y1);
    const float wx = fpx - static_cast<float>(d.line_x1);
    const float wy = fpy - static_cast<float>(d.line_y1);
    const float l2 = ex * ex + ey * ey;
    float t = (l2 > 0.0f) ? ((wx * ex + wy * ey) / l2) : 0.0f;
    if (t < 0.0f) t = 0.0f;
    if (t > 1.0f) t = 1.0f;
    const float ftx = d.line_x1 + t * ex;
    const float fty = d.line_y1 + t * ey;
    const float ftz = d.line_z1 + t * (d.line_z2 - d.line_z1);
    std::wstring route;
    const RouteOutcome ro = BuildTurnByTurnRoute(
        fpx, fpy, fpz, player_tri, ftx, fty, ftz, d.target_tri,
        control_deg, d.model_slot, target_reach, route);
    if (ro == RouteOutcome::SPOKEN_ROUTE) {
        out = d.name;
        out += L": ";
        out += route;
        out += L'.';
        return true;
    }
    if (ro == RouteOutcome::NO_PATH) {
        // Another level -- the connector-chain planner speaks the
        // ladders ("on another level. First take ladder 1, ...").
        std::wstring jmsg;
        if (BuildJourneySpeech(fpx, fpy, fpz, player_tri, ftx, fty, ftz,
                               d.target_tri, control_deg, d.name, jmsg)) {
            out = jmsg;
            return true;
        }
    }
    return false;
}

static DWORD WINAPI FieldNavThread(LPVOID /*unused*/)
{
    // The FF4-scheme hotkeys we poll, with per-key previous-state for edge
    // detection. OEM VKs are the US-layout punctuation keys.
    static const int kVKs[] = {
        'J', 'L', 'K', 'P', 'M',
        VK_OEM_4,     // [
        VK_OEM_6,     // ]
        VK_OEM_5,     // backslash
        VK_OEM_MINUS, // -
        VK_OEM_PLUS,  // =
        VK_OEM_1,     // ; (v2.30.88 layer filter -- SHIFTED only; plain ;
                      //    is decoded to no action, so a ; the player's
                      //    ff7input.cfg might bind stays the game's alone)
    };
    enum { KJ, KL, KK, KP, KM, KLBRACKET, KRBRACKET, KBACKSLASH, KMINUS, KPLUS,
           KSEMICOLON, KEY_COUNT };
    bool was_down[KEY_COUNT] = {};

    // Browser state. Selection and category persist while the player stays
    // on one field (opening the menu or fighting a battle does NOT reset
    // them); a field change resets both.
    static const wchar_t* const kCategoryNames[] = {
        L"All", L"Exits", L"People", L"Save points", L"Triggers", L"Items",
        L"Places"
    };
    constexpr int kCategoryCount = 7;

    // Cross-field journey state (v2.30.65). A journey is started by
    // pressing directions (\ or P) on a Places selection and lives until
    // arrival, an unreachable recompute, or Shift+K. The target NAME is
    // copied (not looked up per use) so the announcement stays stable
    // even if the caption cache learns a different spelling mid-journey.
    bool    journey_active = false;
    int16_t journey_target = 0;
    wchar_t journey_name[24] = {};
    // v2.30.69 last-mile handoff: journeys are field-granular, but a
    // ", save point" Places target is a POINT INSIDE the field -- the
    // third-run log proved arrival is not enough (reactor save room 124:
    // the gateway drops the player on the catwalk at z~640, the pad sits
    // down a ladder at z~-185, and "Journey complete" fired a level
    // above it). While journey_save_slot >= 0 the journey stays alive
    // after reaching the target field: \ routes to the live save icon
    // through the ordinary turn-by-turn machinery, and completion fires
    // only inside the pad's reach bubble on its level. -1 = no last
    // mile (plain caption journeys keep field-arrival completion). The
    // slot is re-found on every arrival at the target field and cleared
    // on every screen change, so it can never go stale across fields.
    int   journey_save_slot  = -1;
    float journey_save_reach = 0.0f;
    // v2.30.73 (review): the save-icon scan is no longer a one-shot on
    // the arrival edge -- on the first poll after a transition the field
    // can still be settling (VISI byte not yet written by the init
    // script, label buffer mid-load), and a single miss used to fall
    // straight back to the field-door completion this feature exists to
    // prevent. The arrival edge only ARMS this retry window; the
    // per-poll last-mile block scans while it is > 0 and falls back to
    // the old completion only when it empties (~3 s of polls). Also
    // re-armed when a latched slot goes bad (unreadable/hidden/out of
    // range) so a transient never strands or falsely completes a journey.
    int   journey_lastmile_tries = 0;
    int16_t nav_field_id = 0;
    int     category     = 0;
    int     selection    = 0;
    // Path filter (v2.30.87, Shift+\ or Shift+P): when on, the list only
    // shows destinations with a valid path (see FilterReachableDests for
    // the exact rules). Session-persistent and NOT reset by field changes
    // â€” it is a browsing MODE like turn_by_turn, not a selection; a
    // player who filters wants it to stay filtered on the next screen.
    // Deliberately not a cfg key: a per-session toggle with a dedicated
    // hotkey needs no embed dance, and defaulting OFF each launch means
    // a tester can never be confused by a filter they forgot they set
    // last week.
    bool    path_filter  = false;
    // Layer filter (v2.30.88, Shift+;): when on, the list only shows
    // destinations on the player's current level (see FilterSameLayerDests
    // for the height rule). Same session-mode contract as path_filter and
    // for the same reasons: survives field changes, defaults off each
    // launch, deliberately not a cfg key. The two filters compose -- both
    // on means "reachable AND on my level".
    bool    layer_filter = false;
    // v2.30.60 ladder state: was the player climbing last poll, and which
    // d-pad sector was announced (so a target flip re-announces but a
    // steady climb stays quiet).
    bool    ladder_was_on  = false;
    int     ladder_last_dir = -1;

    // Screen-change announcement tracker (v2.23) â€” separate from
    // nav_field_id, which only updates on the KEYPRESS path; this one runs
    // every poll so the announcement fires the moment control returns on
    // the new screen. 0 = nothing announced yet this session.
    int16_t announced_field_id = 0;
    // v2.30.68: when the arrival announce fires during a scripted entry
    // (UC lock held -- the new-game train scene is the reported case:
    // "facing down" spoken mid-cutscene, wrong by the time control
    // returns), the facing clause is DEFERRED: this flag speaks a fresh
    // "Facing X." the moment the lock releases, reading the byte at that
    // instant so scripted turns are already reflected.
    bool facing_pending = false;

    // Transition tracker (v2.30.64) â€” watches the engine's field-jump
    // mailbox (FIELD_JUMP_* in ff7_addresses.h). jump_armed_logged is the
    // once-per-jump edge for the JUMP debug line (GAME_MODE holds 1 for
    // the whole load, far longer than one 50ms poll, so the arm is
    // reliably observed; it re-arms when GAME_MODE returns to field play).
    // arrived_via_jump tells the arrival announce whether this screen was
    // entered through a tracked jump (gateway/MAPJUMP/save-load/world) or
    // seen "cold" (mod attached mid-field) â€” context for the ARRIVE
    // facing-confirmation debug line.
    bool    jump_armed_logged = false;
    int16_t jump_dest_field   = 0;
    bool    arrived_via_jump  = false;

    // Visited-places cache (v2.25): previous sessions' learned captions.
    // Loaded here because this thread is the cache's only reader/writer.
    PlacesLoad();

    // Once-per-second rate limiter for the direction-calibration debug line.
    ULONGLONG next_calib_tick = 0;
    int32_t   calib_last_x = 0, calib_last_y = 0;
    bool      calib_have_last = false;

    // Per-model movement tracker (v2.15.1): last sampled position and the
    // tick it last CHANGED, updated every 50ms poll while on a field. A
    // person who moved within the last WANDER_WINDOW_MS gets a short high
    // beep appended to their announcements â€” the cue that this target is
    // WANDERING and directions may go stale (user request 2026-07-13).
    // 880Hz keeps it clearly distinct from the 220Hz wall-bump tone.
    int32_t   track_x[32] = {}, track_y[32] = {};
    ULONGLONG track_move_tick[32] = {};
    bool      track_valid[32] = {};
    int16_t   track_field = 0;
    constexpr ULONGLONG WANDER_WINDOW_MS = 1000;
    constexpr WORD      WANDER_BEEP_HZ = 880, WANDER_BEEP_MS = 70;

    // Interactable-proximity tone state (v2.27, user request after the
    // Jessie incident): one chirp on ENTERING an object's interaction
    // range, re-armed only after leaving it (plus slack, so boundary
    // jitter can't stutter). armed=true means "will chirp on next entry".
    bool      prox_armed_m[32];   // models (people/chests/items/saves)
    bool      prox_armed_l[32];   // LINE trigger zones
    memset(prox_armed_m, 1, sizeof(prox_armed_m));
    memset(prox_armed_l, 1, sizeof(prox_armed_l));
    int16_t   prox_field = 0;
    ULONGLONG last_prox_beep = 0;
    constexpr WORD      PROX_BEEP_HZ = 1175, PROX_BEEP_MS = 60;
    constexpr float     PROX_LINE_RANGE = 35.0f;  // walk-onto distance
    constexpr float     PROX_REARM_SLACK = 25.0f; // leave range + this
    constexpr int32_t   PROX_Z_GATE = 150;        // not on another layer
    constexpr ULONGLONG PROX_MIN_GAP_MS = 250;    // crowd = spaced pings

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().pathfinder_keys) {
            memset(was_down, 0, sizeof(was_down));
            GamepadNav::Reset();
            continue;
        }

        // Normal field control only (same gate set as the wall-bump tone,
        // minus the dialog-activity window â€” a scan DURING dialog is
        // harmless, the announce just queues after the dialog speech).
        const int16_t field_id = *reinterpret_cast<const volatile int16_t*>(
            FF7Addr::FIELD_ID);
        const uint8_t game_mode = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::GAME_MODE);
        const uint8_t menu_open = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::MENU_OPEN);
        // ---- transition watcher (v2.30.64) ----------------------------
        // MUST run BEFORE the field gates below: a pending field jump
        // holds GAME_MODE at 1 (GAME_MODE_FIELD_JUMP), which the gate
        // discards â€” the v2.30.59 lesson (check a new branch's ORDER
        // against existing early-continues) applied preemptively. Log-only
        // this version: one line per armed jump with the full mailbox
        // snapshot, so the first play-test log verifies every entry path
        // (gateway walk, MAPJUMP, save load) hits the interface as the
        // static proof says. Announcing happens at ARRIVAL (below), where
        // the facing byte is readable and speech won't fight the load.
        if (game_mode == FF7Addr::GAME_MODE_FIELD_JUMP) {
            const int16_t dest = *reinterpret_cast<const volatile int16_t*>(
                FF7Addr::FIELD_JUMP_DEST_FIELD);
            if (!jump_armed_logged || dest != jump_dest_field) {
                jump_armed_logged = true;
                jump_dest_field   = dest;
                arrived_via_jump  = true;
                if (Config::Get().debug_log) {
                    char dbg[192];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] JUMP armed dest=%d x=%d y=%d tri=%d "
                        "dir=%u phase=%u mpjpo=%u from=%d",
                        dest,
                        *reinterpret_cast<const volatile int16_t*>(
                            FF7Addr::FIELD_JUMP_DEST_X),
                        *reinterpret_cast<const volatile int16_t*>(
                            FF7Addr::FIELD_JUMP_DEST_Y),
                        *reinterpret_cast<const volatile int16_t*>(
                            FF7Addr::FIELD_JUMP_DEST_TRI),
                        *reinterpret_cast<const volatile uint8_t*>(
                            FF7Addr::FIELD_JUMP_DEST_DIR),
                        *reinterpret_cast<const volatile uint16_t*>(
                            FF7Addr::FIELD_JUMP_PHASE),
                        *reinterpret_cast<const volatile uint8_t*>(
                            FF7Addr::FIELD_MAPJUMP_DISABLED),
                        static_cast<int>(field_id));
                    Log::Write(dbg);
                }
            }
        } else if (game_mode == FF7Addr::GAME_MODE_FIELD) {
            jump_armed_logged = false;   // edge re-arms for the next jump
        }

        // v2.30.37: GameOverTitleContext â€” the GAME OVER film reel passes
        // every byte gate above (frozen field, stale FIELD_ID): without the
        // latch, J/L/K would still browse and route the DEAD field's
        // destinations over the game-over screen.
        if (field_id == 0 || game_mode != FF7Addr::GAME_MODE_FIELD ||
            menu_open != 0 || GameOverTitleContext()) {
            memset(was_down, 0, sizeof(was_down));
            GamepadNav::Reset();
            calib_have_last = false;
            continue;
        }

        // Locate the player's walkmesh position (shared v2.6 pattern).
        const uint32_t arr = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::FIELD_EVENT_DATA_PTR);
        const uint16_t pmid = *reinterpret_cast<const volatile uint16_t*>(
            FF7Addr::FIELD_PLAYER_MODEL_ID);
        const uint16_t nmod = *reinterpret_cast<const volatile uint16_t*>(
            FF7Addr::FIELD_N_MODELS);
        if (arr < 0x401000 || pmid >= nmod || pmid > 0x20)
            continue;
        const uint8_t* elem = reinterpret_cast<const uint8_t*>(
            arr + pmid * FF7Addr::FIELD_EVENT_DATA_STRIDE);
        if (!IsReadableSpan(elem, FF7Addr::FIELD_EVENT_DATA_STRIDE))
            continue;
        const int32_t* pos = reinterpret_cast<const int32_t*>(
            elem + FF7Addr::FIELD_EVENT_MODEL_POS);
        const int32_t px = pos[0] >> 12;   // walkmesh coords
        const int32_t py = pos[1] >> 12;
        const int32_t pz = pos[2] >> 12;   // height (v2.23 layer locates)
        // Player's live walkmesh triangle (v2.22): the turn-by-turn route's
        // start node â€” exact even on stacked layers. <0 (briefly off-mesh,
        // e.g. a scripted jump) makes the route builder point-locate instead.
        const int16_t player_tri = *reinterpret_cast<const int16_t*>(
            elem + FF7Addr::FIELD_EVENT_TRIANGLE_ID);

        // Triggers header for this field. Span covers everything the
        // build reads: name, control_direction, and all 12 gateways.
        const uint32_t hdr = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::FIELD_TRIGGERS_HEADER_PTR);
        if (hdr < 0x401000)
            continue;
        if (!IsReadableSpan(reinterpret_cast<const void*>(hdr),
                            FF7Addr::FTRIG_OFF_GATEWAYS +
                            FF7Addr::FTRIG_GATEWAY_COUNT *
                            FF7Addr::FTRIG_GATEWAY_SIZE))
            continue;
        const uint8_t control_dir = *reinterpret_cast<const uint8_t*>(
            hdr + FF7Addr::FTRIG_OFF_CONTROL_DIR);
        const float control_deg = control_dir * (360.0f / 256.0f);

        // ---- LADDER state + push direction (v2.30.60) ---------------------
        // Tester report: "difficulty knowing when they are on or off a
        // ladder and what direction to push." Both halves are answerable
        // from the LADER handler's own state (provenance: the
        // FIELD_EVENT_MOVE_* block in ff7_addresses.h):
        //   ON/OFF  — movement type 4 or 5 means climbing, written ONLY by
        //             LADER (the two other writers of that byte both write
        //             0), so this needs no heuristic and cannot false-fire
        //             on ordinary walking.
        //   WHICH WAY — the climb target (+0x7C/+0x80, <<12 like model_pos)
        //             is where the ladder takes you; the bearing from the
        //             player to it, rotated by control_direction, is the
        //             d-pad direction to hold. Same math and the same
        //             8-way sector names as every other spoken direction,
        //             so "up and left" means the same thing here as in a
        //             pathfinder route.
        // Announced on the mount edge and again if the target flips
        // (top-of-ladder turnarounds); "Off ladder" on dismount. Speech is
        // gated by pathfinder_keys — the same switch that owns the rest of
        // this thread's field narration.
        {
            const uint8_t mtype = *reinterpret_cast<const volatile uint8_t*>(
                elem + FF7Addr::FIELD_EVENT_MOVE_TYPE);
            const bool climbing =
                (mtype == FF7Addr::MOVE_TYPE_LADDER_A ||
                 mtype == FF7Addr::MOVE_TYPE_LADDER_B);
            int dir_sector = -1;
            if (climbing) {
                const int32_t* tgt = reinterpret_cast<const int32_t*>(
                    elem + FF7Addr::FIELD_EVENT_MOVE_TARGET);
                const float dx = static_cast<float>((tgt[0] >> 12) - px);
                const float dy = static_cast<float>((tgt[1] >> 12) - py);
                if (fabsf(dx) > 0.5f || fabsf(dy) > 0.5f) {
                    // v2.30.68 (third-run report): HEIGHT decides, screen
                    // bearing is only the tiebreak. The v2.30.66 vertical-
                    // component rule failed on nmkin_3's near-flat pipe
                    // ladder (line z 864 -> 849): the descent runs +Y =
                    // screen-UP there, so the mod said "push up" while the
                    // game wanted down. The game's own semantic is height
                    // -- its ladder tutorial says "move Up or Down", and
                    // climbing DOWN always means descending -- so: climb
                    // target LOWER than the player = push down, HIGHER =
                    // push up; only a genuinely level target (|dz| < 3,
                    // rare rope/beam crossings) falls back to the screen
                    // bearing's vertical sign.
                    const int32_t dz = (tgt[2] >> 12) - pz;
                    if (dz >= 3 || dz <= -3) {
                        dir_sector = (dz > 0) ? 0 : 4;        // up : down
                    } else {
                        const float world_deg =
                            atan2f(dx, dy) * (180.0f / 3.14159265f);
                        const float in_rad =
                            (world_deg + control_deg - 180.0f)
                            * (3.14159265f / 180.0f);
                        dir_sector = (cosf(in_rad) >= 0.0f) ? 0 : 4;
                    }
                }
            }
            if (climbing != ladder_was_on ||
                (climbing && dir_sector >= 0 && dir_sector != ladder_last_dir)) {
                if (Config::Get().debug_log) {
                    // dz in the line since v2.30.68 -- it is now the
                    // primary push-direction signal, so every future
                    // wrong-push report carries its own diagnosis.
                    const int32_t* ltgt = reinterpret_cast<const int32_t*>(
                        elem + FF7Addr::FIELD_EVENT_MOVE_TARGET);
                    char dbg[128];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] LADDER %s mtype=%u dir=%d phase=%u dz=%d",
                        climbing ? "on" : "off", mtype, dir_sector,
                        *reinterpret_cast<const volatile uint16_t*>(
                            elem + FF7Addr::FIELD_EVENT_MOVE_PHASE),
                        climbing ? static_cast<int>((ltgt[2] >> 12) - pz) : 0);
                    Log::Write(dbg);
                }
                if (Config::Get().pathfinder_keys) {
                    if (climbing) {
                        std::wstring m = L"On ladder";
                        if (dir_sector >= 0) {
                            m += L", push ";
                            m += kDpadSectors[dir_sector];
                        }
                        TTS::Speak(m.c_str(), /*interrupt=*/true);
                    } else if (ladder_was_on) {
                        TTS::Speak(L"Off ladder", /*interrupt=*/true);
                    }
                }
                ladder_was_on  = climbing;
                ladder_last_dir = climbing ? dir_sector : -1;
            }
        }

        // ---- screen-change announcement (v2.23) ---------------------------
        // Fires the first poll after control returns on a NEW screen. Each
        // screen has its own fixed camera, so an exit crossing REBASES what
        // "up" means (control_direction changed) â€” the user experienced
        // this as directions "shifting as if the perspective changed" and
        // found it disorienting. Sighted players get the camera cut as
        // their cue; this is the audio equivalent. interrupt=false: a
        // transition often follows dialog or an announcement â€” queue behind
        // it, never clobber. Also announces the first screen after launch/
        // load (announced_field_id starts 0), which doubles as a "you're on
        // the field now" orientation cue.
        if (field_id != announced_field_id) {
            announced_field_id = field_id;
            facing_pending = false;   // a new arrival supersedes any
                                      // deferred facing from the last one
            journey_save_slot = -1;   // model slots are per-field; the
                                      // last-mile block below re-finds the
                                      // save icon if THIS is the target
            journey_lastmile_tries = 0;   // ...and the retry window is
                                          // re-armed by the target branch

            // ---- arrival facing (v2.30.64) ----------------------------
            // The arrival routine wrote the jump mailbox's direction into
            // the player's facing byte (+0x38) at 0x63C094; we read the
            // byte itself (not the mailbox) so the announcement is honest
            // even when an entry cutscene has already turned the player.
            // Wheel-to-screen composition is the motion formula (screen =
            // world + control âˆ’ 180) and is PROVISIONAL for facing until
            // one log confirms it â€” hence the ARRIVE line below, which
            // prints every input of the computation (the v2.14
            // direction-calibration playbook applied to facing).
            const uint8_t facing_byte = elem[FF7Addr::FIELD_EVENT_FACING];
            const float   facing_world = facing_byte * (360.0f / 256.0f);
            const int     facing_sector =
                DpadSectorIndex(facing_world + control_deg - 180.0f);

            // Live-confirm line, independent of the announce setting: one
            // line per arrival ties +0x38 to the mailbox direction. match=1
            // is the +0x38 static proof confirmed live; match=0 with
            // via=jump usually means an entry script turned the player
            // (log the walkabout: does the spoken sector fit the room?).
            if (Config::Get().debug_log) {
                const uint8_t dest_dir =
                    *reinterpret_cast<const volatile uint8_t*>(
                        FF7Addr::FIELD_JUMP_DEST_DIR);
                char dbg[192];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] ARRIVE field=%d via=%s facing38=%u "
                    "destdir=%u match=%d ctrl=%.0f sector=%d destfld=%d "
                    "mpjpo=%u ppv=%d",
                    static_cast<int>(field_id),
                    arrived_via_jump ? "jump" : "direct",
                    facing_byte, dest_dir,
                    facing_byte == dest_dir ? 1 : 0,
                    control_deg, facing_sector,
                    static_cast<int>(
                        *reinterpret_cast<const volatile int16_t*>(
                            FF7Addr::FIELD_JUMP_DEST_FIELD)),
                    *reinterpret_cast<const volatile uint8_t*>(
                        FF7Addr::FIELD_MAPJUMP_DISABLED),
                    // v2.30.66: story-progress (PPV) per arrival -- the
                    // evidence base for a future "this way continues the
                    // story" marker in Places (user request 2026-08-02).
                    // Every played session now maps PPV values to the
                    // fields where they changed; once enough of the route
                    // is logged, a curated PPV->next-objective table can
                    // speak the marker under the played-evidence rule.
                    static_cast<int>(
                        *reinterpret_cast<const volatile int16_t*>(
                            FF7Addr::STORY_PROGRESS)));
                Log::Write(dbg);
            }
            arrived_via_jump = false;

            if (Config::Get().announce_map_change) {
                // v2.24: prefer the game's own menu caption ("Sector 1
                // Station") from the MPNAM buffer â€” the friendly name a
                // sighted player reads in the menu. Fall back to the
                // internal header name when the buffer is still blank
                // (before a new game's first MPNAM).
                std::wstring msg = L"Screen: ";
                std::wstring friendly;
                bool have_name = FriendlyLocationName(friendly);
                if (have_name) {
                    msg += friendly;
                } else {
                    for (uint32_t i = 0; i < 9; ++i) {
                        const char c = *reinterpret_cast<const char*>(
                            hdr + FF7Addr::FTRIG_OFF_FIELD_NAME + i);
                        if (c == '\0')
                            break;
                        if (c < 0x20 || c > 0x7E)
                            break;  // non-ASCII = header mid-write; stop
                        // Underscores speak as pauses/garbage on some
                        // synthesizers â€” say them as spaces.
                        msg += (c == '_') ? L' ' : static_cast<wchar_t>(c);
                        have_name = have_name || c != '_';
                    }
                }
                if (have_name) {
                    // v2.30.64: ", facing up" â€” the audio version of the
                    // camera cut's orientation cue. Same d-pad vocabulary
                    // as routes/ladders so "facing up" and "push up" mean
                    // the same thing to the player's hands.
                    // v2.30.68: NOT while a scripted entry holds the UC
                    // lock â€” the scene is still turning the player and
                    // the byte read now is stale by control-return (the
                    // new-game "facing down" report). Deferred instead:
                    // facing_pending speaks it fresh at lock release.
                    const uint8_t uc_now =
                        *reinterpret_cast<const volatile uint8_t*>(
                            FF7Addr::FIELD_UC_LOCK);
                    if (uc_now == 0) {
                        msg += L", facing ";
                        msg += kDpadSectors[facing_sector];
                    } else {
                        facing_pending = true;
                    }
                    TTS::Speak(msg, /*interrupt=*/false);
                }
            }

            // ---- journey progress (v2.30.65) --------------------------
            // Runs on the same arrival edge, AFTER the screen announce so
            // the leg queues behind it (one action, second utterance
            // queues â€” the v2.30.51 interrupt-chain rule). Recomputes
            // from the ACTUAL field every time, so wrong turns, warps,
            // and detours all self-heal: the next leg is always the
            // shortest path from wherever the player really is.
            if (journey_active) {
                wchar_t jmsg[160];
                if (field_id == journey_target) {
                    // v2.30.69: reaching the FIELD is not reaching the
                    // THING when the target was a save point (see the
                    // journey_save_slot state comment). v2.30.73
                    // (review): the icon scan moved OUT of this one-shot
                    // edge -- on the first arrival poll the field can
                    // still be settling, and a single miss here used to
                    // speak the field-door completion this feature
                    // exists to prevent. The edge only arms the retry
                    // window; the per-poll last-mile block (below the
                    // facing release) scans, speaks the hint, completes,
                    // or -- only when the window empties -- falls back.
                    if (FF7FieldGraph::HasSavePoint(
                            static_cast<uint16_t>(field_id))) {
                        journey_lastmile_tries = 60;
                        if (Config::Get().debug_log)
                            Log::Write(
                                "[FF7Access] JOURNEY lastmile pending");
                    } else {
                        _snwprintf_s(jmsg, _countof(jmsg), _TRUNCATE,
                                     L"Arrived: %ls. Journey complete.",
                                     journey_name);
                        TTS::Speak(jmsg, /*interrupt=*/false);
                        journey_active = false;
                    }
                } else {
                    std::vector<int16_t> jdist, jprev;
                    FieldGraphBFS(field_id, jdist, jprev);
                    const int nxt = FieldGraphNextHop(
                        field_id, journey_target, jprev, jdist);
                    NavDest leg;
                    if (nxt < 0) {
                        _snwprintf_s(jmsg, _countof(jmsg), _TRUNCATE,
                                     L"No known route to %ls from here. "
                                     L"Journey ended.", journey_name);
                        TTS::Speak(jmsg, /*interrupt=*/false);
                        journey_active = false;
                    } else if (BuildJourneyLegDest(field_id, nxt, hdr, leg)) {
                        // Straight-line hint only (sector + seconds) â€” the
                        // full turn-by-turn stays on the \ key, where the
                        // player asks for it; an automatic multi-sentence
                        // route every screen would drown the transition.
                        // v2.30.74 (play report): this automatic leg
                        // announce used to speak ONLY the straight-line
                        // hint below, and the player ALWAYS had to press
                        // \ for the real path -- the .65 "don't drown
                        // the transition" tradeoff disproven in play.
                        // Speak the real route up front; the straight-
                        // line hint survives as the fallback when
                        // routing is unavailable, the same ordering the
                        // keypress path uses.
                        bool jspoke = false;
                        {
                            std::wstring jauto;
                            if (JourneyAutoRoute(leg,
                                                 static_cast<float>(px),
                                                 static_cast<float>(py),
                                                 static_cast<float>(pz),
                                                 player_tri, control_deg,
                                                 0.0f, jauto)) {
                                wchar_t jhead[64];
                                _snwprintf_s(jhead, _countof(jhead),
                                             _TRUNCATE,
                                             L"%ls: %d %ls left. Next, ",
                                             journey_name,
                                             static_cast<int>(
                                                 jdist[journey_target]),
                                             jdist[journey_target] == 1
                                                 ? L"screen"
                                                 : L"screens");
                                std::wstring jfull(jhead);
                                jfull += jauto;
                                TTS::Speak(jfull, /*interrupt=*/false);
                                jspoke = true;
                            }
                        }
                        const float ex2 = static_cast<float>(
                            leg.line_x2 - leg.line_x1);
                        const float ey2 = static_cast<float>(
                            leg.line_y2 - leg.line_y1);
                        const float wx2 = static_cast<float>(px - leg.line_x1);
                        const float wy2 = static_cast<float>(py - leg.line_y1);
                        const float l2 = ex2 * ex2 + ey2 * ey2;
                        float tt = (l2 > 0.0f)
                            ? ((wx2 * ex2 + wy2 * ey2) / l2) : 0.0f;
                        if (tt < 0.0f) tt = 0.0f;
                        if (tt > 1.0f) tt = 1.0f;
                        const float jdx = (leg.line_x1 + tt * ex2) - px;
                        const float jdy = (leg.line_y1 + tt * ey2) - py;
                        const float jd  = sqrtf(jdx * jdx + jdy * jdy);
                        const float wdeg =
                            atan2f(jdx, jdy) * (180.0f / 3.14159265f);
                        int secs = static_cast<int>(jd / 160.0f + 0.5f);
                        if (secs < 1) secs = 1;
                        const int16_t left = jdist[journey_target];
                        _snwprintf_s(jmsg, _countof(jmsg), _TRUNCATE,
                                     L"%ls: %d %ls left. Next, %ls, %ls, "
                                     L"%d %ls.",
                                     journey_name,
                                     static_cast<int>(left),
                                     left == 1 ? L"screen" : L"screens",
                                     leg.name,
                                     kDpadSectors[DpadSectorIndex(
                                         wdeg + control_deg - 180.0f)],
                                     secs,
                                     secs == 1 ? L"second" : L"seconds");
                        if (!jspoke)
                            TTS::Speak(jmsg, /*interrupt=*/false);
                    } else {
                        // Edges exist on the graph but nothing resolves
                        // live â€” the story-gated case. Keep the journey:
                        // the door may open after the player does what
                        // the scene wants.
                        _snwprintf_s(jmsg, _countof(jmsg), _TRUNCATE,
                                     L"%ls: the next exit is not available "
                                     L"here yet.", journey_name);
                        TTS::Speak(jmsg, /*interrupt=*/false);
                    }
                    if (Config::Get().debug_log && journey_active) {
                        char dbg[128];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                            "[FF7Access] JOURNEY at=%d target=%d next=%d",
                            static_cast<int>(field_id),
                            static_cast<int>(journey_target), nxt);
                        Log::Write(dbg);
                    }
                }
            }
        }

        // ---- deferred facing release (v2.30.68, every poll) ---------------
        // The arrival announce skipped its facing clause because a scripted
        // entry held the UC lock; speak it now that control is real, from
        // the byte AS IT IS (any scripted turn already applied).
        if (facing_pending) {
            const uint8_t uc_now = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::FIELD_UC_LOCK);
            if (uc_now == 0) {
                facing_pending = false;
                const uint8_t fb = elem[FF7Addr::FIELD_EVENT_FACING];
                const int fs = DpadSectorIndex(
                    fb * (360.0f / 256.0f) + control_deg - 180.0f);
                std::wstring fmsg = L"Facing ";
                fmsg += kDpadSectors[fs];
                TTS::Speak(fmsg, /*interrupt=*/false);
                if (Config::Get().debug_log) {
                    char dbg[96];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] FACING deferred release byte=%u sector=%d",
                        fb, fs);
                    Log::Write(dbg);
                }
            }
        }

        // ---- journey last mile (v2.30.69, reworked v2.30.73, every poll) --
        // Two phases. FIND: while the arrival-armed retry window is open,
        // scan for the live save icon each poll (a one-shot scan proved
        // fragile against fields still settling on the arrival edge);
        // when found, latch the slot and speak ONE hint -- unless the
        // player is already inside the pad's bubble, in which case the
        // completion below is the whole utterance (review: hint +
        // completion used to queue back-to-back in one poll, speaking a
        // movement instruction for a finished journey). COMPLETE: inside
        // the reach bubble ON ITS LEVEL -- the z gate is exactly what
        // field-granular arrival lacked (the pad sits a ladder below the
        // entry catwalk on the reactor field). A latched slot that goes
        // bad (out of range, unreadable, VISI-hidden mid-story-beat)
        // re-arms the FIND window instead of silently wedging or falsely
        // completing; only an EMPTY window falls back to the old
        // field-door completion, so every journey still terminates.
        // interrupt=false throughout: the v2.30.62 walk-into announce
        // fires on the same approach -- queue behind it, one action.
        if (journey_active && field_id == journey_target) {
            wchar_t lmsg[160];
            if (journey_save_slot < 0 && journey_lastmile_tries > 0) {
                // Field name for the label decode (the shared fname is
                // built after the keypress gate, which most polls skip).
                char jfname[10] = {};
                memcpy(jfname, reinterpret_cast<const void*>(
                           hdr + FF7Addr::FTRIG_OFF_FIELD_NAME), 9);
                for (char& c : jfname)
                    if (c != '\0' && (c < 0x20 || c > 0x7E))
                        c = '\0';
                int save_slot = -1;
                NavDest sdest;
                const uint32_t n_walk = (nmod < 32u) ? nmod : 32u;
                if (IsReadableSpan(reinterpret_cast<const void*>(arr),
                                   n_walk *
                                       FF7Addr::FIELD_EVENT_DATA_STRIDE)) {
                    for (uint16_t m = 0; m < n_walk; ++m) {
                        if (m == pmid)
                            continue;
                        const uint8_t* me = reinterpret_cast<const uint8_t*>(
                            arr + m * FF7Addr::FIELD_EVENT_DATA_STRIDE);
                        if (*reinterpret_cast<const uint8_t*>(
                                me + FF7Addr::FIELD_EVENT_VISIBLE) == 0)
                            continue;   // script hid it
                        std::wstring lbl;
                        if (!FieldModelLabel(m, jfname, lbl))
                            continue;
                        const wchar_t* friendly = nullptr;
                        if (ClassifyModelLabel(lbl, &friendly) != MC_SAVE)
                            continue;
                        // Shared constructor validates placement too
                        // (parked-at-origin models are bound but not on
                        // the mesh yet -- keep scanning next poll).
                        if (!BuildModelPointDest(arr, nmod, m, sdest))
                            continue;
                        save_slot = m;
                        break;
                    }
                }
                if (save_slot >= 0) {
                    const uint8_t* sme = reinterpret_cast<const uint8_t*>(
                        arr + save_slot * FF7Addr::FIELD_EVENT_DATA_STRIDE);
                    // Reach bubble = the route builder's talk/contact
                    // rule (v2.30.25/.26) so "complete" and "the walk
                    // stops here" agree -- EXCEPT the 90 cap: that clamp
                    // exists so walks stop within a step of people, but
                    // completion must honor the pad's own interaction
                    // radius (review: a pad with talk > 90 could open
                    // the save prompt outside our bubble and the journey
                    // would never complete). 200 = sanity bound only.
                    int16_t tr = *reinterpret_cast<const int16_t*>(
                        sme + FF7Addr::FIELD_EVENT_TALK_RADIUS);
                    const int16_t mc = *reinterpret_cast<const int16_t*>(
                        sme + FF7Addr::FIELD_EVENT_COLLISION_RADIUS);
                    if (tr < 20)  tr = 20;
                    if (tr > 200) tr = 200;
                    float reach = static_cast<float>(tr);
                    if (mc > 0 && mc <= 200) {
                        const float contact = PlayerCollisionRadius()
                            + static_cast<float>(mc) + 8.0f;
                        if (contact > reach)
                            reach = contact;
                    }
                    const float sdx = static_cast<float>(sdest.line_x1 - px);
                    const float sdy = static_cast<float>(sdest.line_y1 - py);
                    const float sd  = sqrtf(sdx * sdx + sdy * sdy);
                    const int32_t sdz = sdest.line_z1 - pz;
                    journey_save_slot     = save_slot;
                    journey_save_reach    = reach;
                    journey_lastmile_tries = 0;
                    if (Config::Get().debug_log) {
                        char dbg[128];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                            "[FF7Access] JOURNEY lastmile slot=%d "
                            "reach=%.0f dist=%.0f dz=%d",
                            save_slot, reach, sd, static_cast<int>(sdz));
                        Log::Write(dbg);
                    }
                    if (sd <= reach && sdz > -150 && sdz < 150) {
                        // Already at the pad: say nothing here -- the
                        // completion below fires this same poll and is
                        // the one utterance.
                    } else {
                        // v2.30.74 (play report): the automatic hint
                        // speaks the REAL route (the same text \
                        // produces) -- straight-line/level-fact wording
                        // below survives only as the routing-
                        // unavailable fallback. Cross-level pads get
                        // the connector chain ("Save point: on another
                        // level. First take ladder 1, ...") instead of
                        // the bare level fact.
                        wcsncpy_s(sdest.name, L"Save point", _TRUNCATE);
                        std::wstring srt;
                        if (JourneyAutoRoute(sdest,
                                             static_cast<float>(px),
                                             static_cast<float>(py),
                                             static_cast<float>(pz),
                                             player_tri, control_deg,
                                             reach, srt)) {
                            TTS::Speak(srt, /*interrupt=*/false);
                        } else if (sdz <= -150 || sdz >= 150) {
                            // Review (v2.30.73): never a 2D direction
                            // across a level gap -- the honest fallback
                            // is the level fact.
                            _snwprintf_s(lmsg, _countof(lmsg), _TRUNCATE,
                                         L"%ls: save point, on another "
                                         L"level.", journey_name);
                            TTS::Speak(lmsg, /*interrupt=*/false);
                        } else {
                            int ssecs = static_cast<int>(
                                sd / FF7Addr::WALKMESH_UNITS_PER_SEC
                                + 0.5f);
                            if (ssecs < 1) ssecs = 1;
                            // v2.30.70: "Arrived" is RESERVED for the
                            // objective -- ordinary leg idiom.
                            _snwprintf_s(lmsg, _countof(lmsg), _TRUNCATE,
                                         L"%ls: save point, %ls, %d %ls.",
                                         journey_name,
                                         kDpadSectors[DpadSectorIndex(
                                             atan2f(sdx, sdy)
                                                 * (180.0f / 3.14159265f)
                                             + control_deg - 180.0f)],
                                         ssecs,
                                         ssecs == 1 ? L"second"
                                                    : L"seconds");
                            TTS::Speak(lmsg, /*interrupt=*/false);
                        }
                    }
                } else if (--journey_lastmile_tries == 0) {
                    // Window empty with no icon ever seen: the old
                    // field-arrival completion -- best effort, never a
                    // stuck journey.
                    _snwprintf_s(lmsg, _countof(lmsg), _TRUNCATE,
                                 L"Arrived: %ls. Journey complete.",
                                 journey_name);
                    TTS::Speak(lmsg, /*interrupt=*/false);
                    journey_active = false;
                    if (Config::Get().debug_log)
                        Log::Write("[FF7Access] JOURNEY lastmile giveup");
                }
            }
            if (journey_save_slot >= 0) {
                bool slot_ok = false;
                if (journey_save_slot < static_cast<int>(nmod)) {
                    const uint8_t* sme = reinterpret_cast<const uint8_t*>(
                        arr + journey_save_slot *
                        FF7Addr::FIELD_EVENT_DATA_STRIDE);
                    if (IsReadableSpan(sme,
                                       FF7Addr::FIELD_EVENT_DATA_STRIDE) &&
                        *reinterpret_cast<const uint8_t*>(
                            sme + FF7Addr::FIELD_EVENT_VISIBLE) != 0) {
                        slot_ok = true;
                        const int32_t* smp =
                            reinterpret_cast<const int32_t*>(
                                sme + FF7Addr::FIELD_EVENT_MODEL_POS);
                        const float cdx =
                            static_cast<float>((smp[0] >> 12) - px);
                        const float cdy =
                            static_cast<float>((smp[1] >> 12) - py);
                        const float cd = sqrtf(cdx * cdx + cdy * cdy);
                        const int32_t cdz = (smp[2] >> 12) - pz;
                        if (cd <= journey_save_reach &&
                            cdz > -150 && cdz < 150) {
                            // v2.30.70: the journey's ONE "Arrived" --
                            // spoken at the pad, never at the field door.
                            _snwprintf_s(lmsg, _countof(lmsg), _TRUNCATE,
                                         L"Arrived: %ls, save point. "
                                         L"Journey complete.",
                                         journey_name);
                            TTS::Speak(lmsg, /*interrupt=*/false);
                            if (Config::Get().debug_log) {
                                char dbg[96];
                                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                                    "[FF7Access] JOURNEY complete "
                                    "lastmile dist=%.0f dz=%d", cd,
                                    static_cast<int>(cdz));
                                Log::Write(dbg);
                            }
                            journey_active    = false;
                            journey_save_slot = -1;
                        }
                    }
                }
                if (journey_active && journey_save_slot >= 0 && !slot_ok) {
                    // Latched slot went bad (review: the old check would
                    // either skip forever on nmod drift or complete on a
                    // hidden icon's stale position). Drop the latch and
                    // re-open the FIND window -- it re-finds a live icon
                    // or falls back within ~3 s.
                    journey_save_slot      = -1;
                    journey_lastmile_tries = 60;
                    if (Config::Get().debug_log)
                        Log::Write("[FF7Access] JOURNEY lastmile rescan");
                }
            }
        }

        // ---- visited-places learning (v2.25, every poll) ------------------
        // Runs regardless of announce_map_change: learning is what names
        // exit destinations, not an announcement feature.
        {
            std::wstring cap;
            if (FriendlyLocationName(cap))
                PlacesLearn(field_id, cap);
        }

        // ---- per-model movement tracking (every poll) --------------------
        // Sample every model's position; stamp the tick when it changes.
        // Field change invalidates the samples (positions jump between
        // fields â€” without the reset every model would read as "wandering"
        // for one window after each transition).
        {
            if (field_id != track_field) {
                track_field = field_id;
                memset(track_valid, 0, sizeof(track_valid));
                memset(track_move_tick, 0, sizeof(track_move_tick));
            }
            const uint32_t n_tracked = (nmod < 32u) ? nmod : 32u;
            const bool span_ok = IsReadableSpan(
                reinterpret_cast<const void*>(arr),
                n_tracked * FF7Addr::FIELD_EVENT_DATA_STRIDE);
            const ULONGLONG now = GetTickCount64();
            for (uint16_t m = 0; span_ok && m < nmod && m < 32; ++m) {
                const int32_t* mpos = reinterpret_cast<const int32_t*>(
                    arr + m * FF7Addr::FIELD_EVENT_DATA_STRIDE +
                    FF7Addr::FIELD_EVENT_MODEL_POS);
                const int32_t mx = mpos[0], my = mpos[1];
                if (track_valid[m] && (mx != track_x[m] || my != track_y[m]))
                    track_move_tick[m] = now;
                track_x[m] = mx;
                track_y[m] = my;
                track_valid[m] = true;
            }
        }

        // True while the model moved within the wandering window.
        const auto is_wandering = [&](int slot) {
            return slot >= 0 && slot < 32 &&
                   track_move_tick[slot] != 0 &&
                   GetTickCount64() - track_move_tick[slot] <= WANDER_WINDOW_MS;
        };

        // ---- interactable proximity tone (v2.27) -------------------------
        // A sighted player SEES the person/chest/ladder as they pass it;
        // this chirp is that glance: it fires once when the player enters
        // an object's interaction range and re-arms after they leave.
        // Ranges: the model's talk_radius OR body contact, whichever is
        // larger (v2.30.26). âš  The original "talk_radius = the exact
        // circle the OK button tests" reading is WRONG for large-bodied
        // models: Barret's talk radius is 70 but his collision radius is
        // 48 â€” the player's center bottoms out at ~80 from his and can
        // NEVER enter the 70 circle, yet talking at contact works (the
        // 2026-07-25 street scene: blocked at 81, talk ushered the
        // player into the bar; play report: "it does not beep when I
        // get near him"). The engine-side check reader was hunted
        // statically (ff7_talk_range_static.py â€” found the TALKR/TLKR2
        // handlers 0x618253/0x6182DF and the scale-based defaults
        // col=30Â·s>>9 / talk=80Â·s>>9, but not the reader), so the rule
        // shipped is the behaviorally PROVEN one: body contact always
        // suffices to interact â†’ chirp at
        //   max(talk_radius, player_col + model_col + one step).
        // Unchanged for default-sized NPCs (talk 70 > contact ~62).
        // Skips talk-disabled people (the +0x61 byte â€” the Jessie lesson:
        // no ping for someone who won't respond), off-mesh models, and
        // anything on another LAYER (z gate â€” a walkway overhead must not
        // ping the floor below). Suppressed during scripted scenes
        // (uc_lock) and while a dialog is up, so it never plays over
        // conversation; the armed state still updates then, so no
        // spurious ping fires when the dialog closes.
        if (Config::Get().proximity_tone || Config::Get().proximity_announce) {
            if (field_id != prox_field) {
                prox_field = field_id;
                memset(prox_armed_m, 1, sizeof(prox_armed_m));
                memset(prox_armed_l, 1, sizeof(prox_armed_l));
            }
            const uint8_t uc_lock = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::FIELD_UC_LOCK);
            const bool dialog_up =
                (GetTickCount() - Hooks::LastDialogActivityTick()) < 500;
            // Silence gates shared by both loops; the min-gap test runs at
            // each fire site so simultaneous entries can't double-chirp.
            const bool quiet_ok = uc_lock == 0 && !dialog_up;
            const auto try_beep = [&]() {
                if (Config::Get().proximity_tone && quiet_ok &&
                    GetTickCount64() - last_prox_beep >= PROX_MIN_GAP_MS) {
                    Tones::Play(PROX_BEEP_HZ, PROX_BEEP_MS);
                    last_prox_beep = GetTickCount64();
                }
            };

            // v2.30.62: speak WHAT was reached, on the same arming edge as
            // the chirp (user request: "if Cloud comes to a ladder or jump
            // ... same for characters with dialog"). Names come from the
            // SAME machinery the destination browser uses, so a thing is
            // called the same whether you walked into it or cycled to it
            // with J/L — models through FieldModelLabel + the label
            // classifier + TranslateDevLabel, lines through the entity
            // name table + TranslateEntityName + the offline behaviour
            // catalog's suffix ("ladder up", "pinball, exit to Seventh
            // Heaven"). Queued (interrupt=false) so walking past three
            // things in a row reads as a list instead of each cutting the
            // last off, and so it never clips dialog that starts in the
            // same instant.
            const auto speak_prox = [&](const std::wstring& what) {
                if (Config::Get().proximity_announce && quiet_ok &&
                    !what.empty())
                    TTS::Speak(what, /*interrupt=*/false);
            };
            // Field name for the model-label lookup (same source and
            // sanitising as the browser's build pass).
            char pfname[10] = {};
            memcpy(pfname, reinterpret_cast<const void*>(
                       hdr + FF7Addr::FTRIG_OFF_FIELD_NAME), 9);
            for (char& c : pfname)
                if (c != '\0' && (c < 0x20 || c > 0x7E)) c = '\0';

            const uint32_t n_prox = (nmod < 32u) ? nmod : 32u;
            const bool prox_ok = IsReadableSpan(
                reinterpret_cast<const void*>(arr),
                n_prox * FF7Addr::FIELD_EVENT_DATA_STRIDE);
            const int32_t pzv = pos[2] >> 12;
            // Player's collision radius for the contact term (v2.30.26).
            const int16_t pcr = *reinterpret_cast<const int16_t*>(
                elem + FF7Addr::FIELD_EVENT_COLLISION_RADIUS);
            const float player_col = (pcr >= 8 && pcr <= 120)
                                         ? static_cast<float>(pcr) : 32.0f;
            for (uint16_t m = 0; prox_ok && m < n_prox; ++m) {
                if (m == pmid)
                    continue;
                const uint8_t* me = reinterpret_cast<const uint8_t*>(
                    arr + m * FF7Addr::FIELD_EVENT_DATA_STRIDE);
                const int32_t* mp = reinterpret_cast<const int32_t*>(
                    me + FF7Addr::FIELD_EVENT_MODEL_POS);
                const int16_t tri = *reinterpret_cast<const int16_t*>(
                    me + FF7Addr::FIELD_EVENT_TRIANGLE_ID);
                const int16_t radius = *reinterpret_cast<const int16_t*>(
                    me + FF7Addr::FIELD_EVENT_TALK_RADIUS);
                const bool talk_off = *reinterpret_cast<const uint8_t*>(
                    me + FF7Addr::FIELD_EVENT_TALK_OFF) != 0;
                // v2.30.26: effective range = max(talk radius, body
                // contact + one step) â€” see the header comment above.
                // A script-cleared collision radius (<=0, intangible)
                // contributes nothing, leaving the plain talk circle.
                const int16_t mcr = *reinterpret_cast<const int16_t*>(
                    me + FF7Addr::FIELD_EVENT_COLLISION_RADIUS);
                const float mcol = (mcr > 0 && mcr <= 200)
                                       ? static_cast<float>(mcr) : 0.0f;
                float eff = static_cast<float>(radius);
                if (mcol > 0.0f && player_col + mcol + 8.0f > eff)
                    eff = player_col + mcol + 8.0f;
                const float dx = static_cast<float>((mp[0] >> 12) - px);
                const float dy = static_cast<float>((mp[1] >> 12) - py);
                const float dist = sqrtf(dx * dx + dy * dy);
                const int32_t dz = (mp[2] >> 12) - pzv;
                // v2.30.45: a script-hidden model (VISI 0 â€” collected
                // pickups above all) shows a sighted player NOTHING, so
                // it must not ping. The chirp's promise is "something
                // usable is here"; a hidden model isn't.
                const uint8_t mvis = *reinterpret_cast<const uint8_t*>(
                    me + FF7Addr::FIELD_EVENT_VISIBLE);
                const bool reachable = tri >= 0 && radius > 0 && !talk_off &&
                                       mvis != 0 &&
                                       dz > -PROX_Z_GATE && dz < PROX_Z_GATE;
                if (reachable && dist <= eff) {
                    if (prox_armed_m[m]) {
                        prox_armed_m[m] = false;
                        try_beep();
                        // Name it. Scenery is skipped exactly as the
                        // browser skips it (v2.30.18) — but a cataloged
                        // DEVICE (v2.30.45 MC_PROP: buttons, levers)
                        // announces, since that is a thing you operate.
                        if (Config::Get().proximity_announce) {
                            std::wstring lbl;
                            if (FieldModelLabel(m, pfname, lbl)) {
                                const wchar_t* friendly = nullptr;
                                ModelClass mc = ClassifyModelLabel(lbl, &friendly);
                                const uint8_t ent_id =
                                    *reinterpret_cast<const uint8_t*>(
                                        me + FF7Addr::FIELD_EVENT_ENTITY_ID);
                                if (mc == MC_SCENERY && field_id > 0 &&
                                    FF7PropCatalog::Find(
                                        static_cast<uint16_t>(field_id), ent_id))
                                    mc = MC_PROP;
                                if (mc != MC_SCENERY) {
                                    std::wstring name = friendly
                                        ? std::wstring(friendly)
                                        : TranslateDevLabel(lbl);
                                    if (mc == MC_PROP)
                                        name += L", device";
                                    speak_prox(name);
                                }
                            }
                        }
                    }
                } else if (!reachable ||
                           dist > eff + PROX_REARM_SLACK) {
                    prox_armed_m[m] = true;
                }
            }

            const uint16_t n_lines = *reinterpret_cast<const volatile uint16_t*>(
                FF7Addr::FIELD_LINE_COUNT);
            for (uint32_t i = 0; i < n_lines && i < FF7Addr::FLINE_MAX; ++i) {
                const uint8_t* le = reinterpret_cast<const uint8_t*>(
                    FF7Addr::FIELD_LINE_ARRAY + i * FF7Addr::FLINE_STRIDE);
                const int16_t* v = reinterpret_cast<const int16_t*>(le);
                const bool enabled = le[FF7Addr::FLINE_OFF_ENABLED] != 0;
                const int32_t zmid = (v[2] + v[5]) / 2;
                const float dist2 = PointSegDist2(
                    static_cast<float>(px), static_cast<float>(py),
                    v[0], v[1], v[3], v[4]);
                const bool reachable = enabled &&
                    zmid - pzv > -PROX_Z_GATE && zmid - pzv < PROX_Z_GATE;
                if (reachable && dist2 <= PROX_LINE_RANGE * PROX_LINE_RANGE) {
                    if (prox_armed_l[i]) {
                        prox_armed_l[i] = false;
                        try_beep();
                        // Ladders, jumps, exits: the entity's translated
                        // name plus the offline catalog's behaviour word,
                        // i.e. exactly what the Triggers category says.
                        // The entity/slot cross-check is the v2.17 rule —
                        // an unmatched slot falls back to "Trigger N"
                        // rather than speaking a plausible wrong name.
                        if (Config::Get().proximity_announce) {
                            const uint8_t ent = le[FF7Addr::FLINE_OFF_ENTITY];
                            const uint8_t mapped =
                                *reinterpret_cast<const volatile uint8_t*>(
                                    FF7Addr::FIELD_ENTITY_LINE_SLOT + ent);
                            std::wstring name;
                            const uint8_t* et = nullptr;
                            uint8_t ec = 0;
                            std::wstring ename;
                            if (mapped == i && FieldEntityNameTable(&et, &ec) &&
                                EntityNameFromTable(et, ec, ent, ename))
                                name = TranslateEntityName(ename);
                            if (name.empty()) {
                                wchar_t fb[24];
                                _snwprintf_s(fb, _countof(fb), _TRUNCATE,
                                             L"Trigger %u", i + 1u);
                                name = fb;
                            }
                            const FF7LineCatalog::LineInfo* li =
                                (field_id > 0)
                                    ? FF7LineCatalog::Find(
                                          static_cast<uint16_t>(field_id), ent)
                                    : nullptr;
                            if (li) {
                                using namespace FF7LineCatalog;
                                switch (li->kind) {
                                case LK_EXIT:
                                case LK_EXIT_OK: {
                                    std::wstring dn;
                                    bool explored = true;
                                    if (li->dest_field >= 0 &&
                                        DestinationName(li->dest_field, dn,
                                                        &explored)) {
                                        name += L", exit to ";
                                        name += dn;
                                        if (!explored)
                                            name += L", unexplored";
                                    } else {
                                        name += L", exit";
                                    }
                                    if (li->kind == LK_EXIT_OK)
                                        name += L", press OK";
                                    break;
                                }
                                case LK_CLIMB:
                                    // v2.30.68: save-pad lines classify
                                    // CLIMB (their script chains reach a
                                    // LADER -- pads on pipe platforms),
                                    // but "save point, climb" misleads;
                                    // the name is the truth (3rd-run
                                    // report, field 124 ent 6).
                                    if (wcsstr(name.c_str(), L"ladder") == nullptr &&
                                        wcsstr(name.c_str(), L"save") == nullptr)
                                        name += L", climb";
                                    break;
                                case LK_OK:    name += L", press OK"; break;
                                default: break;   // scene/inert: bare name
                                }
                            }
                            speak_prox(name);
                        }
                    }
                } else if (!reachable ||
                           dist2 > (PROX_LINE_RANGE + PROX_REARM_SLACK) *
                                   (PROX_LINE_RANGE + PROX_REARM_SLACK)) {
                    prox_armed_l[i] = true;
                }
            }
        }

        // ---- direction calibration logging (debug_log only) -------------
        // While a direction is held and the player moves, log the held bits
        // against the world motion angle once per second. One walkabout
        // session gives the exact input->world mapping (see header comment).
        if (Config::Get().debug_log) {
            const ULONGLONG now = GetTickCount64();
            const uint32_t keys = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::FIELD_KEY_INPUT_STATUS);
            if (calib_have_last && (keys & FF7Addr::KEY_DIR_ANY) &&
                now >= next_calib_tick &&
                (pos[0] != calib_last_x || pos[1] != calib_last_y)) {
                const float mdx = static_cast<float>(pos[0] - calib_last_x);
                const float mdy = static_cast<float>(pos[1] - calib_last_y);
                const float motion_deg = atan2f(mdx, mdy) * (180.0f / 3.14159265f);
                char dbg[160];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] NAV calib keys=%04X motion_deg=%.1f ctrl_dir=%u (%.1f deg)",
                    static_cast<unsigned>(keys & FF7Addr::KEY_DIR_ANY),
                    motion_deg, static_cast<unsigned>(control_dir), control_deg);
                Log::Write(dbg);
                next_calib_tick = now + 1000;
            }
            calib_last_x = pos[0];
            calib_last_y = pos[1];
            calib_have_last = true;
        }

        // ---- hotkey edge detection (whole FF4-scheme key set) ------------
        // Only while the game window is focused: GetAsyncKeyState is global,
        // and these letters typed into a chat window must not trigger
        // announcements. When unfocused, previous-state still tracks the
        // real key state so re-focusing can't produce a stale edge.
        DWORD fg_pid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &fg_pid);
        const bool focused = (fg_pid == GetCurrentProcessId());

        // v2.30.42: while the F8 settings menu is open it OWNS J/L/K and
        // the bracket/minus/equals aliases â€” one keypress must never both
        // change a setting and cycle a destination. Suppress edges the
        // same way unfocus does (state still tracked, so closing the menu
        // cannot manufacture a stale edge here).
        const bool settings_menu_open = SettingsMenu::IsOpen();

        bool pressed[KEY_COUNT] = {};
        bool any_pressed = false;
        for (int k = 0; k < KEY_COUNT; ++k) {
            const bool down = (GetAsyncKeyState(kVKs[k]) & 0x8000) != 0;
            pressed[k] = focused && !settings_menu_open && down && !was_down[k];
            was_down[k] = down;
            any_pressed = any_pressed || pressed[k];
        }

        // Right-analog-stick input (v2.21): polled every tick like the keys
        // so held-state tracking stays fresh, with edges suppressed while
        // unfocused â€” the exact focus rule the keyboard uses. XInput is a
        // read-only shared query, so the game (and FFNx) see the controller
        // exactly as before; the stick and R3 carry no native function
        // (verified â€” see gamepad.h). gamepad_nav=false skips even the poll.
        GamepadNav::Actions pad = {};
        if (Config::Get().gamepad_nav)
            pad = GamepadNav::Poll(focused && !settings_menu_open);

        if (!any_pressed && !pad.Any())
            continue;

        const bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        const bool ctrl  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        if (ctrl)
            memset(pressed, 0, sizeof(pressed));   // no browser action uses
                // Ctrl (the layer filter moved to Shift+; when the keys
                // file rebound it 2026-08-05), so Ctrl+anything -- incl. a
                // future Ctrl+arrows teleport -- must never fire one.
                // Ctrl suppresses only the KEYS; a simultaneous stick
                // action is unrelated and proceeds.

        // Decode key presses into browser actions (accessiblity_keys.txt),
        // then OR in the stick's alternate triggers (v2.21 â€” same actions,
        // second input path):
        //   J/[ prev dest, L/] next dest (unshifted)   | stick left/right
        //   Shift+J/- prev category, Shift+L/= next    | stick up/down
        //   K announce selection, Shift+K reset category
        //   \/P directions (unshifted)                 | R3 click
        //   Shift+\/Shift+P toggle path filter (v2.30.87)
        //   Shift+; toggle layer filter (v2.30.88)
        //   M current map name
        const bool act_prev_dest = (pressed[KJ] && !shift) ||
                                   pressed[KLBRACKET] || pad.prev_dest;
        const bool act_next_dest = (pressed[KL] && !shift) ||
                                   pressed[KRBRACKET] || pad.next_dest;
        const bool act_prev_cat  = (pressed[KJ] && shift)  ||
                                   pressed[KMINUS] || pad.prev_cat;
        const bool act_next_cat  = (pressed[KL] && shift)  ||
                                   pressed[KPLUS] || pad.next_cat;
        const bool act_announce  = pressed[KK] && !shift;
        const bool act_reset_cat = pressed[KK] && shift;
        const bool act_directions =
            ((pressed[KBACKSLASH] || pressed[KP]) && !shift) ||
            pad.directions;
        const bool act_filter =
            (pressed[KBACKSLASH] || pressed[KP]) && shift;
        // Shift+; only -- unshifted ; deliberately decodes to NOTHING so a
        // semicolon the player's own ff7input.cfg (or a chat overlay) uses
        // never collides with the mod. GetAsyncKeyState is a passive read:
        // the game still receives every key either way.
        const bool act_layer_filter = pressed[KSEMICOLON] && shift;
        const bool act_map_name  = pressed[KM] && !shift;

        if (!(act_prev_dest || act_next_dest || act_prev_cat || act_next_cat ||
              act_announce || act_reset_cat || act_directions || act_filter ||
              act_layer_filter || act_map_name))
            continue;

        // ---- field name (plain ASCII in the header, not FF7-encoded) -----
        char fname[10] = {};
        memcpy(fname, reinterpret_cast<const void*>(hdr + FF7Addr::FTRIG_OFF_FIELD_NAME), 9);
        for (char& c : fname)
            if (c != '\0' && (c < 0x20 || c > 0x7E)) c = '\0';

        if (act_map_name) {
            // v2.24: friendly menu caption first, then the internal name
            // as the unique per-screen identifier ("Sector 1 Station,
            // md1stin") â€” several screens share one caption, and M is the
            // precision key, so it speaks both. Screen-change announces
            // stay caption-only for brevity.
            std::wstring msg;
            std::wstring friendly;
            if (FriendlyLocationName(friendly))
                msg = friendly;
            if (fname[0]) {
                if (!msg.empty())
                    msg += L", ";
                for (int i = 0; i < 9 && fname[i]; ++i)
                    msg += static_cast<wchar_t>(fname[i]);
            }
            if (msg.empty())
                msg = L"Unknown map";
            Log::Write("[FF7Access] NAV map-name announce");
            TTS::Speak(msg, /*interrupt=*/true);
            continue;
        }

        // ---- apply state mutations BEFORE building the list ---------------
        // v2.15.2 bug fix: the list used to be built first, so a category
        // change announced the PREVIOUS category's count ("Exits, 8" when
        // arriving from All, "Exits, 6" when arriving from People â€” the
        // reported direction-dependent numbers). Category/field mutations
        // now happen first and the list is built for the NEW state.
        // (CAT_* constants are file-scope since v2.18.2 â€” see
        // CategoryForModelClass above.)

        // Field change invalidates selection and category.
        if (field_id != nav_field_id) {
            nav_field_id = field_id;
            category  = 0;
            selection = 0;
        }

        bool announce_cat = false;
        bool announce_filter = false;
        bool announce_layer = false;
        bool journey_cancelled = false;
        // Filter toggles mutate BEFORE the build for the same reason
        // category changes do (v2.15.2): the announcement must carry the
        // count of the list the player will actually cycle. Selection
        // resets because the filtered list is a different list â€” keeping
        // an index into the old one would land on an arbitrary entry.
        if (act_filter) {
            path_filter = !path_filter;
            selection = 0;
            announce_filter = true;
        }
        if (act_layer_filter) {
            layer_filter = !layer_filter;
            selection = 0;
            announce_layer = true;
        }
        if (act_prev_cat || act_next_cat) {
            category += act_next_cat ? 1 : -1;
            if (category < 0) category = kCategoryCount - 1;
            if (category >= kCategoryCount) category = 0;
            selection = 0;
            announce_cat = true;
        } else if (act_reset_cat) {
            // Shift+K resets the category AND cancels an active journey
            // (v2.30.65) â€” the one "stop guiding me" gesture, matching
            // its existing "back to a known state" meaning.
            category  = 0;
            selection = 0;
            announce_cat = true;
            if (journey_active) {
                journey_active = false;
                journey_save_slot = -1;
                journey_lastmile_tries = 0;
                journey_cancelled = true;
            }
        }

        // ---- rebuild the destination list (fresh every keypress) ---------
        // Max 12 gateways + 32 models â€” rebuilding on demand is cheaper
        // than any caching scheme and always reflects the live field
        // (NPCs move; a fresh read gives their current position). Slot
        // order is the destination's IDENTITY: "Exit 2" / "Person 3" keep
        // their names as the player moves â€” never renumbered by distance.
        constexpr int kMaxDests =
            FF7Addr::FTRIG_GATEWAY_COUNT + 32    // exits + model cap
            + FF7Addr::FLINE_MAX;                // + LINE trigger zones
        NavDest dests[kMaxDests];
        int n_dests = 0;

        if (category == CAT_ALL || category == CAT_EXITS) {
            // v2.25: exits are named by DESTINATION -- "To No.1 Reactor",
            // "To World map" -- with "Exit N" only when the id resolves
            // to nothing (see DestinationName). v2.30.86: unvisited
            // destinations speak their REAL harvested caption plus
            // ", unexplored" instead of the old internal map code
            // ("To nmkin 2") -- tester-reported nuisance, user-directed
            // change 2026-08-04. Two passes so duplicate destinations
            // get ordinals ("To Platform 2"), the same slot-order
            // identity rule as every other category. A name can still
            // UPGRADE mid-session (harvested spelling -> learned game
            // spelling, suffix drops, once the place is visited) --
            // slot order never changes.
            struct GwTmp {
                const int16_t* v;
                std::wstring   base;
                bool           explored;
            } gws[FF7Addr::FTRIG_GATEWAY_COUNT];
            int n_gws = 0;
            int exit_no = 0;   // fallback numbering: eligible slot order,
                               // matching the pre-v2.25 "Exit N" labels
            for (uint32_t g = 0; g < FF7Addr::FTRIG_GATEWAY_COUNT; ++g) {
                const uint8_t* gw = reinterpret_cast<const uint8_t*>(
                    hdr + FF7Addr::FTRIG_OFF_GATEWAYS + g * FF7Addr::FTRIG_GATEWAY_SIZE);
                const int16_t* v = reinterpret_cast<const int16_t*>(gw);
                const int16_t dest_id = *reinterpret_cast<const int16_t*>(gw + 0x12);
                if (dest_id == FF7Addr::FTRIG_FIELD_ID_UNUSED || dest_id < 0)
                    continue;
                if (v[0] == 0 && v[1] == 0 && v[3] == 0 && v[4] == 0)
                    continue;   // degenerate line = empty slot
                ++exit_no;
                GwTmp& t = gws[n_gws++];
                t.v = v;
                t.explored = true;
                std::wstring dn;
                if (DestinationName(dest_id, dn, &t.explored)) {
                    t.base = L"To ";
                    t.base += dn;
                } else {
                    wchar_t buf[16];
                    _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                                 L"Exit %d", exit_no);
                    t.base = buf;
                }
            }
            for (int a = 0; a < n_gws; ++a) {
                int ordinal = 1, total = 0;
                for (int k = 0; k < n_gws; ++k) {
                    if (gws[k].base == gws[a].base) {
                        ++total;
                        if (k < a) ++ordinal;
                    }
                }
                // ", unexplored" rides AFTER the ordinal ("To Platform 2,
                // unexplored") and stays OUT of the dedupe identity --
                // two exits to one unvisited field must still pair up.
                // (v2.30.86: the suffix replaces the old internal-code
                // obscuring; the name itself is now always the real one.)
                const wchar_t* sfx =
                    gws[a].explored ? L"" : L", unexplored";
                NavDest& d = dests[n_dests++];
                if (total > 1)
                    _snwprintf_s(d.name, _countof(d.name), _TRUNCATE,
                                 L"%ls %d%ls", gws[a].base.c_str(), ordinal,
                                 sfx);
                else
                    _snwprintf_s(d.name, _countof(d.name), _TRUNCATE,
                                 L"%ls%ls", gws[a].base.c_str(), sfx);
                const int16_t* v = gws[a].v;
                d.line_x1 = v[0]; d.line_y1 = v[1];
                d.line_x2 = v[3]; d.line_y2 = v[4];
                d.line_z1 = v[2]; d.line_z2 = v[5];
                d.model_slot = -1;
                d.target_tri = -1;   // exits carry no triangle id â€” the
                                     // route builder point-locates them
            }
        }

        // People + Save points (v2.15/v2.16): every non-player model
        // standing on the walkmesh. A model is stored as a degenerate line
        // (both vertices = its position) so the shared nearest-point math
        // needs no special case. Off-mesh models (triangle_id < 0: hidden,
        // despawned, or scripted-away) are skipped.
        //
        // NAMES (v2.16): the raw model-loader section supplies each model's
        // descriptive .char label ("shinra hei", "ballet") via
        // FieldModelLabel; duplicates get " 2"/" 3" ordinals in slot order
        // (like the battle "MP A"/"MP B" letters). Parse failure falls back
        // to "Person N" by model slot. A label containing "save" classifies
        // the model as a SAVE POINT â€” originally a heuristic, CONFIRMED
        // game-wide by the v2.18 offline flevel catalog ("fieldbg saveicn"
        // Ã—57 is the only save label in all 720 fields). Item props
        // (chests, materia, pickups, keys) classify into the ITEMS
        // category the same way â€” catalog evidence at the classification
        // block in pass 1 below. v2.15.2 note kept for history: the
        // character_id (+0x6C) naming idea was live-DISPROVED (an NPC read
        // as "Red XIII") â€” never name from that field.
        if (category == CAT_ALL || category == CAT_PEOPLE ||
            category == CAT_SAVE || category == CAT_ITEMS) {
            // The array span was not fully validated above (only the
            // player's element) â€” validate every element this walk reads.
            const uint32_t n_walk = (nmod < 32u) ? nmod : 32u;
            const bool span_ok = IsReadableSpan(
                reinterpret_cast<const void*>(arr),
                n_walk * FF7Addr::FIELD_EVENT_DATA_STRIDE);

            // Pass 1: labels/classification for EVERY model, eligibility
            // and positions for on-mesh ones. Labels and class are
            // assigned regardless of eligibility (v2.18.2): the ordinal
            // pass counts by label over ALL labeled models so a collected
            // pickup's despawn cannot rename its surviving sibling
            // ("Item 2" stays "Item 2" after "Item" is taken â€” the
            // identity-stability rule; the review confirmed the old
            // eligible-only counting silently renumbered). Corollary: a
            // never-on-mesh labeled model still reserves its ordinal, so a
            // field can list "guard 2" with no "guard" â€” accepted, slot
            // order IS the identity.
            bool       eligible[32] = {};
            ModelClass cls[32]      = {};
            bool       is_open[32]  = {};   // chests only: lid state
            bool       talk_off[32] = {};   // TLKON disabled (v2.26)
            int16_t    ex[32], ey[32];
            int16_t    ez[32];              // height (v2.23, layer locates)
            int16_t    etri[32];            // live triangle id (v2.22): the
                                            // route's exact goal node
            wchar_t    labels[32][24] = {};
            for (uint16_t m = 0; span_ok && m < nmod && m < 32; ++m) {
                if (m == pmid)
                    continue;
                const uint8_t* me = reinterpret_cast<const uint8_t*>(
                    arr + m * FF7Addr::FIELD_EVENT_DATA_STRIDE);
                const int32_t* mpos = reinterpret_cast<const int32_t*>(
                    me + FF7Addr::FIELD_EVENT_MODEL_POS);
                const int16_t tri = *reinterpret_cast<const int16_t*>(
                    me + FF7Addr::FIELD_EVENT_TRIANGLE_ID);
                const int32_t mx = mpos[0] >> 12;
                const int32_t my = mpos[1] >> 12;

                // v2.30.45: entity id (for the prop-catalog lookup) and
                // the VISI visibility byte (+0x62). Provenance: the VISI
                // opcode handler (0x618A01) writes its operand here, and
                // the CHAR bind handler stores 1 at 0x6143D2 â€” every
                // bound model STARTS visible, so 0 can only mean a script
                // hid it (both disasm'd 2026-07-31; see FIELD_EVENT_VISIBLE
                // in ff7_addresses.h). Pickup scripts hide collected
                // items exactly this way (offline proof: nmkin_3 'po0' /
                // nmkin_5 'mtr' talk scripts are LOOT+VISI â€”
                // ff7_prop_interact_catalog.py).
                const uint8_t ent_id = *reinterpret_cast<const uint8_t*>(
                    me + FF7Addr::FIELD_EVENT_ENTITY_ID);
                const uint8_t vis = *reinterpret_cast<const uint8_t*>(
                    me + FF7Addr::FIELD_EVENT_VISIBLE);

                std::wstring lbl;
                const bool have_lbl = FieldModelLabel(m, fname, lbl);

                if (Config::Get().debug_log) {
                    // col = live collision radius (+0x72, confirmed
                    // v2.30.24 â€” the rc6E/rc70 candidates are retired,
                    // both rejected by the 2026-07-25 dump).
                    char dbg[224];
                    // sol = SOLID-OFF byte (v2.30.81): logged so a play
                    // log shows each model's live tangibility -- the
                    // Echo-S station report could not be diagnosed
                    // without it (modded scripts may hide people
                    // without clearing solidity, or vice versa).
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] NAV person m=%u tri=%d ent=%u talk=%d "
                        "col=%d vis=%u sol=%u pos=(%ld,%ld) label='%ls'",
                        m, tri, ent_id,
                        *reinterpret_cast<const int16_t*>(me + FF7Addr::FIELD_EVENT_TALK_RADIUS),
                        *reinterpret_cast<const int16_t*>(me + FF7Addr::FIELD_EVENT_COLLISION_RADIUS),
                        vis,
                        me[FF7Addr::FIELD_EVENT_SOLID_OFF],
                        static_cast<long>(mx), static_cast<long>(my),
                        have_lbl ? lbl.c_str() : L"(none)");
                    Log::Write(dbg);
                }

                if (have_lbl) {
                    // One classifier decides class AND spoken base name
                    // (v2.18.2 â€” see ClassifyModelLabel for the catalog
                    // evidence). The friendly name replaces the label so
                    // the ordinal pass yields "Chest 2", "Materia 3".
                    // People (no friendly name) get the v2.20 dev-label
                    // translation instead: romaji -> English, character
                    // words -> live savemap names. Translation runs BEFORE
                    // the ordinal pass, so duplicates group on the SPOKEN
                    // name ("man", "man 2" â€” even when the dev names
                    // differed only by their meaningless digit suffixes).
                    const wchar_t* friendly = nullptr;
                    cls[m] = ClassifyModelLabel(lbl, &friendly);
                    // v2.30.45: resurrect talk-scripted scenery as a
                    // DEVICE (button/lever/valve). The offline catalog is
                    // keyed by (field, script entity) â€” see MC_PROP's
                    // enum comment. Only scenery consults it: everything
                    // else is already browsable somewhere.
                    if (cls[m] == MC_SCENERY && field_id > 0 &&
                        FF7PropCatalog::Find(
                            static_cast<uint16_t>(field_id), ent_id))
                        cls[m] = MC_PROP;
                    wcsncpy_s(labels[m],
                              friendly ? friendly
                                       : TranslateDevLabel(lbl).c_str(),
                              _TRUNCATE);
                    if (cls[m] == MC_CHEST) {
                        // Chest lid state (v2.18.1, tightened v2.18.2):
                        // opened = lid animation held AT its final frame â€”
                        // lastFrame != 0 AND currentFrame == lastFrame<<4
                        // (the subframe scale both confirmed states showed:
                        // 0x1D0 == 0x1D << 4 after settle AND after field
                        // re-entry; see ff7_addresses.h state matrix). The
                        // extra currentFrame term keeps a non-lid animation
                        // that RETURNS to rest (deny rattle, cutscene pose)
                        // from reading as opened; the residual risk flips
                        // to a missed "opened" â€” the safer direction, a
                        // wasted walk instead of skipped treasure.
                        const int16_t last_frame =
                            *reinterpret_cast<const int16_t*>(
                                me + FF7Addr::FIELD_EVENT_LAST_FRAME);
                        const int16_t cur_frame =
                            *reinterpret_cast<const int16_t*>(
                                me + FF7Addr::FIELD_EVENT_CURRENT_FRAME);
                        is_open[m] = last_frame != 0 &&
                            cur_frame == static_cast<int16_t>(last_frame << 4);
                    }
                }

                if (tri < 0)
                    continue;   // off the walkmesh = not a reachable target

                // v2.30.19: PARKED-model filter. Models a scene hasn't
                // placed yet sit at EXACTLY (0,0) with triangle id 0 â€”
                // the 2026-07-23 hideout log showed Tifa (upstairs at the
                // time), the camera dummy, and a not-yet-granted materia
                // all with this exact signature, while every VISIBLE
                // model had a nonzero position (three of them also read
                // tri=0, which is why tri alone can't tell â€” 0 is a valid
                // triangle id, only the tri==0 AND pos==(0,0) combination
                // marks "parked"). Listing them produced unreachable
                // ghost "people"/"items". The scan re-runs continuously,
                // so the moment the script actually places the model it
                // gains a real position and appears â€” hiding is dynamic,
                // not permanent.
                if (tri == 0 && mx == 0 && my == 0)
                    continue;

                // v2.30.45: a hidden pickup/device is GONE for the player
                // (tester report: collected items stayed listed all
                // visit). Placed AFTER the label/ordinal assignment so a
                // taken "Item" still reserves its ordinal and "Item 2"
                // keeps its name (v2.18.2 identity-stability rule).
                // v2.30.81: extended to PEOPLE -- the follow-up evidence
                // the v2.30.45 deferral asked for arrived in the
                // 2026-08-04 station log: hidden soldiers (vis=0, the
                // pair the intro scene removes) were browsable as
                // "Shinra soldier 1/2, talk disabled" on a visibly empty
                // platform, and one was named as blocking the exit. A
                // person a sighted player cannot see is not a
                // destination. List flap is not a regression: entries
                // appearing/disappearing as scenes show/hide people IS
                // the visible truth, and the ordinal pass (which counts
                // ALL labeled models, eligible or not) keeps every
                // returning person's spoken name stable.
                if ((cls[m] == MC_ITEM || cls[m] == MC_PROP ||
                     cls[m] == MC_PERSON) && vis == 0)
                    continue;

                eligible[m] = true;
                ex[m] = static_cast<int16_t>(mx);
                ey[m] = static_cast<int16_t>(my);
                ez[m] = static_cast<int16_t>(mpos[2] >> 12);
                etri[m] = tri;
                // v2.26: TLKON state â€” see FIELD_EVENT_TALK_OFF for the
                // derivation and the Jessie incident that motivated it.
                talk_off[m] = *reinterpret_cast<const uint8_t*>(
                    me + FF7Addr::FIELD_EVENT_TALK_OFF) != 0;
            }

            // Pass 2: duplicate-label counts (so "shinra guard" Ã—3 becomes
            // "shinra guard", "shinra guard 2", "shinra guard 3").
            // Counted over ALL labeled models, eligible or not (v2.18.2)
            // â€” despawned pickups keep reserving their ordinal so
            // survivors are never renamed.
            // Pass 3: emit destinations in slot order. The category
            // filter is ONE comparison against the classâ†’category map â€”
            // mutual exclusion is structural, not hand-maintained
            // (v2.18.2; the old sv/it boolean chain was the review's
            // drift-risk finding).
            for (uint16_t m = 0; m < 32; ++m) {
                if (!eligible[m])
                    continue;
                // v2.30.18: scenery is browsable NOWHERE â€” not even All.
                // A sighted player doesn't "navigate to" the cash register
                // or the camera dummy; listing them (usually with no
                // walkable path â€” they sit inside furniture) is pure noise.
                if (cls[m] == MC_SCENERY)
                    continue;
                if (category != CAT_ALL &&
                    category != CategoryForModelClass(cls[m]))
                    continue;

                // Ordinal among same-label models before this slot.
                int ordinal = 1, total = 0;
                if (labels[m][0]) {
                    for (uint16_t k = 0; k < 32; ++k) {
                        if (!labels[k][0])
                            continue;
                        if (wcscmp(labels[k], labels[m]) == 0) {
                            ++total;
                            if (k < m) ++ordinal;
                        }
                    }
                }

                NavDest& d = dests[n_dests++];
                const wchar_t* base = labels[m][0] ? labels[m] : nullptr;
                if (base && total > 1)
                    _snwprintf_s(d.name, _countof(d.name), _TRUNCATE,
                                 L"%ls %d", base, ordinal);
                else if (base)
                    _snwprintf_s(d.name, _countof(d.name), _TRUNCATE,
                                 L"%ls", base);
                else
                    _snwprintf_s(d.name, _countof(d.name), _TRUNCATE,
                                 L"Person %u", m + 1u);
                // Lid state is a SUFFIX after the ordinal, never part of
                // the label: ordinals group on the bare "Chest" label, so
                // "Chest 2" keeps its number when "Chest 1" gets opened
                // (identity-stability rule, same as exits/people).
                if (is_open[m])
                    wcsncat_s(d.name, _countof(d.name), L", opened",
                              _TRUNCATE);
                // v2.26: definitive "cannot talk right now" marker (the
                // TLKON-off byte â€” the Jessie ladder-tutorial incident:
                // the pathfinder placed the player 17 units from her,
                // inside her talk radius, and OK did nothing because her
                // dialog was script-disabled). People only, and only the
                // DISABLED side: an enabled byte does not guarantee the
                // entity has a talk script, so silence stays honest.
                if (cls[m] == MC_PERSON && talk_off[m])
                    wcsncat_s(d.name, _countof(d.name), L", talk disabled",
                              _TRUNCATE);
                // v2.30.45: devices say what they are â€” the label alone
                // ("nmkdr 3") reads like scenery; the suffix is the cue
                // that OK does something here. Same suffix philosophy as
                // the line catalog's ", press OK".
                if (cls[m] == MC_PROP)
                    wcsncat_s(d.name, _countof(d.name), L", device",
                              _TRUNCATE);
                d.line_x1 = d.line_x2 = ex[m];
                d.line_y1 = d.line_y2 = ey[m];
                d.line_z1 = d.line_z2 = ez[m];
                d.model_slot = m;
                d.target_tri = etri[m];
            }
        }

        // LINE trigger zones (v2.17): script-created lines â€” ladders,
        // elevators, touch/cross zones. Stored in the engine's static line
        // array (see ff7_addresses.h SECTION 1g for the full derivation:
        // three opcode handlers disassembled, all agreeing on the layout).
        // Disabled lines (LINON 0) are skipped â€” the script has switched
        // that zone off, so walking to it does nothing; this also gives
        // information parity with what the zone would DO for a sighted
        // player right now. Named by the owning entity's dev name
        // ("yubiwa", "svisen1"); slot order is the identity, so "Trigger 3"
        // keeps its number as the player moves, same rule as exits.
        if (category == CAT_ALL || category == CAT_TRIGGERS) {
            const uint16_t n_lines = *reinterpret_cast<const volatile uint16_t*>(
                FF7Addr::FIELD_LINE_COUNT);

            // Entity-name table resolved and span-validated ONCE per
            // build, not per line (v2.18.2 â€” review efficiency finding).
            const uint8_t* ent_table = nullptr;
            uint8_t        ent_count = 0;
            const bool have_names =
                FieldEntityNameTable(&ent_table, &ent_count);

            // Gather first, then emit: names must all be known before
            // duplicate ordinals can be computed (v2.18.2 â€” the review
            // confirmed two same-named lines used to speak identically,
            // which J/L cycling cannot disambiguate by ear).
            struct TrigLine {
                int16_t x1, y1, x2, y2;
                int16_t z1, z2;     // heights (v2.23, layer locates)
                uint8_t line_idx;
                wchar_t name[24];   // translated entity name (v2.20 â€”
                                    // widened from 16 for "AVALANCHE
                                    // member"); empty = fallback
                const FF7LineCatalog::LineInfo* info;  // behavior catalog
                                    // row (v2.30.23), null = unknown
            } tl[FF7Addr::FLINE_MAX];
            int n_tl = 0;

            for (uint32_t i = 0; i < n_lines && i < FF7Addr::FLINE_MAX; ++i) {
                const uint8_t* le = reinterpret_cast<const uint8_t*>(
                    FF7Addr::FIELD_LINE_ARRAY + i * FF7Addr::FLINE_STRIDE);
                if (le[FF7Addr::FLINE_OFF_ENABLED] == 0)
                    continue;
                const int16_t* v = reinterpret_cast<const int16_t*>(le);
                const uint8_t ent = le[FF7Addr::FLINE_OFF_ENTITY];

                TrigLine& t = tl[n_tl++];
                // x1,y1,z1,x2,y2,z2 â€” heights kept since v2.23 (layer
                // location for turn-by-turn); routing itself stays 2D.
                t.x1 = v[0]; t.y1 = v[1]; t.z1 = v[2];
                t.x2 = v[3]; t.y2 = v[4]; t.z2 = v[5];
                t.line_idx = static_cast<uint8_t>(i);
                t.name[0] = L'\0';
                // v2.30.23: what this line DOES, from the offline script
                // catalog â€” keyed by the same (field, owning entity)
                // identity the engine's own line array carries. A field
                // mid-transition can briefly pair the OLD array with the
                // NEW field id; a mismatched key then simply finds no
                // row (or a same-field stale row for one keypress), the
                // identical tradeoff the name lookup above accepts.
                t.info = FF7LineCatalog::Find(
                    static_cast<uint16_t>(field_id), ent);

                // Name only when the engine's own entityâ†’line-slot map
                // agrees this slot belongs to that entity (the LINE
                // handler writes both together). During a field
                // transition the line array can briefly hold the OLD
                // field's entries while the script pointer already serves
                // the NEW field's names â€” the review's cross-field
                // mismatch finding; a stale entry then speaks a
                // plausible-but-wrong name. On mismatch the line stays
                // LISTED (stale geometry for one keypress is the accepted
                // v2.17 tradeoff) but falls back to "Trigger N" instead
                // of an actively wrong name. Also covers an entity that
                // declared LINE twice: the map tracks only its newest
                // slot, so the older one numbers instead.
                const uint8_t mapped_slot =
                    *reinterpret_cast<const volatile uint8_t*>(
                        FF7Addr::FIELD_ENTITY_LINE_SLOT + ent);
                std::wstring ename;
                if (have_names && mapped_slot == i &&
                    EntityNameFromTable(ent_table, ent_count, ent, ename))
                    // v2.20: translate the dev name ("ladd0" -> "ladder
                    // down", "av j" -> "Jessie") before it becomes the
                    // spoken identity; unknown names pass through.
                    wcsncpy_s(t.name, TranslateEntityName(ename).c_str(),
                              _TRUNCATE);

                if (Config::Get().debug_log) {
                    char dbg[160];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] NAV line %u ent=%u map=%u '%ls' "
                        "(%d,%d,%d)-(%d,%d,%d)",
                        i, ent, mapped_slot, t.name,
                        v[0], v[1], v[2], v[3], v[4], v[5]);
                    Log::Write(dbg);
                }
            }

            for (int a = 0; a < n_tl; ++a) {
                // Ordinal among same-named triggers, same scheme as
                // people/items ("ev1", "ev1 2"). "Trigger N" fallbacks
                // are already unique by line number.
                int ordinal = 1, total = 0;
                if (tl[a].name[0]) {
                    for (int k = 0; k < n_tl; ++k) {
                        if (tl[k].name[0] &&
                            wcscmp(tl[k].name, tl[a].name) == 0) {
                            ++total;
                            if (k < a) ++ordinal;
                        }
                    }
                }

                NavDest& d = dests[n_dests++];
                if (tl[a].name[0] && total > 1)
                    _snwprintf_s(d.name, _countof(d.name), _TRUNCATE,
                                 L"%ls %d", tl[a].name, ordinal);
                else if (tl[a].name[0])
                    _snwprintf_s(d.name, _countof(d.name), _TRUNCATE,
                                 L"%ls", tl[a].name);
                else
                    _snwprintf_s(d.name, _countof(d.name), _TRUNCATE,
                                 L"Trigger %u", tl[a].line_idx + 1u);

                // v2.30.23: behavior suffix from the offline catalog â€”
                // the 2026-07-25 hideout lesson (player hunted the way
                // upstairs on a cutscene 'border' line while the real
                // exit was the 'pinball' lift line). A sighted player
                // SEES lift platform vs floor patch; this suffix is that
                // glance: "pinball, exit to Seventh Heaven" / "border,
                // scene". Suffixes state only what the SCRIPTS contain â€”
                // an exit may still be story-gated at any given moment.
                if (tl[a].info != nullptr) {
                    using namespace FF7LineCatalog;
                    const LineInfo* li = tl[a].info;
                    std::wstring sfx;
                    switch (li->kind) {
                    case LK_EXIT:
                    case LK_EXIT_OK: {
                        std::wstring dn;
                        bool explored = true;
                        if (li->dest_field >= 0 &&
                            DestinationName(li->dest_field, dn, &explored)) {
                            sfx = L", exit to ";
                            sfx += dn;
                            if (!explored)
                                sfx += L", unexplored";
                        } else {
                            sfx = L", exit";   // multi/unknown destination
                        }
                        if (li->kind == LK_EXIT_OK)
                            sfx += L", press OK";
                        break;
                    }
                    case LK_CLIMB:
                        // Ladder names already say "ladder N" (v2.30.67)
                        // â€” only unnamed/odd climbs need the word.
                        // v2.30.68: save-pad lines also classify CLIMB
                        // (script chains reach a LADER) but must not say
                        // it â€” the name is the truth (3rd-run report).
                        if (wcsstr(d.name, L"ladder") == nullptr &&
                            wcsstr(d.name, L"save") == nullptr)
                            sfx = L", climb";
                        break;
                    case LK_OK:
                        sfx = L", press OK";
                        break;
                    case LK_SCENE:
                        sfx = L", scene";
                        break;
                    case LK_INERT:
                        sfx = L", inactive";
                        break;
                    default:
                        break;
                    }
                    if (!sfx.empty())
                        wcsncat_s(d.name, _countof(d.name), sfx.c_str(),
                                  _TRUNCATE);
                }
                d.line_x1 = tl[a].x1; d.line_y1 = tl[a].y1;
                d.line_x2 = tl[a].x2; d.line_y2 = tl[a].y2;
                d.line_z1 = tl[a].z1; d.line_z2 = tl[a].z2;
                d.model_slot = -1;
                d.target_tri = -1;   // LINE zones are point-located like exits
            }

            // v2.30.46: hand-curated STORY HOTSPOTS â€” interaction spots
            // the engine exposes NOTHING for: no LINE in the runtime
            // array, no prop model, because the whole interaction is an
            // NPC's script reacting to the player (the defining case:
            // elevtr1's reactor elevator switch, where "Switch On." is
            // JESSIE's script â€” MES text 46 in av_j's slots, traced
            // 2026-08-01 after the tester screenshots; the panel spot
            // merely sits inside her talk radius). Players hunt for a
            // "button" destination the browser cannot derive from any
            // engine state, so these few entries are curated by hand
            // from played evidence ONLY â€” the same never-guess rule as
            // the v2.30.18 non-fieldbg scenery list. Listed always
            // (story-gating a curated spot would need the story var,
            // which is exactly the guessing this list refuses to do).
            // Table hoisted to file scope in v2.30.66 so journey legs can
            // consult it too (declaration above BuildJourneyLegDest).
            for (const StoryHotspot& h : kStoryHotspots) {
                if (h.field_id != static_cast<uint16_t>(field_id))
                    continue;
                if (n_dests >= static_cast<int>(_countof(dests)))
                    break;
                NavDest& d = dests[n_dests++];
                _snwprintf_s(d.name, _countof(d.name), _TRUNCATE, L"%ls",
                             h.name);
                d.line_x1 = d.line_x2 = h.x;
                d.line_y1 = d.line_y2 = h.y;
                d.line_z1 = d.line_z2 = h.z;
                d.model_slot = -1;
                d.target_tri = -1;   // point-located like exits/lines
            }
        }

        // ---- Places (v2.30.65): cross-field journey targets ---------------
        // Every VISITED place (the v2.25 caption cache â€” parity with a
        // sighted player's memory of where they have been) reachable on
        // the journey graph from here, nearest-first by screen count.
        // Several fields can share one caption ("Sector 1 Station"); only
        // the nearest of each spoken name is listed â€” J/L cycling cannot
        // disambiguate identical names by ear, and "take me to the nearest
        // one" is the right reading of a spoken duplicate anyway. NOT in
        // CAT_ALL: places are not positions on this screen, and mixing
        // them into the positional list would break its distance idiom.
        if (category == CAT_PLACES) {
            std::vector<int16_t> pdist, pprev;
            FieldGraphBFS(field_id, pdist, pprev);
            struct PlaceTmp { int16_t id; int16_t hops; };
            std::vector<PlaceTmp> places;
            for (int id = 1; id < FF7FieldNames::kCount; ++id) {
                if (id == field_id || !g_places[id][0] || pdist[id] < 0)
                    continue;
                places.push_back({static_cast<int16_t>(id), pdist[id]});
            }
            std::sort(places.begin(), places.end(),
                      [](const PlaceTmp& a, const PlaceTmp& b) {
                          return a.hops != b.hops ? a.hops < b.hops
                                                  : a.id < b.id;
                      });
            // v2.30.66: save-point fields (offline saveicn table) list as
            // their own entries ("Mako Reactor 1, save point, 7 screens")
            // and dedupe separately from the plain caption -- the run-2
            // report: every reactor screen shares one caption, so the
            // pre-boss save room was untargetable. The spoken BASE
            // (caption + optional ", save point") is the dedupe identity;
            // nearest of each base wins (the list is sorted nearest-first).
            std::vector<std::wstring> used_bases;
            for (const PlaceTmp& p : places) {
                if (n_dests >= static_cast<int>(_countof(dests)))
                    break;
                std::wstring base = g_places[p.id];
                const bool is_save = FF7FieldGraph::HasSavePoint(
                    static_cast<uint16_t>(p.id));
                if (is_save)
                    base += L", save point";
                bool dup = false;
                for (const std::wstring& u : used_bases)
                    if (u == base) { dup = true; break; }
                if (dup)
                    continue;   // nearest same-name field already listed
                used_bases.push_back(base);
                NavDest& d = dests[n_dests++];
                _snwprintf_s(d.name, _countof(d.name), _TRUNCATE,
                             L"%ls, %d %ls", base.c_str(),
                             static_cast<int>(p.hops),
                             p.hops == 1 ? L"screen" : L"screens");
                d.line_x1 = d.line_y1 = d.line_x2 = d.line_y2 = 0;
                d.line_z1 = d.line_z2 = 0;
                d.model_slot = -1;
                d.target_tri = -1;
                d.place_field = p.id;
            }
        }

        // ---- path filter (v2.30.87, Shift+\ or Shift+P) -------------------
        // Applied AFTER the build so names/ordinals are already assigned
        // (identity stability: hiding "Exit 1" never renames "Exit 2").
        // Places is exempt: that list is ALREADY reachable-only (the
        // FieldGraphBFS build drops pdist<0 fields), and its entries are
        // whole fields, not points on this screen's walkmesh.
        int n_hidden = 0;
        if (path_filter && category != CAT_PLACES && n_dests > 0)
            FilterReachableDests(dests, n_dests,
                                 static_cast<float>(px),
                                 static_cast<float>(py),
                                 static_cast<float>(pz),
                                 player_tri, arr, n_hidden);

        // ---- layer filter (v2.30.88, Shift+;) -----------------------------
        // Runs AFTER the path filter so each counter reports what ITS pass
        // hid (order does not change the surviving set -- both are pure
        // per-entry predicates). Same CAT_PLACES exemption: place entries
        // are whole fields with no height on this screen (their line_z is
        // a builder-zeroed placeholder, not a position).
        int n_layer_hidden = 0;
        if (layer_filter && category != CAT_PLACES && n_dests > 0)
            FilterSameLayerDests(dests, n_dests,
                                 static_cast<float>(pz), n_layer_hidden);

        if (selection >= n_dests)
            selection = (n_dests > 0) ? n_dests - 1 : 0;

        // Announce helpers ---------------------------------------------------
        // "No destinations with a path." / "on this level." (vs the plain
        // "No destinations.") tells the player the emptiness is a FILTER's
        // doing, not an empty room â€” without it, a filtered-empty list is
        // indistinguishable from a field with nothing in it. ("Level" is
        // the mod's spoken word for a layer everywhere else -- "on another
        // level" in journey/route speech -- so the emptiness message uses
        // it too; "Layer filter" stays the feature's NAME because that is
        // what the keys file calls it.)
        const auto no_dest_text = [&]() {
            if (n_hidden > 0 && n_layer_hidden > 0)
                return L"No destinations with a path on this level.";
            if (n_layer_hidden > 0)
                return L"No destinations on this level.";
            return n_hidden > 0 ? L"No destinations with a path."
                                : L"No destinations.";
        };
        const auto speak_category = [&]() {
            wchar_t msg[112];
            _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"%ls. %d %ls.%ls%ls",
                         kCategoryNames[category], n_dests,
                         n_dests == 1 ? L"destination" : L"destinations",
                         n_hidden > 0 ? L" Path filter on." : L"",
                         n_layer_hidden > 0 ? L" Layer filter on." : L"");
            TTS::Speak(msg, /*interrupt=*/true);
        };
        const auto speak_selection = [&](bool with_position) {
            if (n_dests == 0) {
                TTS::Speak(no_dest_text(), /*interrupt=*/true);
                return;
            }
            wchar_t msg[128];  // name is up to 95 chars since v2.30.66
            if (with_position)
                _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"%ls. %d of %d.",
                             dests[selection].name, selection + 1, n_dests);
            else
                _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"%ls",
                             dests[selection].name);
            TTS::Speak(msg, /*interrupt=*/true);
            // Wandering cue: speech is async, so the beep overlaps the
            // start of the announcement instead of delaying it.
            if (is_wandering(dests[selection].model_slot))
                Tones::Play(WANDER_BEEP_HZ, WANDER_BEEP_MS);
        };

        // Filter toggle: one utterance carrying the new state AND the
        // count under it ("Path filter on. Exits. 2 destinations.") â€” the
        // count is the immediate proof of what the filter just did. One
        // block for both filters: Shift+\ and Shift+; landing on the same
        // 50ms poll is legal input, and two separate early-continue blocks
        // would silently swallow the second toggle's announcement.
        if (announce_filter || announce_layer) {
            wchar_t msg[144];
            wchar_t states[48] = L"";
            if (announce_filter)
                _snwprintf_s(states, _countof(states), _TRUNCATE,
                             L"Path filter %ls. ",
                             path_filter ? L"on" : L"off");
            if (announce_layer)
                _snwprintf_s(states + wcslen(states),
                             _countof(states) - wcslen(states), _TRUNCATE,
                             L"Layer filter %ls. ",
                             layer_filter ? L"on" : L"off");
            _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                         L"%ls%ls. %d %ls.",
                         states,
                         kCategoryNames[category], n_dests,
                         n_dests == 1 ? L"destination" : L"destinations");
            TTS::Speak(msg, /*interrupt=*/true);
            if (Config::Get().debug_log) {
                char dbg[128];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] NAV filters path=%s layer=%s shown=%d "
                    "path_hidden=%d layer_hidden=%d",
                    path_filter ? "on" : "off",
                    layer_filter ? "on" : "off",
                    n_dests, n_hidden, n_layer_hidden);
                Log::Write(dbg);
            }
            continue;
        }

        // Category changes were applied BEFORE the list build (v2.15.2 fix)
        // â€” only the announcement remains to be made here, with the count
        // of the list actually built for the new category.
        if (announce_cat) {
            speak_category();
            if (journey_cancelled)
                // Second utterance of one action QUEUES (v2.30.51 rule).
                TTS::Speak(L"Journey ended.", /*interrupt=*/false);
            continue;
        }
        if (act_prev_dest || act_next_dest) {
            if (n_dests == 0) {
                TTS::Speak(no_dest_text(), /*interrupt=*/true);
                continue;
            }
            selection += act_next_dest ? 1 : -1;
            if (selection < 0) selection = n_dests - 1;
            if (selection >= n_dests) selection = 0;
            speak_selection(/*with_position=*/true);
            continue;
        }
        if (act_announce) {
            speak_selection(/*with_position=*/false);
            continue;
        }

        // ---- directions to the selected destination (\ or P) -------------
        // v2.30.68: an ACTIVE journey owns the directions key. The field
        // change resets category/selection (v2.14 behavior), so after a
        // transition \ used to route to whatever sat first in "All" --
        // the third run's report ("the wrong thing selected"). While a
        // journey is live, \ in any NON-Places category speaks the
        // current leg; picking a different Places entry retargets; and
        // Shift+K remains the one way OFF the journey (it also restores
        // \ to plain selection directions).
        NavDest journey_leg;
        bool leg_ready = false;
        if (journey_active && field_id == journey_target &&
            category != CAT_PLACES) {
            // v2.30.69 last mile: the journey now points INSIDE this
            // field. Route to the live save icon through the same NavDest
            // flow every selection uses (turn-by-turn, level journeys,
            // body cautions) so \ speaks exactly what the Save-points
            // browser entry would -- one vocabulary. The third-run log is
            // the spec: "Save point: on another level. First take ladder
            // 1, ..." is what got the player to the pad by hand.
            // v2.30.73 (review): the branch now also catches the FIND
            // window (slot not latched yet), and a bad read is TRANSIENT
            // -- it re-opens the scan instead of cancelling a journey the
            // player spent screens on. Every other read guard in this
            // thread skips the poll; \ additionally owes an answer.
            bool built = false;
            if (journey_save_slot >= 0 &&
                BuildModelPointDest(arr, nmod, journey_save_slot,
                                    journey_leg)) {
                _snwprintf_s(journey_leg.name,
                             _countof(journey_leg.name), _TRUNCATE,
                             L"Journey to %ls. Save point",
                             journey_name);
                built = true;
                leg_ready = true;
            }
            if (!built) {
                journey_save_slot      = -1;
                journey_lastmile_tries = 60;   // (re)open the find window
                TTS::Speak(L"Save point not found right now. Ask again.",
                           /*interrupt=*/true);
                continue;
            }
        } else if (journey_active && category != CAT_PLACES) {
            std::vector<int16_t> jdist, jprev;
            FieldGraphBFS(field_id, jdist, jprev);
            const int nxt = FieldGraphNextHop(field_id, journey_target,
                                              jprev, jdist);
            if (nxt < 0) {
                TTS::Speak(L"No known route from here. Journey ended.",
                           /*interrupt=*/true);
                journey_active = false;
                continue;
            }
            if (!BuildJourneyLegDest(field_id, nxt, hdr, journey_leg)) {
                TTS::Speak(L"The way there is not available here yet.",
                           /*interrupt=*/true);
                continue;
            }
            wchar_t wrapped[96];
            _snwprintf_s(wrapped, _countof(wrapped), _TRUNCATE,
                         L"Journey to %ls, %d %ls. Next, %ls",
                         journey_name,
                         static_cast<int>(jdist[journey_target]),
                         jdist[journey_target] == 1 ? L"screen" : L"screens",
                         journey_leg.name);
            wcsncpy_s(journey_leg.name, wrapped, _TRUNCATE);
            leg_ready = true;
        }

        if (!leg_ready && n_dests == 0) {
            TTS::Speak(no_dest_text(), /*interrupt=*/true);
            continue;
        }

        // v2.30.65: on a Places selection, \ STARTS (or retargets) a
        // journey and the thing to route to is the FIRST LEG's exit on
        // this field, not the place itself (which is screens away). The
        // leg NavDest then flows through the unchanged directions code
        // below â€” turn-by-turn, journeys-within-field, body cautions and
        // all â€” exactly as if the player had selected that exit by hand.
        if (!leg_ready && category == CAT_PLACES) {
            const int16_t target = dests[selection].place_field;
            std::vector<int16_t> jdist, jprev;
            FieldGraphBFS(field_id, jdist, jprev);
            const int nxt = FieldGraphNextHop(field_id, target, jprev, jdist);
            if (nxt < 0) {
                // Should not happen (the list only offers reachable
                // places) â€” but the field can change under a queued press.
                TTS::Speak(L"No known route from here.", /*interrupt=*/true);
                continue;
            }
            if (!BuildJourneyLegDest(field_id, nxt, hdr, journey_leg)) {
                TTS::Speak(L"The way there is not available here yet.",
                           /*interrupt=*/true);
                continue;
            }
            journey_active = true;
            journey_target = target;
            journey_save_slot = -1;   // retarget: any prior last mile is
                                      // void; the new arrival re-finds it
            journey_lastmile_tries = 0;
            wcsncpy_s(journey_name, g_places[target], _TRUNCATE);
            // Fold the journey context into the leg's spoken name so the
            // whole thing is ONE utterance ("Journey to Sector 1 Station,
            // 3 screens. First, To nmkin 2: up 4 seconds...").
            wchar_t wrapped[96];
            _snwprintf_s(wrapped, _countof(wrapped), _TRUNCATE,
                         L"Journey to %ls, %d %ls. First, %ls",
                         journey_name,
                         static_cast<int>(jdist[target]),
                         jdist[target] == 1 ? L"screen" : L"screens",
                         journey_leg.name);
            wcsncpy_s(journey_leg.name, wrapped, _TRUNCATE);
            if (Config::Get().debug_log) {
                char dbg[128];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] JOURNEY start at=%d target=%d hops=%d next=%d",
                    static_cast<int>(field_id), static_cast<int>(target),
                    static_cast<int>(jdist[target]), nxt);
                Log::Write(dbg);
            }
            leg_ready = true;
        }
        const NavDest& d = leg_ready ? journey_leg : dests[selection];

        // Nearest point on the exit line segment to the player.
        const float ex = static_cast<float>(d.line_x2 - d.line_x1);
        const float ey = static_cast<float>(d.line_y2 - d.line_y1);
        const float wx = static_cast<float>(px - d.line_x1);
        const float wy = static_cast<float>(py - d.line_y1);
        const float len2 = ex * ex + ey * ey;
        float t = (len2 > 0.0f) ? ((wx * ex + wy * ey) / len2) : 0.0f;
        if (t < 0.0f) t = 0.0f;
        if (t > 1.0f) t = 1.0f;
        const float dx = (d.line_x1 + t * ex) - static_cast<float>(px);
        const float dy = (d.line_y1 + t * ey) - static_cast<float>(py);
        const float dist = sqrtf(dx * dx + dy * dy);

        // World bearing 0 = +Y axis, clockwise toward +X.
        const float world_deg = atan2f(dx, dy) * (180.0f / 3.14159265f);

        // Screen/d-pad angle. FULLY CONFIRMED 2026-07-13 in two steps:
        // calibration walkabout (md1stin, control_dir=124 -> 174.4Â°:
        // pressing Up moved the player at world bearing 5.6Â° = 180Â° âˆ’
        // control_deg exactly, Down at 185.6Â°) fixed the rotation â€”
        // control_direction is the world bearing of screen-DOWN â€” and the
        // follow-up play test confirmed left/right land correctly, so the
        // mapping is a pure rotation with no mirror. (The first guess,
        // world âˆ’ control, was 180Â° off: "down" for a dead-ahead exit.)
        const float input_deg = world_deg + control_deg - 180.0f;

        if (Config::Get().debug_log) {
            char dbg[224];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] NAV dir %ls line=(%d,%d)-(%d,%d) player=(%d,%d) "
                "dist=%.0f world_deg=%.1f ctrl=%u dir=%ls",
                d.name, d.line_x1, d.line_y1, d.line_x2, d.line_y2,
                px, py, dist, world_deg, static_cast<unsigned>(control_dir),
                DpadSectorName(input_deg));
            Log::Write(dbg);
        }

        // ---- turn-by-turn route (v2.22, direction_style=turns) -----------
        // Plans a real walkmesh route to the SAME target point the
        // straight-line style aims at (nearest point of the line, computed
        // above; height interpolated along the line the same way). Outcomes:
        //   SPOKEN_ROUTE â€” the route is the announcement, done;
        //   NO_PATH      â€” mesh healthy but the target is graph-unreachable:
        //                  usually ANOTHER LEVEL â€” try the v2.23 journey
        //                  planner ("first take ladder up..."); only when
        //                  that also finds no connector chain, fall back to
        //                  straight-line + an explicit "no walkable path"
        //                  prefix (the FF4 mod's out-of-range behavior);
        //   UNAVAILABLE  â€” mesh unreadable or failed its self-guards:
        //                  silent straight-line fallback.
        // v2.30.25: how far short of the target the walk may stop â€” a
        // person is reached at their TALK RADIUS (read live; floor 20 so
        // talk=0/1 models still get approached, cap 90). v2.30.26: OR at
        // body contact, whichever is larger â€” the same behaviorally
        // proven rule as the proximity chirp (Barret: contact 80 > talk
        // 70, and talking at contact works). Exits/lines keep 0: those
        // must be stepped on. Shared with the path filter's rule 4 since
        // v2.30.87 (ModelTargetReach) so the two can't drift.
        const float target_reach = ModelTargetReach(arr, d.model_slot);

        const wchar_t* fallback_prefix = L"";
        bool spoke_route = false;
        if (Config::Get().turn_by_turn) {
            const float fpx = static_cast<float>(px);
            const float fpy = static_cast<float>(py);
            const float fpz = static_cast<float>(pz);
            const float ftx = fpx + dx;
            const float fty = fpy + dy;
            const float ftz = d.line_z1 + t * (d.line_z2 - d.line_z1);
            std::wstring route;
            const RouteOutcome ro = BuildTurnByTurnRoute(
                fpx, fpy, fpz, player_tri, ftx, fty, ftz,
                d.target_tri, control_deg, d.model_slot, target_reach,
                route);
            if (ro == RouteOutcome::SPOKEN_ROUTE) {
                // v2.30.83: no body caution -- characters cannot block
                // the player (corrected-model block above
                // WallBumpThread), so the route is the whole truth.
                std::wstring rmsg(d.name);
                rmsg += L": ";
                rmsg += route;
                rmsg += L'.';
                TTS::Speak(rmsg, /*interrupt=*/true);
                spoke_route = true;
            } else if (ro == RouteOutcome::NO_PATH) {
                // v2.30.83: STORY-GATE check first. If the target would
                // be reachable with every IDLCK lock open, the honest
                // answer is "closed for now" -- a script gate a story
                // beat will open -- not a connector journey or an
                // "off the walkable area" detour toward a shut door.
                if (ReachableIgnoringLocks(fpx, fpy, fpz, player_tri,
                                           ftx, fty, ftz, d.target_tri)) {
                    std::wstring rmsg(d.name);
                    rmsg += L": the way there is closed for now.";
                    TTS::Speak(rmsg, /*interrupt=*/true);
                    spoke_route = true;
                    if (Config::Get().debug_log) {
                        char dbg[160];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                            "[FF7Access] NAV route: lock-blocked '%ls' "
                            "player=(%.0f,%.0f)",
                            d.name, fpx, fpy);
                        Log::Write(dbg);
                    }
                } else {
                    std::wstring jmsg;
                    if (BuildJourneySpeech(fpx, fpy, fpz, player_tri,
                                           ftx, fty, ftz, d.target_tri,
                                           control_deg, d.name, jmsg)) {
                        TTS::Speak(jmsg, /*interrupt=*/true);
                        spoke_route = true;
                    } else {
                        // v2.30.25: no journey either â€” the target
                        // stands OFF the walkable floor (Biggs on the
                        // hideout crates). Route to the nearest
                        // reachable point instead of a bare
                        // straight-line shrug; the talk radius covers
                        // the last gap.
                        std::wstring nroute;
                        int   nsec = -1;
                        float nlen = 0.0f;
                        if (BuildTurnByTurnRoute(fpx, fpy, fpz,
                                player_tri, ftx, fty, ftz, d.target_tri,
                                control_deg, d.model_slot, target_reach,
                                nroute, &nsec, &nlen,
                                /*to_nearest=*/true)
                            == RouteOutcome::SPOKEN_ROUTE) {
                            std::wstring rmsg(d.name);
                            rmsg += L", off the walkable area: ";
                            rmsg += nroute;
                            rmsg += L'.';
                            TTS::Speak(rmsg, /*interrupt=*/true);
                            spoke_route = true;
                        } else {
                            fallback_prefix = L"No walkable path found. ";
                        }
                    }
                }
            }
        }

        // ---- straight-line announcement (style "line", and the fallback) --
        if (!spoke_route) {
            wchar_t msg[192];
            const int secs = static_cast<int>(
                dist / FF7Addr::WALKMESH_UNITS_PER_SEC + 0.5f);
            if (secs < 1 && dist < 1.0f)
                // v2.30.73 (review): standing ON the target -- with
                // zero displacement atan2f(0,0) manufactures a sector
                // from control_deg alone, a confident wrong direction.
                // Same degenerate guard as the route builder's early
                // return, so the two styles agree here too.
                _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                             L"%ls%ls: very close.",
                             fallback_prefix, d.name);
            else if (secs < 1)
                // v2.30.72: same word order as the route builder --
                // proximity first, then the facing (user-specified).
                _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                             L"%ls%ls: very close to the %ls.",
                             fallback_prefix, d.name, DpadSectorName(input_deg));
            else
                _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                             L"%ls%ls: %ls, %d %ls.",
                             fallback_prefix, d.name, DpadSectorName(input_deg),
                             secs, secs == 1 ? L"second" : L"seconds");
            // (v2.30.83: the straight-line body caution that lived here
            // was removed with the corrected blocking model --
            // characters do not block the player.)
            TTS::Speak(msg, /*interrupt=*/true);
        }
        // Wandering cue on the directions query too â€” a moving target's
        // direction is a snapshot, and the beep says exactly that.
        if (is_wandering(d.model_slot))
            Tones::Play(WANDER_BEEP_HZ, WANDER_BEEP_MS);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Name-entry screen TTS thread (v2.8).
//
// Speaks the character grid on the "Please enter a name" screen:
//   - on screen open: "Name entry. Current name, Cloud. Cursor on capital A."
//   - on cursor move: the letter now under the cursor ("capital G", "comma")
//   - on letter add (Confirm): echoes the added letter, then spells the
//     whole name ("g. capital C l o u d g")
//   - on letter delete (Cancel): "Deleted g." then spells what remains
// The full-name spell-out after every edit is deliberate: keyboard/controller
// auto-repeat can double a letter without the player noticing, and hearing
// the complete name after each change catches that immediately.
//
// All addresses live-confirmed 2026-07-12 (ff7_name_entry_scan.py +
// ff7_name_entry_verify.py) â€” see ff7_addresses.h name-entry section for the
// full discovery story, including why the buffer base is 0xDD45F0 and why
// 0xDD46F8 is the char index (not a cursor, despite the Echo mod's label).
//
// GATE: GAME_MODE == 6 (name entry, new live-observed value) AND
// NAME_ENTRY_ACTIVE == 1, held for 2 consecutive polls (same streak pattern
// as MenuCursorThread's MENU_OPEN debounce â€” a single stale poll of either
// byte never triggers the announce logic).
//
// WHY WE NEVER PREDICT CURSOR MOVEMENT: the cursor does not wrap at the
// right grid edge â€” it JUMPS to the side panel (player-observed, then
// live-confirmed 2026-07-12). Entering the panel can also CHANGE the ROW
// byte (observed 1 -> 4), and leaving restores the remembered grid column.
// We only ever announce the cell/button the cursor actually landed on, so
// all of these engine quirks are self-correcting.
//
// SIDE PANEL (resolved 2026-07-12): NAME_ENTRY_PANE_FLAG (0x921ED4) is 1
// while the cursor is on the Space/Delete/Select/Default panel, and
// NAME_ENTRY_PANEL_INDEX (0xDD4574) says which button (0-3, wraps).
// Grid-letter announcements are gated on pane_flag == 0 â€” without that
// gate, the ROW change at panel entry would speak a phantom letter.
// Indices 0/1 (Space/Delete) proven by their effect on the name buffer;
// 2/3 (Select/Default) from on-screen order, player ear-confirmed. If
// final testing shows 2/3 swapped, fix kPanelNames below.
//
// MULTI-SCREEN HANDOFF: FF7 can chain naming screens back-to-back (Cloud â†’
// Barret at game start) without NAME_ENTRY_ACTIVE dropping 0 long enough to
// guarantee our 100ms poll sees it. NAME_ENTRY_CHAR_INDEX changing is the
// reliable handoff signal (0â†’1 captured live at the exact frame the Barret
// screen replaced Cloud's) â€” we re-announce the screen when it changes.
//
// Gated by Config::Get().speak_menus (the naming screen is a menu-module
// screen; no separate config option needed).
// ---------------------------------------------------------------------------

// The on-screen character grid, row-major. Rows/columns match the confirmed
// cursor value ranges (row 0-6, col 0-9).
// UNCERTAIN CELLS: row 5, columns 8-9 (apostrophe/quote) were hard to read
// in the reference screenshot. If a player reports hearing the wrong
// punctuation there, fix these two entries. The add/delete echo is immune to
// this: it decodes the byte the game actually wrote, not the grid guess.
// Side-panel button names, indexed by NAME_ENTRY_PANEL_INDEX (top to
// bottom). 0/1 proven by buffer effects; 2/3 ear-confirmed order.
static const wchar_t* const kPanelNames[4] = {
    L"Space", L"Delete", L"Select", L"Default",
};

static const wchar_t kNameGrid[7][10] = {
    { L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H', L'I', L'J' },
    { L'K', L'L', L'M', L'N', L'O', L'P', L'Q', L'R', L'S', L'T' },
    { L'U', L'V', L'W', L'X', L'Y', L'Z', L',', L'.', L'+', L'-' },
    { L'a', L'b', L'c', L'd', L'e', L'f', L'g', L'h', L'i', L'j' },
    { L'k', L'l', L'm', L'n', L'o', L'p', L'q', L'r', L's', L't' },
    { L'u', L'v', L'w', L'x', L'y', L'z', L':', L';', L'\'', L'"' },
    { L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9' },
};

// Spoken form of a single name character. Punctuation gets its word (SAPI
// and most screen readers skip or mangle lone punctuation), and uppercase
// letters get a "capital" prefix so A/a are distinguishable by ear â€” Tolk
// passes plain text, so we cannot rely on a screen reader's pitch-change
// capital indication being enabled.
static std::wstring SpokenNameChar(wchar_t c)
{
    switch (c) {
        case L',':  return L"comma";
        case L'.':  return L"period";
        case L'+':  return L"plus";
        case L'-':  return L"minus";
        case L':':  return L"colon";
        case L';':  return L"semicolon";
        case L'\'': return L"apostrophe";
        case L'"':  return L"quote";
        case L' ':  return L"space";
    }
    if (c >= L'A' && c <= L'Z') {
        std::wstring s = L"capital ";
        s += c;
        return s;
    }
    return std::wstring(1, c);
}

// Decode the raw NAME_ENTRY_BUFFER bytes into a wide string (0xFF terminates).
// Uses FF7Text::DecodeChar so the full encoding table applies: the naive
// byte+0x20 formula only covers bytes 0x00-0x5E, and the grid's apostrophe/
// quote cells may well be stored as extended bytes (FF7's dialog apostrophe
// is 0xB5). Sharing the table means any future encoding fix in ff7_text.cpp
// automatically reaches the name reader too.
static std::wstring DecodeNameBuffer(const uint8_t* raw, size_t cap)
{
    std::wstring out;
    for (size_t i = 0; i < cap && raw[i] != 0xFF; ++i) {
        const wchar_t c = FF7Text::DecodeChar(raw[i]);
        if (c != L'\0') out += c;
    }
    return out;
}

// Spell a name character-by-character with spoken punctuation/capitals:
// "Cloud" -> "capital C l o u d". Empty input -> "empty".
static std::wstring SpellName(const std::wstring& name)
{
    if (name.empty()) return L"empty";
    std::wstring out;
    for (size_t i = 0; i < name.size(); ++i) {
        if (i) out += L' ';
        out += SpokenNameChar(name[i]);
    }
    return out;
}

static DWORD WINAPI NameEntryThread(LPVOID /*unused*/)
{
    // Poll at 100ms (vs the menus' 150ms): grid navigation is the fastest
    // repeated input in the game short of battle, and a missed cell between
    // polls would announce a letter the player already left.
    constexpr DWORD kPollMs = 100;

    bool     on_screen  = false;  // debounced "naming screen is open" state
    uint8_t  gate_streak = 0;     // consecutive polls with both gate bytes set
    uint8_t  last_row = 0, last_col = 0;
    uint8_t  last_pane = 0, last_panel = 0;
    uint8_t  last_char_index = 0;
    uint8_t  last_buf[FF7Addr::NAME_ENTRY_BUFFER_CAP] = {};
    // Set when a wholesale buffer rewrite is seen; the announce is deferred
    // one poll so a chained-screen handoff (buffer rewritten before the
    // char-index flips â€” two separate game writes we sample 100ms apart)
    // resolves to the screen-open announce instead of a spurious
    // "Name is now Barret" immediately followed by "Name entry ... Barret".
    bool     rewrite_pending = false;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, kPollMs) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_menus) {
            on_screen = false;
            gate_streak = 0;
            rewrite_pending = false;
            continue;
        }

        // Gate: both bytes must agree that a naming screen is open. Either
        // alone could be unrelated BSS reuse in another module; together
        // (plus the 2-poll streak) false positives have not been observed.
        const uint8_t game_mode =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE);
        const uint8_t active =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::NAME_ENTRY_ACTIVE);

        if (game_mode != FF7Addr::GAME_MODE_NAME_ENTRY || active != 1) {
            on_screen = false;
            gate_streak = 0;
            rewrite_pending = false;
            continue;
        }

        // 2-poll debounce (saturating): skip the first gated poll so a single
        // stale poll of either gate byte never triggers announces.
        if (gate_streak < 2) gate_streak++;
        if (gate_streak < 2) continue;

        // Read the live state â€” TWICE, requiring both samples identical.
        // The game writes these values on its own thread; a poll can land
        // mid-update (e.g. between the new char byte and the moved 0xFF
        // terminator of an append, or between the COL and ROW writes of a
        // wrap). A torn snapshot decodes to a name/cell that never existed
        // on screen, so on any mismatch we skip this poll and pick up the
        // settled state 100ms later â€” imperceptible, and self-correcting.
        //
        // ROW/COL are read as u8: the confirming scans only ever observed the
        // LOW byte of each DWORD slot changing, and the three high bytes are
        // unverified â€” if they held nonzero data, a u32 read would fail the
        // grid bound check forever and silence the whole feature.
        uint8_t row, col, pane, panel, char_index;
        uint8_t buf[FF7Addr::NAME_ENTRY_BUFFER_CAP];
        {
            const uint8_t row1 =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::NAME_ENTRY_ROW);
            const uint8_t col1 =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::NAME_ENTRY_COL);
            const uint8_t pan1 =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::NAME_ENTRY_PANE_FLAG);
            const uint8_t pix1 =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::NAME_ENTRY_PANEL_INDEX);
            const uint8_t idx1 =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::NAME_ENTRY_CHAR_INDEX);
            memcpy(buf, reinterpret_cast<const void*>(FF7Addr::NAME_ENTRY_BUFFER),
                   sizeof(buf));

            uint8_t buf2[FF7Addr::NAME_ENTRY_BUFFER_CAP];
            memcpy(buf2, reinterpret_cast<const void*>(FF7Addr::NAME_ENTRY_BUFFER),
                   sizeof(buf2));
            const uint8_t row2 =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::NAME_ENTRY_ROW);
            const uint8_t col2 =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::NAME_ENTRY_COL);
            const uint8_t pan2 =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::NAME_ENTRY_PANE_FLAG);
            const uint8_t pix2 =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::NAME_ENTRY_PANEL_INDEX);
            const uint8_t idx2 =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::NAME_ENTRY_CHAR_INDEX);

            if (row1 != row2 || col1 != col2 || pan1 != pan2 ||
                pix1 != pix2 || idx1 != idx2 ||
                memcmp(buf, buf2, sizeof(buf)) != 0) {
                continue;   // torn read â€” retry next poll
            }
            row = row1; col = col1; pane = pan1; panel = pix1;
            char_index = idx1;
        }

        // Screen (re)open: first gated poll, or the game chained straight to
        // the next character's screen (char_index change, e.g. Cloudâ†’Barret).
        if (!on_screen || char_index != last_char_index) {
            const std::wstring name = DecodeNameBuffer(buf, sizeof(buf));

            std::wstring msg = L"Name entry. Current name, ";
            msg += name.empty() ? L"empty" : name;
            msg += L". ";
            if (pane == 1 && panel <= FF7Addr::NAME_ENTRY_PANEL_MAX) {
                msg += L"Cursor on ";
                msg += kPanelNames[panel];
                msg += L".";
            } else if (row < 7 && col < 10) {
                msg += L"Cursor on ";
                msg += SpokenNameChar(kNameGrid[row][col]);
                msg += L".";
            }

            char dbg[112];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] NAME-ENTRY open char=%u row=%u col=%u pane=%u "
                "panel=%u len=%u",
                char_index, row, col, pane, panel,
                static_cast<unsigned>(name.size()));
            Log::Write(dbg);

            TTS::Speak(msg.c_str(), /*interrupt=*/true);

            on_screen = true;
            rewrite_pending = false;   // handoff explains any pending rewrite
            last_char_index = char_index;
            last_row = row;
            last_col = col;
            last_pane = pane;
            last_panel = panel;
            memcpy(last_buf, buf, sizeof(buf));
            continue;
        }

        // Cursor movement â€” pane-aware. Grid letters are announced ONLY
        // while the cursor is actually in the grid (pane == 0): entering the
        // panel can change the ROW byte (observed live, 1 -> 4), which would
        // otherwise speak a phantom letter. All branches announce where the
        // cursor LANDED, never a prediction (see header comment).
        if (pane != last_pane) {
            // Crossed between grid and panel.
            if (pane == 1) {
                if (panel <= FF7Addr::NAME_ENTRY_PANEL_MAX) {
                    TTS::Speak(kPanelNames[panel], /*interrupt=*/true);
                }
            } else if (row < 7 && col < 10) {
                // Back on the grid â€” the game restores the remembered grid
                // column, so tell the player where they landed.
                std::wstring msg = L"grid, ";
                msg += SpokenNameChar(kNameGrid[row][col]);
                TTS::Speak(msg.c_str(), /*interrupt=*/true);
            }
            last_pane  = pane;
            last_panel = panel;
            last_row   = row;
            last_col   = col;
        } else if (pane == 1 && panel != last_panel) {
            // Moving between panel buttons (wraps 0 <-> 3).
            if (panel <= FF7Addr::NAME_ENTRY_PANEL_MAX) {
                TTS::Speak(kPanelNames[panel], /*interrupt=*/true);
            }
            last_panel = panel;
            last_row   = row;    // keep grid state in sync silently â€” the
            last_col   = col;    // ROW byte can drift while on the panel
        } else if (pane == 0 && (row != last_row || col != last_col)) {
            if (row < 7 && col < 10) {
                TTS::Speak(SpokenNameChar(kNameGrid[row][col]).c_str(),
                           /*interrupt=*/true);
            } else {
                char dbg[80];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] NAME-ENTRY cursor outside grid row=%u col=%u",
                    row, col);
                Log::Write(dbg);
            }
            last_row = row;
            last_col = col;
        }

        // Name edits. The raw memcmp is only the cheap change GATE (no
        // per-poll allocations); classification and announce decisions use
        // the DECODED names, so a change in stale bytes past the 0xFF
        // terminator (indices beyond the visible name â€” unverified BSS up to
        // the 12-byte cap) can never fire a spurious announce.
        if (memcmp(buf, last_buf, sizeof(buf)) != 0) {
            const std::wstring now_name  = DecodeNameBuffer(buf, sizeof(buf));
            const std::wstring prev_name = DecodeNameBuffer(last_buf, sizeof(last_buf));

            // Raw bytes changed but the visible name did not (post-terminator
            // churn): adopt the new bytes silently.
            if (now_name == prev_name) {
                memcpy(last_buf, buf, sizeof(buf));
                rewrite_pending = false;
                continue;
            }

            std::wstring msg;
            if (now_name.size() == prev_name.size() + 1 &&
                now_name.compare(0, prev_name.size(), prev_name) == 0) {
                // Single letter appended (Confirm on a grid cell): echo the
                // letter the GAME wrote (ground truth even if our grid table
                // has a wrong guess), then spell the full name.
                msg  = SpokenNameChar(now_name.back());
                msg += L". ";
                msg += SpellName(now_name);
                rewrite_pending = false;

                // Self-check: the appended byte is ground truth for the cell
                // the cursor is on. Log any disagreement with kNameGrid so a
                // normal play session verifies the uncertain cells (row 5
                // cols 8-9) without needing a sighted tester â€” TODO.txt's
                // "fix when observed" plan depends on this record existing.
                // Only meaningful for GRID confirms: the panel's Space button
                // also appends a character while row/col still point at a
                // grid cell, which would log a false mismatch.
                if (pane == 0 && row < 7 && col < 10 &&
                    now_name.back() != kNameGrid[row][col]) {
                    char dbg[112];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] NAME-ENTRY GRID MISMATCH row=%u col=%u "
                        "guessed=0x%04X game-wrote=0x%04X â€” fix kNameGrid",
                        row, col,
                        static_cast<unsigned>(kNameGrid[row][col]),
                        static_cast<unsigned>(now_name.back()));
                    Log::Write(dbg);
                }
            } else if (prev_name.size() == now_name.size() + 1 &&
                       prev_name.compare(0, now_name.size(), now_name) == 0) {
                // Single letter deleted (Cancel).
                msg  = L"Deleted ";
                msg += SpokenNameChar(prev_name.back());
                msg += L". ";
                msg += SpellName(now_name);
                rewrite_pending = false;
            } else {
                // Wholesale rewrite â€” either the Default button restoring the
                // original name, or the first half of a chained-screen
                // handoff whose char-index flip we haven't sampled yet.
                // Defer ONE poll: if the char index changes by next poll, the
                // screen-open announce covers it; if not, it was a genuine
                // in-screen rewrite and we announce it 100ms late.
                if (!rewrite_pending) {
                    rewrite_pending = true;
                    // Deliberately do NOT update last_buf â€” next poll must
                    // re-detect this same change to complete the deferral.
                    continue;
                }
                rewrite_pending = false;
                msg  = L"Name is now ";
                msg += SpellName(now_name);
            }

            Log::Write("[FF7Access] NAME-ENTRY buffer changed");
            TTS::Speak(msg.c_str(), /*interrupt=*/true);
            memcpy(last_buf, buf, sizeof(buf));
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Background initialization thread.
//
// This thread handles Config/TTS/Hook init outside the loader lock.
// Created by Proxy::Init() during DllMain DLL_PROCESS_ATTACH.
// ---------------------------------------------------------------------------
static DWORD WINAPI InitThread(LPVOID /*unused*/)
{
    // Wait for DllMain to return and the loader lock to be released before
    // calling LoadLibrary (TTS::Init â†’ Tolk.dll). The 200ms is purely for
    // loader-lock safety â€” it does NOT guarantee FFNx has finished initializing.
    // FFNx timing is handled by Resolve() checking execute_opcode_table[0x40]:
    // we only install hooks after FFNx's voice_init() has patched that entry,
    // which is a reliable signal that ff7_find_externals has already completed.
    //
    // CreateThread from DllMain is technically a grey area per MSDN, but is
    // the established standard for proxy DLLs (used by ReShade, ENBSeries,
    // DXVK, etc.) and is safe here because DisableThreadLibraryCalls() was
    // called before us, and this Sleep() guards the LoadLibrary call.
    Sleep(200);

    // Load and parse ffvii_accessibility.cfg. Pure file I/O; no DLL loading.
    Config::Load();

    // Open the debug log file if debug_log = true. Must be called after
    // Config::Load() so we know the user's setting. TTS::Init() and all
    // subsequent code route their diagnostic output through Log::Write().
    Log::Init(Config::Get().debug_log);

    // Initialize the Tolk screen reader library. Calls LoadLibrary("Tolk.dll").
    // Safe here because 200ms have passed and the loader lock is long released.
    TTS::Init();

    // Let the text decoder speak LIVE character names (v2.19): dialog speaker
    // tokens ("Barret:") and inline name tokens now read the savemap records,
    // so player renames carry through everywhere. Registered before any hook
    // installs (below) so no decode can race the registration. Safe this
    // early: the provider reads only static .data addresses that exist from
    // process start, and falls back to defaults while the savemap is zeroed.
    FF7Text::SetNameProvider(&DialogNameProvider);

    // Patch FF7's IAT to intercept dotemuRegSetValueExA calls from AF3DN.P.
    // Must run after TTS::Init() (the hook calls TTS::Speak and Log::Write)
    // and after the loader lock is released (we call GetModuleHandleA and
    // VirtualProtect).  The 200ms sleep above satisfies both requirements.
    SetupSoundIATHook();

    // Resolve the waveOut tone player (v2.30.41). Must run after Log::Init
    // (its ready/fallback line is a diagnostic we want in every bug-report
    // log â€” the 2026-07-31 "no tones" report was undebuggable without
    // knowing which playback path was active) and BEFORE any of the tone-
    // playing threads below are created, so Tones::Play never races the
    // one-time pointer resolution.
    Tones::Init();

    // Create the shared stop event used by both TitleCursorThread and
    // MenuCursorThread. It is a manual-reset event: one SetEvent() in
    // Proxy::Shutdown() wakes both threads simultaneously.
    //
    // Both threads must start before the Install() loop below, because the
    // title screen and main menu are reachable before the field module loads.
    g_cursor_stop_event = CreateEvent(nullptr, /*bManualReset=*/TRUE,
                                      /*bInitialState=*/FALSE, nullptr);
    if (g_cursor_stop_event) {
        g_title_thread = CreateThread(nullptr, 0, TitleCursorThread, nullptr, 0, nullptr);
        if (g_title_thread) {
            Log::Write("[FF7Access] Title cursor polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start title cursor thread.");
        }

        // Game-over watch (v2.30.37): 30ms GAME_MODE poll for the ~60ms
        // game-over blip (value 26). Must start before the field module can
        // run â€” a wipe is reachable in the first battle. See the
        // g_game_over_latch declaration for the full design.
        g_gameover_thread = CreateThread(nullptr, 0, GameOverWatchThread, nullptr, 0, nullptr);
        if (g_gameover_thread) {
            Log::Write("[FF7Access] Game-over watch thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start game-over watch thread.");
        }

        // Confirmed cursor address: 0x00DC1154 (see ff7_addresses.h MENU_CURSOR).
        // Found by ff7_menu_cursor_isolate.py (2026-07-01): both snapshot phases
        // ran inside the already-open menu so field scripts were frozen, then we
        // subtracted idle-phase changes from navigation-phase changes to isolate
        // addresses that only move when the cursor moves.  Verified across two
        // independent game launches with different PIDs.
        g_menu_thread = CreateThread(nullptr, 0, MenuCursorThread, nullptr, 0, nullptr);
        if (g_menu_thread) {
            Log::Write("[FF7Access] Menu cursor polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start menu cursor thread.");
        }

        // Config sub-menu row tracking. Confirmed address: 0x00DC10F0 (see
        // ff7_addresses.h CONFIG_ROW). Found by ff7_config_menu_scan.py (2026-07-02):
        // isolate scan inside the config sub-menu subtracted idle background changes
        // from navigation changes; 0x00DC10F0 was the sole candidate in row range 0â€“9.
        // Verified by ff7_config_menu_verify.py: clean 0â€“9 sequential tracking.
        g_config_thread = CreateThread(nullptr, 0, ConfigMenuThread, nullptr, 0, nullptr);
        if (g_config_thread) {
            Log::Write("[FF7Access] Config menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start config menu thread.");
        }

        // Save/Load menu TTS (v2.29). Cursor/phase addresses from the
        // guided scan ff7_save_menu_scan.py (2026-07-17, grid cursor
        // live-verified in-session); slot previews parsed from the save
        // files on disk (research doc Â§5 layout table).
        g_savemenu_thread = CreateThread(nullptr, 0, SaveMenuThread, nullptr, 0, nullptr);
        if (g_savemenu_thread) {
            Log::Write("[FF7Access] Save menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start save menu thread.");
        }

        // Item menu TTS (v2.31). Cursor/mode addresses from the guided scan
        // ff7_item_menu_scan.py (2026-07-18, all single candidates, list
        // cursor speak-back verified); inventory read from savemap
        // items[320]; the which-screen gate from the dispatcher disasm.
        g_itemmenu_thread = CreateThread(nullptr, 0, ItemMenuThread, nullptr, 0, nullptr);
        if (g_itemmenu_thread) {
            Log::Write("[FF7Access] Item menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start item menu thread.");
        }

        // Order menu + main-menu pane focus TTS (v2.32). Cursor/latch from
        // the guided scan (order_menu_scan_20260718_152825); focus mode and
        // outcome semantics from the 0x6CA346 handler disasm (provenance in
        // ff7_addresses.h ORDERMENU block).
        g_ordermenu_thread = CreateThread(nullptr, 0, OrderMenuThread, nullptr, 0, nullptr);
        if (g_ordermenu_thread) {
            Log::Write("[FF7Access] Order menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start order menu thread.");
        }

        // Status screen TTS (v2.33). Dispatch index 5 (FFNx status_menu_sub);
        // effective stats from the menu-populated char-data block, guarded
        // against staleness by the savemap HP cross-check.
        g_statusmenu_thread = CreateThread(nullptr, 0, StatusMenuThread, nullptr, 0, nullptr);
        if (g_statusmenu_thread) {
            Log::Write("[FF7Access] Status menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start status menu thread.");
        }

        // Shop menus TTS (v2.30.28). Entirely static-derived in one offline
        // session (ff7_shop_static.py): GAME_MODE==8 gate, 7-state loop,
        // cursor widgets, catalog, and price table â€” provenance in
        // ff7_addresses.h's SHOP block. Debug logging on state changes is
        // the live-confirm channel.
        g_shopmenu_thread = CreateThread(nullptr, 0, ShopMenuThread, nullptr, 0, nullptr);
        if (g_shopmenu_thread) {
            Log::Write("[FF7Access] Shop menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start shop menu thread.");
        }

        // Materia menu TTS (v2.30.33). Dispatch index 3; all state
        // static-derived (ff7_materia_menu_static.py â€” the MATMENU block
        // in ff7_addresses.h). Mode-change debug lines are the live
        // verify.
        g_materiamenu_thread = CreateThread(nullptr, 0, MateriaMenuThread, nullptr, 0, nullptr);
        if (g_materiamenu_thread) {
            Log::Write("[FF7Access] Materia menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start materia menu thread.");
        }

        // Equip menu TTS (v2.30.34). Dispatch index 4 (FFNx
        // menu_sub_705D16 = table[4]); state static-derived
        // (ff7_equip_menu_static.py â€” EQMENU block in ff7_addresses.h).
        g_equipmenu_thread = CreateThread(nullptr, 0, EquipMenuThread, nullptr, 0, nullptr);
        if (g_equipmenu_thread) {
            Log::Write("[FF7Access] Equip menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start equip menu thread.");
        }

        // Limit menu TTS (v2.30.35). Dispatch index 7 (row->index
        // pattern); state static-derived (ff7_limit_menu_static.py â€”
        // LIMITMENU block in ff7_addresses.h).
        g_limitmenu_thread = CreateThread(nullptr, 0, LimitMenuThread, nullptr, 0, nullptr);
        if (g_limitmenu_thread) {
            Log::Write("[FF7Access] Limit menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start limit menu thread.");
        }

        // Magic menu TTS (v2.30.48). Dispatch index 2 (row->index
        // pattern); state static-derived (ff7_magic_menu_static.py —
        // MAGICMENU block in ff7_addresses.h). Closes the last main-menu
        // narration gap besides PHS.
        g_magicmenu_thread = CreateThread(nullptr, 0, MagicMenuThread, nullptr, 0, nullptr);
        if (g_magicmenu_thread) {
            Log::Write("[FF7Access] Magic menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start magic menu thread.");
        }

        // Announcement keys (FF4-scheme parity): G = current gil
        // (v2.30.28), H = in battle, current character's HP/MP/status
        // (v2.30.30).
        g_gilkey_thread = CreateThread(nullptr, 0, AnnounceKeysThread, nullptr, 0, nullptr);
        if (g_gilkey_thread) {
            Log::Write("[FF7Access] Announcement keys thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start announcement keys thread.");
        }

        // Menu tutorial per-slide narration (v2.30.29). Live window state
        // + engine tutorial flag from ff7_tutorial_static.py; replaces
        // v2.30.27's read-everything-up-front model in hook_tutor.
        g_tutorial_thread = CreateThread(nullptr, 0, TutorialThread, nullptr, 0, nullptr);
        if (g_tutorial_thread) {
            Log::Write("[FF7Access] Tutorial narration thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start tutorial thread.");
        }

        // Countdown timer announcements + T/Shift+T (v2.34). Value/units
        // static-proven via the STTIM handler disasm; shipped speculatively
        // ahead of the first reachable timer with debug logging as the
        // live verify (see the TimerThread header comment).
        g_timer_thread = CreateThread(nullptr, 0, TimerThread, nullptr, 0, nullptr);
        if (g_timer_thread) {
            Log::Write("[FF7Access] Timer polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start timer thread.");
        }

        // Battle victory screens TTS (v2.35). Mode/pools/drops static-
        // derived (results-block scripts 2026-07-19); pools captured at
        // results entry because the game consumes them on apply.
        g_victory_thread = CreateThread(nullptr, 0, VictoryThread, nullptr, 0, nullptr);
        if (g_victory_thread) {
            Log::Write("[FF7Access] Victory screen polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start victory thread.");
        }

        // Battle action TTS (v2.7). Polls g_active_actor_id + commandID for
        // turn detection, then the flash-message struct (battle_actor_data,
        // 0xDC38E0) for the exact action, resolving names from the kernel2
        // text sections located by in-process signature scan.  Confirmed
        // addresses: G_ACTIVE_ACTOR_ID=0xBE1170, G_BATTLE_MODEL_STATE=0xBE1178,
        // BATTLE_ACTOR_CMD_INDEX=0xDC38EC, BATTLE_ACTOR_ACTION_INDEX=0xDC38F0,
        // BATTLE_DISPATCH_BYTE_TABLE=0x6D70A8, ENEMY_ATTACK_NAME_TABLE=0x9A9484
        // (action_name_final_verify.py live run, 2026-07-11).
        g_battle_thread = CreateThread(nullptr, 0, BattleActionThread, nullptr, 0, nullptr);
        if (g_battle_thread) {
            Log::Write("[FF7Access] Battle action polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start battle action thread.");
        }

        // Battle scene-message reader (v2.36): enemy AI dialogue (the
        // scorpion tail warning etc.) from the battle text display queue.
        g_battlemsg_thread = CreateThread(nullptr, 0, BattleMessageThread, nullptr, 0, nullptr);
        if (g_battlemsg_thread) {
            Log::Write("[FF7Access] Battle message polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start battle message thread.");
        }

        // Battle command-menu navigation TTS (v2.9). Polls the battle menu
        // widget state machine solved 2026-07-12: BATTLE_MENU_STATE=0x91EF9C,
        // widget block 0xDC20A0+slot*0x700, command table 0xDBA4E4+slot*0x440,
        // target index 0xDC3C94 â€” all live-confirmed by
        // ff7_battle_menu_cursor_live_verify.py before implementation.
        g_battlemenu_thread = CreateThread(nullptr, 0, BattleMenuThread, nullptr, 0, nullptr);
        if (g_battlemenu_thread) {
            Log::Write("[FF7Access] Battle menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start battle menu thread.");
        }

        // Wall-bump navigation tone. Addresses resolved statically via FFNx's
        // discovery chains (ff7_wall_nav_static.py) and the detection signal
        // verified live (ff7_wall_nav_verify.py), both 2026-07-09 â€” see the
        // WallBumpThread header comment and ff7_addresses.h SECTION 1d.
        g_wallbump_thread = CreateThread(nullptr, 0, WallBumpThread, nullptr, 0, nullptr);
        if (g_wallbump_thread) {
            Log::Write("[FF7Access] Wall-bump tone polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start wall-bump thread.");
        }

        // Story-dialog wait/choice tones (v2.30.5). See DialogToneThread's
        // header comment; the producer side lives in hooks.cpp's
        // hook_message/hook_ask.
        g_dialogtone_thread = CreateThread(nullptr, 0, DialogToneThread, nullptr, 0, nullptr);
        if (g_dialogtone_thread) {
            Log::Write("[FF7Access] Dialog tone polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start dialog tone thread.");
        }

        // Field exit scan (v2.14). Triggers header resolved statically via
        // FFNx's chain with three name-embedded cross-checks
        // (ff7_field_triggers_static.py, 2026-07-13) â€” see the FieldNavThread
        // header comment and ff7_addresses.h SECTION 1e.
        g_fieldnav_thread = CreateThread(nullptr, 0, FieldNavThread, nullptr, 0, nullptr);
        if (g_fieldnav_thread) {
            Log::Write("[FF7Access] Field navigation (exit scan) thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start field navigation thread.");
        }

        // F8 in-game accessibility menu (v2.30.42). Started here â€” not
        // gated on any game state â€” because settings should be reachable
        // from the title screen onward (the menu itself refuses only the
        // naming screen). Takes the shared stop event like every other
        // polling thread.
        g_settingsmenu_thread = SettingsMenu::Start(g_cursor_stop_event);
        if (g_settingsmenu_thread) {
            Log::Write("[FF7Access] Settings menu (F8) thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start settings menu thread.");
        }

        // Name-entry screen TTS (v2.8). Grid cursor + name buffer confirmed
        // live 2026-07-12 (ff7_name_entry_scan.py / ff7_name_entry_verify.py):
        // NAME_ENTRY_COL=0xDD4538, NAME_ENTRY_ROW=0xDD453C,
        // NAME_ENTRY_BUFFER=0xDD45F0, NAME_ENTRY_CHAR_INDEX=0xDD46F8,
        // NAME_ENTRY_ACTIVE=0xDD46FC, GAME_MODE==6 on the naming screen.
        // Must start before the Install() loop below for the same reason as
        // the title thread: the first naming screen (Cloud) appears minutes
        // into a New Game, but a naming screen is reachable without any of
        // the field-module state Install() waits for.
        g_nameentry_thread = CreateThread(nullptr, 0, NameEntryThread, nullptr, 0, nullptr);
        if (g_nameentry_thread) {
            Log::Write("[FF7Access] Name-entry polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start name-entry thread.");
        }

        if (!g_title_thread && !g_menu_thread && !g_config_thread &&
            !g_savemenu_thread && !g_itemmenu_thread && !g_ordermenu_thread &&
            !g_statusmenu_thread && !g_shopmenu_thread &&
            !g_materiamenu_thread && !g_equipmenu_thread &&
            !g_limitmenu_thread && !g_magicmenu_thread && !g_gilkey_thread &&
            !g_tutorial_thread && !g_timer_thread && !g_victory_thread &&
            !g_battle_thread && !g_battlemsg_thread && !g_battlemenu_thread &&
            !g_wallbump_thread && !g_dialogtone_thread && !g_fieldnav_thread &&
            !g_nameentry_thread) {
            CloseHandle(g_cursor_stop_event);
            g_cursor_stop_event = nullptr;
        }
    } else {
        Log::Write("[FF7Access] Warning: could not create cursor stop event.");
    }

    // Poll until both conditions are met (checked inside FF7Addr::Resolve()):
    //   1. FF7's field opcode table is populated (field module has loaded), AND
    //   2. FFNx's voice_init() has patched table[0x40] (if FFNx is running),
    //      confirming that ff7_find_externals has safely finished reading it.
    // The 50ms poll interval is imperceptible â€” FF7 takes seconds to reach
    // the first field map. Once both conditions clear, Install() is idempotent
    // and the thread exits.
    while (!Hooks::Install()) {
        Sleep(50);
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Proxy::Init and Proxy::Shutdown
// ---------------------------------------------------------------------------

namespace Proxy {

static HMODULE s_real_version = nullptr;
static bool    s_loaded       = false;

void Init()
{
    if (s_loaded) return;
    s_loaded = true;

    // Load the real system version.dll from System32 by full absolute path.
    // Using the full path creates a distinct module-list entry (System32\version.dll)
    // separate from our proxy (FINAL FANTASY VII\version.dll). Both coexist in
    // the process because Windows module identity is based on the canonical path.
    char sys_dir[MAX_PATH]  = {};
    char real_path[MAX_PATH] = {};
    GetSystemDirectoryA(sys_dir, MAX_PATH);
    _snprintf_s(real_path, MAX_PATH, _TRUNCATE, "%s\\version.dll", sys_dir);

    s_real_version = LoadLibraryA(real_path);
    if (!s_real_version) {
        // Log::Init has not been called yet at this point (Config::Load is in the
        // background thread, not here). Route directly to OutputDebugStringA.
        OutputDebugStringA("[FF7Access] FATAL: could not load system version.dll.\n");
        return;
    }

    // Pass 3: Resolve all 17 stub function pointers.
    // GetProcAddress follows DLL forwarder chains automatically, so
    // VerLanguageNameA/W resolve to their kernel32 implementations.
#define RESOLVE_FP(name) fp_##name = GetProcAddress(s_real_version, #name);
    VERSION_FORWARD_FUNCS(RESOLVE_FP)
#undef RESOLVE_FP

    // Spawn the background init thread. We do NOT wait for it; it runs
    // independently and exits after Hooks::Install() succeeds.
    //
    // DisableThreadLibraryCalls() was called in DllMain before this function,
    // which suppresses DLL_THREAD_ATTACH notifications for our DLL and reduces
    // loader lock contention from the new thread's startup sequence.
    HANDLE hThread = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
    if (hThread) {
        CloseHandle(hThread); // Don't need to join; thread exits on its own.
    } else {
        // Log::Init has not been called yet here either â€” still direct.
        OutputDebugStringA("[FF7Access] Warning: could not create init thread. "
                           "Hooks will not be installed.\n");
    }
}

void Shutdown()
{
    // Restore the IAT slot before stopping any threads.  If the hook is live
    // while our code is being unloaded, any FF7 registry write between
    // FreeLibrary and IAT restore would jump into freed memory and crash.
    // Restoring first makes the window between "our code unloaded" and "IAT
    // points at original" impossible.
    if (g_iat_dotemu_entry && g_orig_dotemu_regset) {
        DWORD old_protect;
        if (VirtualProtect(g_iat_dotemu_entry, sizeof(ULONG_PTR),
                           PAGE_READWRITE, &old_protect)) {
            g_iat_dotemu_entry->u1.Function =
                reinterpret_cast<ULONG_PTR>(g_orig_dotemu_regset);
            VirtualProtect(g_iat_dotemu_entry, sizeof(ULONG_PTR),
                           old_protect, &old_protect);
            Log::Write("[FF7Access] IAT hook: dotemuRegSetValueExA restored");
        } else {
            Log::Write("[FF7Access] IAT hook: VirtualProtect failed during restore");
        }
        g_iat_dotemu_entry   = nullptr;
        g_orig_dotemu_regset = nullptr;
    }

    // Signal and join TitleCursorThread before anything else tears down.
    // dllmain.cpp calls Proxy::Shutdown() first (before TTS::Shutdown and
    // Log::Shutdown), so by the time those run no background thread can be
    // mid-call into TTS or Log.
    //
    // On process exit (lpvReserved != NULL in DLL_PROCESS_DETACH) the OS
    // has already terminated all threads, so WaitForSingleObject returns
    // immediately (the handle is in signaled state). On explicit FreeLibrary
    // the thread wakes from WaitForSingleObject within 150ms and exits normally.
    // Signal both cursor threads. The shared event is manual-reset so both
    // TitleCursorThread and MenuCursorThread wake from their 150ms waits.
    if (g_cursor_stop_event) SetEvent(g_cursor_stop_event);

    // Join each thread individually. Both exit within 150ms of the signal.
    if (g_title_thread) {
        WaitForSingleObject(g_title_thread, 500);
        CloseHandle(g_title_thread);
        g_title_thread = nullptr;
    }
    if (g_gameover_thread) {
        WaitForSingleObject(g_gameover_thread, 500);
        CloseHandle(g_gameover_thread);
        g_gameover_thread = nullptr;
    }
    if (g_menu_thread) {
        WaitForSingleObject(g_menu_thread, 500);
        CloseHandle(g_menu_thread);
        g_menu_thread = nullptr;
    }
    if (g_config_thread) {
        WaitForSingleObject(g_config_thread, 500);
        CloseHandle(g_config_thread);
        g_config_thread = nullptr;
    }
    if (g_savemenu_thread) {
        WaitForSingleObject(g_savemenu_thread, 500);
        CloseHandle(g_savemenu_thread);
        g_savemenu_thread = nullptr;
    }
    if (g_itemmenu_thread) {
        WaitForSingleObject(g_itemmenu_thread, 500);
        CloseHandle(g_itemmenu_thread);
        g_itemmenu_thread = nullptr;
    }
    if (g_ordermenu_thread) {
        WaitForSingleObject(g_ordermenu_thread, 500);
        CloseHandle(g_ordermenu_thread);
        g_ordermenu_thread = nullptr;
    }
    if (g_statusmenu_thread) {
        WaitForSingleObject(g_statusmenu_thread, 500);
        CloseHandle(g_statusmenu_thread);
        g_statusmenu_thread = nullptr;
    }
    if (g_shopmenu_thread) {
        WaitForSingleObject(g_shopmenu_thread, 500);
        CloseHandle(g_shopmenu_thread);
        g_shopmenu_thread = nullptr;
    }
    if (g_materiamenu_thread) {
        WaitForSingleObject(g_materiamenu_thread, 500);
        CloseHandle(g_materiamenu_thread);
        g_materiamenu_thread = nullptr;
    }
    if (g_equipmenu_thread) {
        WaitForSingleObject(g_equipmenu_thread, 500);
        CloseHandle(g_equipmenu_thread);
        g_equipmenu_thread = nullptr;
    }
    if (g_limitmenu_thread) {
        WaitForSingleObject(g_limitmenu_thread, 500);
        CloseHandle(g_limitmenu_thread);
        g_limitmenu_thread = nullptr;
    }
    if (g_magicmenu_thread) {
        WaitForSingleObject(g_magicmenu_thread, 500);
        CloseHandle(g_magicmenu_thread);
        g_magicmenu_thread = nullptr;
    }
    if (g_gilkey_thread) {
        WaitForSingleObject(g_gilkey_thread, 500);
        CloseHandle(g_gilkey_thread);
        g_gilkey_thread = nullptr;
    }
    if (g_tutorial_thread) {
        WaitForSingleObject(g_tutorial_thread, 500);
        CloseHandle(g_tutorial_thread);
        g_tutorial_thread = nullptr;
    }
    if (g_timer_thread) {
        WaitForSingleObject(g_timer_thread, 500);
        CloseHandle(g_timer_thread);
        g_timer_thread = nullptr;
    }
    if (g_victory_thread) {
        WaitForSingleObject(g_victory_thread, 500);
        CloseHandle(g_victory_thread);
        g_victory_thread = nullptr;
    }
    if (g_battle_thread) {
        WaitForSingleObject(g_battle_thread, 500);
        CloseHandle(g_battle_thread);
        g_battle_thread = nullptr;
    }
    if (g_battlemsg_thread) {
        WaitForSingleObject(g_battlemsg_thread, 500);
        CloseHandle(g_battlemsg_thread);
        g_battlemsg_thread = nullptr;
    }
    if (g_battlemenu_thread) {
        WaitForSingleObject(g_battlemenu_thread, 500);
        CloseHandle(g_battlemenu_thread);
        g_battlemenu_thread = nullptr;
    }
    if (g_fieldnav_thread) {
        WaitForSingleObject(g_fieldnav_thread, 500);
        CloseHandle(g_fieldnav_thread);
        g_fieldnav_thread = nullptr;
    }
    if (g_wallbump_thread) {
        WaitForSingleObject(g_wallbump_thread, 500);
        CloseHandle(g_wallbump_thread);
        g_wallbump_thread = nullptr;
    }
    if (g_settingsmenu_thread) {
        WaitForSingleObject(g_settingsmenu_thread, 500);
        CloseHandle(g_settingsmenu_thread);
        g_settingsmenu_thread = nullptr;
    }
    if (g_dialogtone_thread) {
        WaitForSingleObject(g_dialogtone_thread, 500);
        CloseHandle(g_dialogtone_thread);
        g_dialogtone_thread = nullptr;
    }
    if (g_nameentry_thread) {
        WaitForSingleObject(g_nameentry_thread, 500);
        CloseHandle(g_nameentry_thread);
        g_nameentry_thread = nullptr;
    }

    if (g_cursor_stop_event) {
        CloseHandle(g_cursor_stop_event);
        g_cursor_stop_event = nullptr;
    }

    if (s_real_version) {
        FreeLibrary(s_real_version);
        s_real_version = nullptr;
    }
}

} // namespace Proxy
