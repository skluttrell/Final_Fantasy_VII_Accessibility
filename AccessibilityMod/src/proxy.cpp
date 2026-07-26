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
 *   unit. We need none of winver.h's declarations here — we never call these
 *   functions directly, only forward to them. All other windows.h content
 *   (HMODULE, GetSystemDirectoryA, CreateThread, etc.) is unaffected.
 *
 * BACKGROUND THREADS:
 *   Proxy::Init() spawns InitThread (a one-shot thread) that:
 *
 *     1. Sleep(200ms) — loader lock released, FFNx init safe.
 *     2. Config::Load() — parse ffvii_accessibility.cfg (no DLL loading).
 *     3. TTS::Init()   — LoadLibrary("Tolk.dll"); safe past the 200ms mark.
 *     4. Spawn TitleCursorThread — persistent thread for title screen cursor
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
#include "gamepad.h" // right-analog-stick pathfinder input (v2.21)
#include "ff7_field_names.h" // generated maplist: field id -> internal name (v2.25)
#include "ff7_line_trigger_catalog.h" // generated: what each LINE trigger DOES
                                      // (exit/climb/OK/scene, v2.30.23)
#include <string>
#include <fstream>   // visited-places cache file IO (v2.25)
#include <cstring>   // memchr/memcmp/memcpy in the kernel2 section scanner
#include <cmath>     // atan2f/sqrtf/fmodf in the field pathfinder (v2.14)
#include <cwctype>   // iswdigit in the dev-label translator (v2.20)
#include <vector>    // walkmesh snapshot + A* state (v2.22 turn-by-turn)
#include <cfloat>    // FLT_MAX as the A* "unvisited" cost (v2.22)
#include <set>       // battle scene-message dedup by buffer_idx (v2.36)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

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
// Pass 2: Naked stub bodies — one per forwarded function.
//
// Each generates FF 25 [&fp_name] (JMP DWORD PTR [abs_addr]).
// The call passes control to the real function with the exact same stack
// layout as a direct call. No prologue or epilogue needed.
//
// These work without parameter lists because we never touch the stack —
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
static HANDLE g_gilkey_thread     = nullptr;
static HANDLE g_timer_thread      = nullptr;
static HANDLE g_victory_thread    = nullptr;
static HANDLE g_battle_thread     = nullptr;
static HANDLE g_battlemsg_thread  = nullptr;

// v2.35.1: the post-battle VICTORY screens set MENU_OPEN=1 (the v2.8.3
// observation), which made MenuCursorThread's open-re-announce speak the
// STALE main-menu row ("Item", "Config") over the victory announcements
// (player report 2026-07-19). Two cross-thread signals suppress it:
//   g_last_battle_tick  — GetTickCount() stamped every battle poll while
//     GAME_MODE==2 (BattleActionThread). A "menu open" within seconds of
//     battle mode can only be the results screens — the real main menu is
//     unreachable that fast (fade + results + field control in between).
//     Covers the race where results appear before the mode byte moves.
//   g_victory_active    — set by VictoryThread while the results window
//     is live (covers however long the player reads the screens).
// Plain aligned 32-bit stores/loads; benign racing (x86 atomicity).
static volatile DWORD g_last_battle_tick = 0;
static volatile LONG  g_victory_active   = 0;
static HANDLE g_battlemenu_thread = nullptr;
static HANDLE g_wallbump_thread   = nullptr;
static HANDLE g_dialogtone_thread = nullptr;
static HANDLE g_fieldnav_thread   = nullptr;
static HANDLE g_nameentry_thread  = nullptr;

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
// dotemuRegSetValueExA IAT hook — Sound sub-menu Left/Right value TTS.
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
//   etc.) have MENU_OPEN=0 or CONFIG_ROW≠1 and are forwarded silently.
//
// VALUE CACHING:
//   Updates g_sound_music_vol / g_sound_fx_vol on every matching call so
//   ConfigMenuThread can include the volume in Up/Down cursor announces.
//
// REGISTRY KEY NAMES:
//   "MusicVolume" — music volume slider (byte 0=silence, 127=maximum)
//   "SFXVolume"   — FX volume slider    (same scale)
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
// SetupSoundIATHook — patch FF7's IAT to intercept dotemuRegSetValueExA.
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
        // by name — FirstThunk holds runtime addresses, not IMAGE_IMPORT_BY_NAME
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
//   the first valid cursor position is always announced — regardless of what
//   value the BSS byte held during field mode.
//
// last_cursor SENTINEL UPDATE RULE:
//   last_cursor is updated ONLY inside the announce branches (values 0 and 1).
//   Non-0/1 BSS values (from other modules writing into the 0xDD segment) must
//   not advance the sentinel. If they did, a silent field-mode write of 0 or 1
//   could pin last_cursor, silencing the announcement when the title screen
//   later shows the same cursor position.
//
// KNOWN LIMITATION — initial splash announce:
//   Windows zero-initializes the 0xDD BSS segment before process start, so
//   TITLE_CURSOR == 0x00 (= New Game) during the company logo splash (~350ms).
//   With FIELD_ID also zero at that point, the first poll fires a "New Game"
//   announcement during the splash. last_cursor then equals 0, so when the
//   actual title screen appears with cursor=0, the change-check suppresses a
//   second announce. The user hears one premature cue and then must navigate
//   (Up/Down) to hear the position on the real title screen. This is an
//   inherent limitation of reading a BSS byte before the title module
//   initializes it; there is no in-process signal that distinguishes "splash"
//   from "title screen" at the byte level.
//
// Gated by Config::Get().speak_menus.
// ---------------------------------------------------------------------------
static DWORD WINAPI TitleCursorThread(LPVOID /*unused*/)
{
    uint8_t last_cursor = 0xFF;  // 0xFF = sentinel; triggers announce on first valid read

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
        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        if (field_id != 0) {
            last_cursor = 0xFF;
            continue;
        }

        // Safe dereference: 0x00DD6F24 is in the statically-allocated game BSS.
        const uint8_t curr =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::TITLE_CURSOR);

        if (curr == last_cursor) continue;

        // Update last_cursor only for values we announce, so non-0/1 BSS values
        // cannot pin the sentinel and cause a false negative on title re-entry.
        if (curr == 1) {
            last_cursor = curr;
            Log::Write("[FF7Access] TITLE cursor=1 (Continue)");
            TTS::Speak(L"Continue", /*interrupt=*/true);
        } else if (curr == 0) {
            last_cursor = curr;
            Log::Write("[FF7Access] TITLE cursor=0 (New Game)");
            TTS::Speak(L"New Game", /*interrupt=*/true);
        }
        // Other values are BSS data from unrelated modules — do not announce
        // and do not update last_cursor.
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Main-menu cursor polling thread.
//
// Polls FF7Addr::MENU_CURSOR (0x00CC1B42) and announces the highlighted
// main-menu option by name whenever the cursor moves.
//
// CURSOR INDEX → OPTION NAME (v2.31.1, player-corrected 2026-07-18):
//   0=Item  1=Magic  2=Materia  3=Equip  4=Status  5=Order  6=Limit
//   7=Config  8=PHS  9=Save  10=Quit
// The original 2026-07-01 table was built before the player could compare
// rows in game and OMITTED Materia — everything from Equip down was one
// row early ("equip, status, order and limit all need to move down 1; the
// selection directly under magic is not available yet" = the grayed
// Materia row). The shift also resolves both old "unlockable, identity
// TBD" slots: 6 is just Limit, 8 is PHS (grayed until the story grants
// it). Config=7 and Save=9 were correct in both tables — which is why the
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
//   speak on value-change — not on menu-open. The player can press a
//   direction to hear their current position if they re-open at the same row.
//   A "menu is open" flag (to re-announce on open) was not found during
//   investigation; locating it is noted as future work.
//
// UNKNOWN SLOTS 7–8:
//   These cursor indices exist but correspond to menu options not yet
//   unlocked in the game (likely PHS and one other). The thread skips them
//   silently and logs a diagnostic. Update kMenuLabels[] when confirmed.
//
// Gated by Config::Get().speak_menus.
// ---------------------------------------------------------------------------
static DWORD WINAPI MenuCursorThread(LPVOID /*unused*/)
{
    // Map cursor index → spoken label. nullptr entries are unlockable options
    // whose names are not yet confirmed; they are logged but not spoken.
    static const wchar_t* const kMenuLabels[] = {
        L"Item",     // 0
        L"Magic",    // 1
        L"Materia",  // 2 — grayed until the story grants materia
        L"Equip",    // 3
        L"Status",   // 4
        L"Order",    // 5
        L"Limit",    // 6
        L"Config",   // 7
        L"P H S",    // 8 — spaced so TTS spells the letters; grayed until granted
        L"Save",     // 9
        L"Quit",     // 10
    };
    static const uint8_t kMenuMax = 10;   // highest valid main-menu index

    // Quit confirmation dialog: 0=Yes  1=No  (No is the default on open).
    static const wchar_t* const kQuitLabels[] = { L"Yes", L"No" };
    static const uint8_t kQuitMax = 1;

    uint8_t last_cursor      = 0xFF;  // main-menu cursor; 0xFF = none announced
    uint8_t last_menu_open   = 0;
    uint8_t last_quit_cursor = 0xFF;  // quit-dialog cursor; 0xFF = none announced
    // Counts consecutive polls where MENU_OPEN=1. We require at least 2 before
    // treating MENU_OPEN as a real menu open. This prevents a single stale
    // MENU_OPEN=1 poll (the title-screen overlay briefly persisting into the
    // first field-load poll) from triggering the re-announce logic and
    // announcing "Item" (MENU_CURSOR BSS default = 0) before the player has
    // done anything.
    uint8_t menu_open_streak = 0;

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
        // non-zero (player-reported 2026-07-12: a false "Item" announce —
        // MENU_CURSOR's stale value — talked over NameEntryThread's own
        // screen-open announcement). GAME_MODE==6 identifies the naming
        // screen; that screen's TTS belongs to NameEntryThread, so stand
        // down completely while it is active. (Deliberately a narrow !=6
        // exclusion rather than requiring GAME_MODE==9: 9=menu is live-
        // confirmed for the field main menu, but other MENU_OPEN contexts
        // haven't been mode-sampled yet, and this project only trusts
        // live-observed GAME_MODE values.)
        const uint8_t menu_game_mode =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE);
        if (menu_game_mode == FF7Addr::GAME_MODE_NAME_ENTRY) {
            last_cursor      = 0xFF;
            last_menu_open   = 0;
            last_quit_cursor = 0xFF;
            menu_open_streak = 0;
            continue;
        }

        // ── Main menu ────────────────────────────────────────────────────────
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);

        if (menu_open == 0) {
            // v2.30.27: the menu closing ends any running tutorial —
            // clear the flag and cut whatever narration is still queued
            // (the player has moved on; finishing the lesson into the
            // field would talk over gameplay).
            if (Hooks::TutorialActive()) {
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

        // On the 0→1 transition of MENU_OPEN, force last_cursor to 0xFF so
        // the current position is announced immediately on re-open.
        // This fires on the 2nd consecutive poll of MENU_OPEN=1, when
        // last_menu_open is still 0 from the previous menu-close reset.
        if (last_menu_open == 0) {
            last_cursor = 0xFF;
        }
        last_menu_open = menu_open;

        // v2.35.1: the post-battle VICTORY screens also raise MENU_OPEN,
        // which made the open-re-announce speak the STALE menu row over
        // the victory announcements (player report). Stand down while the
        // results context is live: either VictoryThread says so, or the
        // "menu" opened within seconds of battle mode — the real main
        // menu is unreachable that fast. Seed silently so nothing stale
        // fires when the window ends.
        if (g_victory_active != 0 ||
            (GetTickCount() - g_last_battle_tick) < 4000) {
            last_cursor = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::MENU_CURSOR);
            last_quit_cursor = 0xFF;
            continue;
        }

        // v2.30.27: a menu TUTORIAL is running — the script drives the
        // cursor, and hook_tutor has already queued the lesson text.
        // Track state silently (so nothing stale fires when the
        // tutorial ends) but announce nothing over the narration.
        if (Hooks::TutorialActive()) {
            last_cursor = *reinterpret_cast<const volatile uint8_t*>(
                FF7Addr::MENU_CURSOR);
            last_quit_cursor = 0xFF;
            continue;
        }

        // ── Quit confirmation cursor (runs in parallel, no priority block) ──
        // QUIT_CURSOR tracks Yes (0) / No (1) while the Quit dialog is visible.
        // We intentionally do NOT gate this on a QUIT_OPEN flag: the initial
        // candidate (0x00DC0FB1) did not reliably return to 0 when the dialog
        // was dismissed with No, which caused the main menu to stop announcing.
        // Tracking QUIT_CURSOR in parallel here — without any continue — keeps
        // the main menu cursor logic running at all times.
        const uint8_t qcurr =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::QUIT_CURSOR);
        if (qcurr != last_quit_cursor) {
            if (qcurr <= kQuitMax) {
                last_quit_cursor = qcurr;
                char qdbg[80];
                _snprintf_s(qdbg, sizeof(qdbg), _TRUNCATE,
                    "[FF7Access] QUIT cursor=%u (%ls)", qcurr, kQuitLabels[qcurr]);
                Log::Write(qdbg);
                TTS::Speak(kQuitLabels[qcurr], /*interrupt=*/true);
            } else {
                last_quit_cursor = 0xFF;
            }
        }

        // ── Main menu cursor ─────────────────────────────────────────────────
        const uint8_t curr =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_CURSOR);

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

        // v2.32: the activation handler refuses rows whose bit is set in
        // the disabled-rows mask (disasm 0x6CA4CD — this is exactly what
        // grays Materia/PHS early game). Sighted players see the gray;
        // append the same information.
        const uint16_t disabled_rows =
            *reinterpret_cast<const volatile uint16_t*>(FF7Addr::MENU_DISABLED_ROWS);
        const bool row_disabled = ((disabled_rows >> curr) & 1u) != 0;

        wchar_t line[64];
        _snwprintf_s(line, _countof(line), _TRUNCATE, L"%ls%ls",
                     label, row_disabled ? L", not available" : L"");
        char dbg[96];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] MENU cursor=%u (%ls)%s", curr, label,
            row_disabled ? " disabled" : "");
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
// GATE — CONFIG_OPEN PROXY:
//   No dedicated "config sub-menu open" flag was found.  All symmetric-toggle
//   candidates from ff7_config_menu_scan.py Phase C fired on any main-menu
//   open event, identical to the existing MENU_OPEN (0x00DC12DC).  We gate
//   on MENU_CURSOR == 7 (the Config row in the main menu) as a proxy:
//     - In the config sub-menu: MENU_CURSOR is frozen at 7 and CONFIG_ROW
//       changes with Up/Down presses.  Thread tracks and announces.
//     - On the Config row of the main menu (before pressing Confirm): MENU_CURSOR
//       is also 7 but Up/Down moves the MAIN MENU cursor, not CONFIG_ROW.
//       CONFIG_ROW doesn't change → thread is active but stays silent. ✓
//     - On any other main-menu row: MENU_CURSOR ≠ 7 → thread skips. ✓
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
    // Never reset to 0xFF — see "FALSE-ANNOUNCE PREVENTION" note above.
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

        // Field must be active — config sub-menu only reachable from a field map.
        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        if (field_id == 0) continue;

        // Main menu (and therefore config sub-menu) requires MENU_OPEN.
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        if (menu_open == 0) continue;

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
            // Battle speed: raw byte 0–255 (0=Fast, 255=Slow)
            new_value = *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_SPEED_BATTLE);
            _snwprintf_s(val_str, _countof(val_str), _TRUNCATE, L"%u", new_value);
            break;
        }
        case 6: {
            // Battle message: raw byte 0–255 (0=Fast, 255=Slow)
            new_value = *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_SPEED_MSG);
            _snwprintf_s(val_str, _countof(val_str), _TRUNCATE, L"%u", new_value);
            break;
        }
        case 7: {
            // Field message: raw byte 0–255 (0=Fast, 255=Slow)
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
            // Magic order: bits 4:2 of CONFIG_PACKED_CAMERA_MAGIC (0–5 → No.1–No.6)
            const uint8_t packed =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::CONFIG_PACKED_CAMERA_MAGIC);
            new_value = (packed >> 2) & 7;
            _snwprintf_s(val_str, _countof(val_str), _TRUNCATE, L"No. %u", new_value + 1u);
            break;
        }
        default:
            break;  // rows 0, 1, 2: new_value stays 0xFFFF, val_str stays empty
        }

        // ── Sound sub-menu cursor (Up/Down between Music and FX sliders) ─────
        // Runs independently of the row-value check below so a cursor navigation
        // that leaves CONFIG_ROW unchanged is still caught.
        //
        // Guards:
        //   first_obs (last_sound_cursor==0xFF): silently establishes baseline
        //     on the first poll after entering CONFIG_ROW==1, preventing a false
        //     announce caused by the retained cursor byte from a prior session.
        //   sc > 1: out-of-range — ignore; do not update sentinel so the next
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

        // Row navigation → "Row name, value" (or just row name for untracked rows).
        // Left/Right within a row → just the value string.
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
// title block (ff7_continue_menu_scan.py) — each grid cursor was
// live-verified by its scan's speak-back pass, and both instances share
// the same +0x3C grid→slot struct spacing. See ff7_addresses.h
// SAVEMENU_* / LOADMENU_*.
//
// The slot PREVIEW data (what the sighted player sees per slot: lead
// character, level, location, play time, gil, party portraits) is read
// from the save FILES themselves, not from game memory: the menu renders
// from saveNN.ff7 on disk, whose layout was derived from the player's own
// save00.ff7 against screenshot ground truth (research doc §5 "Save file
// (.ff7) slot-preview layout", ff7_savefile_preview_derive.py). Files are
// re-read on every announce — 65 KB a press is nothing, and it means a
// just-written save can never be announced stale.
//
// ANNOUNCE MODEL (change-only, the MenuCursorThread rule): neither menu
// has a known "just opened" flag — in save mode the gate (MENU_OPEN=1
// with MENU_CURSOR frozen on the Save row, the Config-submenu signature)
// becomes true while the player is still browsing the main menu, and at
// the title nothing observable distinguishes the Continue grid from the
// plain title screen (continue_menu_verify: every known byte constant).
// So: cursor moves and pane changes announce; entering the slot list
// announces "Game N" plus the slot under the cursor; everything is
// range-guarded — any out-of-range value (grid>9, slot>14, phase>1)
// means some other module owns those bytes right now — reset and stay
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

// .ff7 layout constants — every one verified against the real file
// (research doc §5): 9-byte header, 15 slots of 0x10F4, preview at the
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
// pattern as Config::Load / PlacesFilePath — immune to CWD games).
// Returns false if the file is absent or malformed; out[] is then all
// unused, which speaks as an empty file — exactly what the sighted menu
// shows for a file that was never saved to.
static bool ReadSaveFilePreviews(int file_idx, SaveSlotPreview out[/*15*/])
{
    memset(out, 0, sizeof(SaveSlotPreview) * kSaveSlotCount);

    HMODULE hSelf = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&ReadSaveFilePreviews), &hSelf);
    char path[MAX_PATH] = {};
    GetModuleFileNameA(hSelf, path, MAX_PATH);
    char* sep = strrchr(path, '\\');
    if (sep) *(sep + 1) = '\0';
    char full[MAX_PATH];
    _snprintf_s(full, sizeof(full), _TRUNCATE, "%ssave\\save%02d.ff7",
                path, file_idx);

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

// "1 hour 5 minutes" / "21 minutes" — the menu's HH:MM, made speakable.
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
// 21 minutes, 376 gil, with Barret" — the whole sighted preview minus
// HP/MP (menu-identity noise). Non-lead party from the portrait ids via
// the DEFAULT names (the lead's name is the saved text; the others'
// renames are not in the preview block — default names are the honest
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

        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        const uint8_t menu_cursor =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_CURSOR);

        // TWO menu implementations, one speaker (live-proven 2026-07-17:
        // the title Continue menu does NOT share the save menu's state —
        // continue_menu_verify log — it has its own instance in the TITLE
        // block, found by continue_menu_scan the same day):
        //   SAVE mode — in-field menu module, gated by the frozen-row
        //   signature (MENU_OPEN=1, MENU_CURSOR held at 9, FIELD_ID!=0).
        //   LOAD mode — title context (FIELD_ID==0).
        // The PANE for BOTH comes from LOADMENU_LIST_PTR (nonzero = the
        // slot list is open; it is the loaded file's heap pointer, and
        // both scans observed it independently — nonzero-check only,
        // never deref). The per-menu phase byte 0xDC1210 is DISPROVED:
        // it oscillates in real use, which made v2.29.1 alternate the
        // two pane announcements endlessly (player report).
        //
        // The slot position is ROW (0..2 visible window) + SCROLL
        // (0..12) — the "only 3 slots" player report; scroll offsets per
        // ff7_slot_scroll_probe.py (title instance live-confirmed; save
        // instance inferred at the same struct offset +0x10).
        //
        // The FILE position is likewise split (v2.29.3, the "second row
        // counts wrong" player report): GRID_CURSOR is the COLUMN 0..4,
        // the 5×2 grid's row a separate byte at grid+4: 0 = top row
        // (Save 1-5), 1 = bottom row (Save 6-10). File index =
        // rowbyte*5 + column. (v2.29.4: the first reading was inverted —
        // the probe's baseline of 1 was the player already PARKED on the
        // bottom row, not the top; their play report of Save 6 spoken on
        // the top row is the decisive observation.)
        const bool save_mode =
            menu_open == 1 && menu_cursor == 9 && field_id != 0;

        // v2.29.5: the "Are you sure you want to save?" Yes/No dialog.
        // Widget-state byte 0xDCA028 == 7 while it is open (1 = slot
        // list — it is the save menu's little state machine, the SINGLE
        // A/B/A candidate of ff7_save_confirm_scan 2026-07-17); cursor
        // 0xDC6C6C 0=Yes 1=No, speak-back verified. The slot-row byte
        // holds still during the dialog (same scan log), so this block
        // runs FIRST and short-circuits the pane/cursor logic below
        // while the dialog is up. Save mode only — the Continue menu
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
        } else if (field_id == 0) {
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
        // Save row — announcing then would talk over MenuCursorThread's
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
            // while the list is open — scan-verified). Back to the grid:
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
// "Machine Gun", "Braver") by replicating the game's own dispatcher — see the
// v2.7 resolution notes in ff7_addresses.h (SECTION 1c) for the full data-flow
// derivation (kernel2_consumer_disasm / action_name_final_verify, 2026-07-11).
//
// WHY POLLING (not a function hook):
//   FFNx trampolines display_battle_action_text_42782A (0x42782A) and
//   sub_6D71FA (0x6D71FA).  Hooking those entry points would intercept FFNx,
//   not the game.  Polling reads the same data with no patching.
//
// ACTOR VALIDITY:
//   Party slots 0–2; enemy slots 4–9.  Slot 3 never appears.
//   g_active_actor_id initialises to 0 at process start and is never reset
//   between battles; commandID==0 is the only reliable "not in battle" gate.
//   The first action of a new battle is announced because actor_id changes;
//   a new battle whose first actor equals the previous battle's last actor
//   misses that one action (accepted).
//
// ANNOUNCE TIMING (why announcements are two-phase):
//   The turn STARTS when g_active_actor_id changes, but the flash-message
//   struct (battle_actor_data 0xDC38E0) is only written ~1–2s later, when the
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
//       resolved (repeated-flash case — values are still correct); otherwise
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
// ⚠ LIFETIME (v2.22.1, from the 2026-07-16 play-session log): "scan once,
// cache forever" is TRUE for magic/item/weapon (one resident block, stable
// all session) but FALSE for the COMMAND section — it lives in a TRANSIENT
// battle allocation that is freed and reused between battles. The cached
// pointer then decodes reused binary as a "name" that passes every
// structural check in SectionEntryText, and the battle menu spoke garbage
// ("-Û+! ' $...") on menu open in the affected battles. Every pointer is
// therefore RE-VALIDATED on each use via ValidatedSection() below; a stale
// pointer is dropped (rate-limited rescan re-finds the live one) and the
// caller falls back to its generic label — degraded, never garbage.
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
    // sighted menu shows a description bar — three more sections, same
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
    // 2026-07-26 — it is the F9-expanded PC text, which is why the heap
    // copies contain plain strings): materia names [0]="MP Plus",
    // [1]="HP Plus"; materia descs [0]="Increases MP capacity"; weapon
    // descs [0]="Initial equipment" (kernel.bin's "Initial equiping" is
    // the PSX-era text — the PC runtime uses kernel2's spelling). Armor
    // descriptions have a BLANK entry 0 (single space) so no signature can
    // find them — armor rows just get no description, exactly what a
    // sighted player sees (the bar is blank for armor too).
    const uint8_t* materia_name;  // entries 0-95 materia names
    const uint8_t* materia_desc;  // entries 0-95 materia descriptions
    const uint8_t* weapon_desc;   // entries 0-127 weapon descriptions
    const uint8_t* accessory_desc;// entries 0-31 accessory descriptions
                                  // (head bytes include the 0xB2/0xB3
                                  // colour codes -> raw-byte signature)
};
static Kernel2Sections g_k2 = { nullptr, nullptr, nullptr, nullptr,
                                nullptr, nullptr, nullptr,
                                nullptr, nullptr, nullptr, nullptr };

// Raw-byte section signature for the accessory descriptions: entry 0 is
// "<0xB2>Strength<0xB3> +10" (kernel2.bin ground truth) — the colour-code
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
// x86) but each scan walks the whole address space — the guard just prevents
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

// Re-verify a cached kernel2 section pointer before EVERY use (v2.22.1).
//
// WHY: the command-name section is a transient battle allocation (see the
// Kernel2Sections lifetime note) — after the game frees and reuses it, the
// cached pointer still "looks like" a section to SectionEntryText's
// structural checks and decodes reused binary as a speakable name. The one
// check garbage cannot pass is the section's own HEAD SIGNATURE: u16[base]
// is the offset of entry 0, and entry 0 must still begin with the exact
// encoded strings FindSectionBase matched ("Attack|Magic|" etc.) — the
// identical self-validating rule that located the section in the first
// place, now applied at read time.
//
// On mismatch the slot is NULLED so the callers' rate-limited rescan can
// re-find the live copy; this call returns nullptr and the caller uses its
// generic fallback label. Cost: one ~13-byte encode+memcmp per menu/action
// event — noise. Cross-thread: two battle threads may race on *slot; both
// only ever write nullptr here, and aligned pointer stores are atomic on
// x86 (same argument as the scan guard above).
static const uint8_t* ValidatedSectionBytes(const uint8_t** slot,
                                            const uint8_t* sig, size_t sig_len,
                                            const char* debug_label)
{
    const uint8_t* base = *slot;
    if (!base)
        return nullptr;

    bool ok = false;
    if (IsReadableSpan(base, 2)) {
        uint16_t first_off;
        memcpy(&first_off, base, sizeof(first_off));
        ok = first_off >= 2 && first_off <= 0x800 &&  // FindSectionBase range
             IsReadableSpan(base + first_off, sig_len) &&
             memcmp(base + first_off, sig, sig_len) == 0;
    }
    if (!ok) {
        char dbg[128];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] kernel2 section STALE ('%s' head gone at %p) — "
            "dropped for rescan", debug_label, base);
        Log::Write(dbg);
        *slot = nullptr;
        return nullptr;
    }
    return base;
}

// ASCII-signature wrapper — the original v2.22.1 entry point; the raw-byte
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
// This rule self-validates — a false positive requires u16[cand] to equal its
// own distance to an accidental signature match, which live scans never hit.
static const uint8_t* FindSectionBase(const uint8_t* region, size_t size,
                                      const uint8_t* sig, size_t sig_len)
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
            if (first_off == back)
                return cand;
        }
    }
    return nullptr;
}

// Scan this process's committed private read-write memory for the kernel2
// text sections.  Runs from our own polling thread INSIDE the game process,
// so all reads are direct pointer reads.  Called lazily on the first battle
// action and retried (rate-limited) while any section is missing — kernel2
// is decompressed during startup and stays resident for the process lifetime,
// so one successful scan is permanent.
//
// ENGLISH-ONLY: the signatures are the English section heads.  On a non-
// English kernel2 the scan finds nothing and every action falls back to the
// v2.5 generic labels — degraded, never wrong.
static void ScanKernel2Sections()
{
    // Skip if another thread is mid-scan (see g_k2_scan_busy comment).
    if (InterlockedCompareExchange(&g_k2_scan_busy, 1, 0) != 0)
        return;

    uint8_t sig_magic[24], sig_item[24], sig_weapon[24], sig_command[24];
    uint8_t sig_armor[24], sig_access[24], sig_idesc[24];
    uint8_t sig_mname[24], sig_mdesc[24], sig_wdesc[24];
    const size_t len_magic  = EncodeSignature("Cure|Cure2|",        sig_magic,  sizeof(sig_magic));
    const size_t len_item   = EncodeSignature("Potion|Hi-Potion|",  sig_item,   sizeof(sig_item));
    const size_t len_weapon = EncodeSignature("Buster Sword|",      sig_weapon, sizeof(sig_weapon));
    // Command-name section head: entries 0,1,... are "Attack","Magic",...
    // stored back-to-back like every other kernel2 text section.
    const size_t len_command = EncodeSignature("Attack|Magic|",     sig_command, sizeof(sig_command));
    // v2.31 item-menu sections. Armor/accessory heads are kernel entry 0
    // ("Bronze Bangle"/"Power Wrist", both present in walkthrough.txt);
    // the item-description head is Potion's caption, ground-truthed by
    // items_menu_1.png. Signature-or-fallback as always.
    const size_t len_armor  = EncodeSignature("Bronze Bangle|",       sig_armor,  sizeof(sig_armor));
    const size_t len_access = EncodeSignature("Power Wrist|",         sig_access, sizeof(sig_access));
    const size_t len_idesc  = EncodeSignature("Restores HP by 100|",  sig_idesc,  sizeof(sig_idesc));
    // v2.30.28 shop sections — heads ground-truthed from kernel2.bin (the
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
            !g_k2.accessory_desc)) {
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
            break;
        const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        // Only committed, private (heap — excludes the exe/DLL images, whose
        // .data contains battle-menu inventory copies that would false-match),
        // plain read-write pages.  Guard pages (stack tips) are excluded by
        // the exact protection match.
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            mbi.Protect == PAGE_READWRITE) {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(base);
            if (!g_k2.magic)   g_k2.magic   = FindSectionBase(p, mbi.RegionSize, sig_magic,   len_magic);
            if (!g_k2.item)    g_k2.item    = FindSectionBase(p, mbi.RegionSize, sig_item,    len_item);
            if (!g_k2.weapon)  g_k2.weapon  = FindSectionBase(p, mbi.RegionSize, sig_weapon,  len_weapon);
            if (!g_k2.command) g_k2.command = FindSectionBase(p, mbi.RegionSize, sig_command, len_command);
            if (!g_k2.armor)     g_k2.armor     = FindSectionBase(p, mbi.RegionSize, sig_armor,  len_armor);
            if (!g_k2.accessory) g_k2.accessory = FindSectionBase(p, mbi.RegionSize, sig_access, len_access);
            if (!g_k2.item_desc) g_k2.item_desc = FindSectionBase(p, mbi.RegionSize, sig_idesc,  len_idesc);
            if (!g_k2.materia_name)   g_k2.materia_name   = FindSectionBase(p, mbi.RegionSize, sig_mname, len_mname);
            if (!g_k2.materia_desc)   g_k2.materia_desc   = FindSectionBase(p, mbi.RegionSize, sig_mdesc, len_mdesc);
            if (!g_k2.weapon_desc)    g_k2.weapon_desc    = FindSectionBase(p, mbi.RegionSize, sig_wdesc, len_wdesc);
            if (!g_k2.accessory_desc) g_k2.accessory_desc = FindSectionBase(p, mbi.RegionSize, kAccessoryDescSig, sizeof(kAccessoryDescSig));
        }
        addr = base + mbi.RegionSize;
    }

    char dbg[320];
    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
        "[FF7Access] kernel2 section scan: magic=%p item=%p weapon=%p command=%p "
        "armor=%p accessory=%p item_desc=%p mat_name=%p mat_desc=%p "
        "weap_desc=%p acc_desc=%p",
        g_k2.magic, g_k2.item, g_k2.weapon, g_k2.command,
        g_k2.armor, g_k2.accessory, g_k2.item_desc,
        g_k2.materia_name, g_k2.materia_desc,
        g_k2.weapon_desc, g_k2.accessory_desc);
    Log::Write(dbg);

    InterlockedExchange(&g_k2_scan_busy, 0);
}

// Decode entry `entry` of a kernel2 text section into `out`.
// Returns false (leaving generic-label fallback to the caller) when the
// section is missing, the entry is out of table bounds, or the text is
// empty/blank — never returns a wrong or garbage name.
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
    // parameter byte to decode as a stray character — skip both here.
    if (text[0] == 0xF8)
        text += 2;
    if (text[0] == 0xFF)
        return false;
    out = FF7Text::Decode(reinterpret_cast<const char*>(text));
    for (wchar_t c : out)
        if (c != L' ')
            return true;
    return false;   // blank/whitespace-only entry (padding) — treat as no name
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

    // v2.22.1: revalidate the cached section pointers at USE time — a
    // freed-and-reused section must fall back to generic labels, never
    // decode reused memory (see ValidatedSection / the lifetime note).
    const uint8_t* const k2_magic  = ValidatedSection(&g_k2.magic,  "Cure|Cure2|");
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
              // names ('Choco/Mog'…'Knights of Round', verified live), so
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
    case 6:   // cmd 0x0D Enemy Skill: magic entries 72-95 ('Frog Song'…)
        return SectionEntryText(k2_magic, idx + 72, out);
    case 7:   // cmd 0x14 Limit Break: magic entries 128+ ('Braver'…)
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
    default:  // branch 9 (Attack/Steal/… — no flash text) or unknown
        return false;
    }
}

// Generic command labels — the v2.5 fallback, used when no exact name exists
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
// Replicates get_kernel_text section 7 — the game's OWN target-name lookup,
// found by static disassembly of the section jump table at 0x419A38
// (investigate/ff7_target_name_disasm.py, 2026-07-13; details in
// ff7_addresses.h SECTION 1c3). Chain: formation slot table (u16 record
// index per enemy slot) -> loaded scene.bin enemy record (stride 0xB8,
// FF7-encoded name in bytes 0-0x1F) -> duplicate-type letter suffix
// ("MP A" / "MP B"), so two same-type enemies stay distinguishable by ear
// exactly as they are on screen.
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
    // decode per byte under the length cap — the game itself copies at most
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
    // the game renders base-char + index, i.e. 0='A', 1='B', ...
    const uint8_t letter = *reinterpret_cast<const volatile uint8_t*>(
        FF7Addr::BATTLE_DUP_LETTER_TABLE +
        static_cast<uint32_t>(slot) * FF7Addr::BATTLE_DUP_LETTER_STRIDE);
    if (letter != 0xFF && letter < 26) {
        out += L' ';
        out += static_cast<wchar_t>(L'A' + letter);
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
// Pre-v2.19 the battle threads could only name party slot 0 (PARTY_LEADER →
// hardcoded default names); slots 1-2 were positional "ally 2"/"ally 3" —
// the user's play test heard Barret announced as "ally 2" all through the
// reactor. The savemap has had everything needed all along (TODO.txt's
// party-KO entry predicted this): the three party-member character IDs at
// SAVEMAP_PARTY_IDS, and each character's LIVE name (renames included) in
// their character record. See ff7_addresses.h SECTION 1b for the layout
// derivation and the cross-check that guards it.
// ---------------------------------------------------------------------------

// Read character `char_id`'s current name from its savemap record.
// Returns false when the name is empty/undecodable (zeroed savemap before
// any save is loaded, or an ID with no record) — callers then fall back.
static bool SavemapCharName(uint8_t char_id, std::wstring& out)
{
    // Flashback aliases: Young Cloud (9) and Sephiroth (10) have no records
    // of their own — the game stores their data in Cait Sith's and Vincent's
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

    // Per-byte decode (FF7 encoding, 0xFF terminator, hard 12-byte cap) —
    // same approach as the name-entry echo; Decode() is dialog-oriented
    // (token expansion) and wrong for a fixed name field.
    std::wstring decoded;
    for (uint32_t i = 0; i < FF7Addr::SAVEMAP_CHAR_NAME_LEN && name[i] != 0xFF; ++i) {
        const wchar_t ch = FF7Text::DecodeChar(name[i]);
        if (ch != L'\0')
            decoded += ch;
    }

    // A zeroed record decodes to all spaces (byte 0x00 = ' ') — trim, and
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
//   2. the default English name for the ID (savemap name blank — in practice
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
// 114427 — every pass a single intersected candidate — plus the dispatcher
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
    if (maxhp == 0)   // zeroed savemap (no save loaded) — numbers meaningless
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
// (ff7_shop_static.py — provenance in ff7_addresses.h's SHOP block): the
// shop is its own top-level menu-module branch selected by GAME_MODE == 8,
// NOT a menu_subs_call_table screen, with a 7-state loop at 0x71AAA3 whose
// state variable, cursor widgets, catalog, and price table all fell out of
// the annotated dump. Shipped static-first with debug logging as the live
// verify — the same discipline as v2.32's FOCUS_MODE and v2.34's timer.
// ---------------------------------------------------------------------------

// Materia name / description via the kernel2 sections (heads ground-truthed
// from kernel2.bin — see the Kernel2Sections comment).
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
// the caller speaks its no-description line — same info a sighted player
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
// here — this feeds the buy screen's "own N" hint, not the full Owned+
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
// past the shop's ware count (or on an insane shop id — the catalog region
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
// at id*4, materia at +0x600). Pointer-validated every read — it is a heap
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
// pointer is not live — degraded, never wrong.
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
// ("Price through AP" on the sighted panel — screenshot-verified: Restore
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

        // Kernel2 sections are needed for every name — kick the scan early
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

            // "<Shop name>. <Greeting>" — both FF7-encoded statics in the
            // exe's own .data (catalog provenance in ff7_addresses.h).
            const uint32_t name_idx = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::SHOP_NAME_IDX);
            const uint32_t text_idx = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::SHOP_TEXT_IDX);
            std::wstring greet;
            if (name_idx < 32) {
                // Shop titles are packed 0x14 bytes apart and may use the
                // full width — copy out and force a terminator.
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

        // ── Screen-state transitions ─────────────────────────────────────
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
            // instead of interrupting it — the greeting is one sentence and
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
            default: break;   // unmapped value — logged above, stay quiet
            }
        }

        // ── Per-screen cursor tracking ───────────────────────────────────
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
        case 2: {   // sell item list — idx formula from the confirm handler
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

        // ── I key: description of the highlighted ware (FF4-scheme parity:
        // "I: In shop menus, reads description of highlighted item") ──────
        DWORD fg_pid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &fg_pid);
        const bool focused = (fg_pid == GetCurrentProcessId());
        const bool i_down  = (GetAsyncKeyState('I') & 0x8000) != 0;
        const bool i_edge  = focused && i_down && !i_was_down;
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
// G key — announce current gil (FF4-scheme parity: "G: Announce current
// Gil"). Works any time a game is loaded: field, menus, shops, battle. The
// gil dword is savemap+0xB7C — live-proven by the v2.35 victory total and
// the shop's own buy/sell arithmetic.
// ---------------------------------------------------------------------------
static DWORD WINAPI GilKeyThread(LPVOID /*unused*/)
{
    bool g_was_down = false;

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        DWORD fg_pid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &fg_pid);
        const bool focused = (fg_pid == GetCurrentProcessId());
        const bool down    = (GetAsyncKeyState('G') & 0x8000) != 0;
        const bool edge    = focused && down && !g_was_down;
        g_was_down = down;
        if (!edge)
            continue;

        // No game loaded -> the savemap is zeroed and "0 gil" would be a
        // lie about a game that doesn't exist yet. The naming screen gets
        // typed letters — G there is text entry, not a query.
        const int16_t field_id = *reinterpret_cast<const volatile int16_t*>(
            FF7Addr::FIELD_ID);
        const uint8_t game_mode = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::GAME_MODE);
        if (field_id == 0 || game_mode == FF7Addr::GAME_MODE_NAME_ENTRY)
            continue;

        const uint32_t gil = *reinterpret_cast<const volatile uint32_t*>(
            FF7Addr::SAVEMAP_GIL);
        wchar_t msg[32];
        _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"%lu gil",
                     static_cast<unsigned long>(gil));
        TTS::Speak(msg, true);
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
                                   // cursor stays put — re-announce so the
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

        // Gate: main menu open, in field, and the dispatcher is running the
        // ITEM sub-screen. The dispatch index is the menu module's own
        // "which screen" variable (see ff7_addresses.h) — but its value on
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
            // v2.35.1: victory screens raise MENU_OPEN with a STALE
            // dispatch index — if the last screen visited was Item, this
            // gate would false-open over the victory announcements.
            g_victory_active != 0 ||
            (GetTickCount() - g_last_battle_tick) < 4000 ||
            // v2.30.27: a menu TUTORIAL drives the screens itself —
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
            // the ITEM LIST — player-corrected flow 2026-07-18).
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
                    // Description bar parity (items only — the sighted bar
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
            // the pane stays open — the player can use several in a row.
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
            // Unmapped mode (Arrange popup? Key Items pane?) — stay silent,
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
// the party pane — no dispatch change, no confirm chime (player-observed;
// proven by the 0x6CA346 handler disasm — provenance in ff7_addresses.h at
// the ORDERMENU block). MENU_FOCUS_MODE drives everything:
//   0 = menu bar (MenuCursorThread's domain — silent here)
//   1 = character-select pane (Magic/Equip/Status/... rows): speak the
//       pane cursor by name so "whose screen?" is audible
//   2 = Order pane: full flow — member + position + row on cursor moves,
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
    return nullptr;   // unexpected value — say nothing rather than guess
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
    // Data snapshot taken when the latch sets, diffed when it clears —
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

        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        const uint32_t screen =
            *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MENU_DISPATCH_INDEX);
        if (menu_open != 1 || field_id == 0 || screen != 0) {
            last_focus = 0xFF;
            latch_armed = false;
            continue;
        }

        const uint8_t focus =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_FOCUS_MODE);

        // v2.30.27: tutorial scripts move menu focus too — track
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
                // couldn't see — FOCUS_MODE is written silently at 0x6CA526).
                // last_focus != 0xFF: only a REAL bar→pane transition — a
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
                // real transition (not gate-open with stale 1) — the chime
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
            // mid-selection — drop the pending outcome.
            latch_armed = (focus == 2) ? latch_armed : false;
            continue;   // announce settled; next poll resumes tracking
        }

        if (focus == 2) {
            // ── Order pane ──────────────────────────────────────────────
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
                    // Speak the resulting order — the outcome the player
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
            // ── Character-select pane ───────────────────────────────────
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
//   mode → 1: "Victory! Gained X experience and Y A P." (pools CAPTURED at
//             results entry — the game consumes them on apply, see the
//             BATTLE_END_MODE block in ff7_addresses.h)
//   level bytes changing during the results window: "<name> grew to
//             level N!" (savemap watcher — catches multi-level-ups)
//   mode → 3: "Gained X gil, total Y." + drop item names ("No items"
//             when the list is empty)
// All state transitions debug-logged (mode value 2's on-screen meaning is
// not yet known; the log will name it).
// ---------------------------------------------------------------------------
static DWORD WINAPI VictoryThread(LPVOID /*unused*/)
{
    uint16_t last_mode   = 0xFFFF;
    bool     in_results  = false;
    uint32_t cap_exp = 0, cap_ap = 0, cap_gil = 0;   // pools captured at entry
    uint8_t  base_levels[3] = {};                    // level bytes at entry
    bool     spoke_gil   = false;

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
            g_victory_active = 0;
            last_mode = 0xFFFF;
            continue;
        }

        // The results screens run under the menu module with MENU_OPEN=1
        // (the v2.8.3 observation). Outside that window the mode global is
        // stale — transitions are only trusted inside it.
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        if (menu_open != 1) {
            in_results = false;
            g_victory_active = 0;
            last_mode = 0xFFFF;
            continue;
        }

        // v2.35.2 (player report: announcements trailed the button-driven
        // flow): the mode byte advances on the player's OK presses, not
        // when screens APPEAR — the EXP/AP screen shows during mode 0
        // (waiting for OK), mode 1 is the roll-up itself (the chirps), the
        // gil/items screen shows at mode 2, and 3 only lands after its OK.
        // So the victory line fires at the RESULTS WINDOW OPENING (the
        // post-battle MENU_OPEN rise, identified by the v2.35.1 battle-
        // recency signal), while the pools are provably intact; the
        // gil/items line fires entering mode 2 (fallback 3, whichever is
        // seen first — semantics harvested from the transition log).
        const uint16_t mode =
            *reinterpret_cast<const volatile uint16_t*>(FF7Addr::BATTLE_END_MODE);

        if (!in_results &&
            (GetTickCount() - g_last_battle_tick) < 4000) {
            // The results window just opened. Capture the pools NOW —
            // the roll-up consumes them — and announce before the
            // player's first OK starts the chirping count-up.
            in_results = true;
            g_victory_active = 1;   // v2.35.1 suppressor, whole window
            spoke_gil = false;
            last_mode = mode;
            cap_exp = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::BATTLE_GAINED_EXP);
            cap_ap = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::BATTLE_GAINED_AP);
            cap_gil = *reinterpret_cast<const volatile uint32_t*>(
                FF7Addr::BATTLE_GAINED_GIL);
            for (uint8_t s = 0; s <= 2; ++s)
                base_levels[s] = slot_level(s);
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "[FF7Access] VICTORY window open: mode=%u exp=%lu ap=%lu gil=%lu",
                mode, static_cast<unsigned long>(cap_exp),
                static_cast<unsigned long>(cap_ap),
                static_cast<unsigned long>(cap_gil));
            Log::Write(dbg);
            if (cap_exp <= 1000000 && cap_ap <= 1000000) {
                wchar_t msg[96];
                _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                    L"Victory! Gained %lu experience and %lu A P",
                    static_cast<unsigned long>(cap_exp),
                    static_cast<unsigned long>(cap_ap));
                TTS::Speak(msg, /*interrupt=*/true);
            } else {
                Log::Write("[FF7Access] VICTORY pools implausible — silent");
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

        // Level-up watcher: active through the whole results window.
        if (in_results) {
            for (uint8_t s = 0; s <= 2; ++s) {
                const uint8_t lv = slot_level(s);
                if (lv > base_levels[s] && base_levels[s] != 0) {
                    base_levels[s] = lv;
                    wchar_t label[64];
                    PartySlotLabel(s, label, _countof(label));
                    wchar_t msg[96];
                    _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                        L"%ls grew to level %u!", label,
                        static_cast<unsigned>(lv));
                    char dbg[96];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] VICTORY level up slot=%u -> %u", s, lv);
                    Log::Write(dbg);
                    // Queue behind the victory line, never clobber it.
                    TTS::Speak(msg, /*interrupt=*/false);
                }
            }
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// COUNTDOWN TIMER announcements + freeze (v2.34, 2026-07-18).
//
// The timed-escape clock (first: the No.1 Reactor run). Value = u32 WHOLE
// SECONDS at savemap+0xB84, written by the STTIM opcode as h*3600+m*60+s
// and ticked down ~1/sec — all established STATICALLY before the first
// timer was reachable in play (provenance: ff7_addresses.h COUNTDOWN
// block). This thread was therefore shipped SPECULATIVELY with heavy debug
// logging; the player's first real escape run is the live verify.
//
// ANNOUNCEMENTS (user spec, config timer_announcements):
//   start → "Timer started, N minutes S seconds"; every minute boundary →
//   "N minutes remaining"; 30s → "30 seconds"; final 10 → bare numbers;
//   0 → "Time is up". Battle announces QUEUE (interrupt=false) behind
//   battle speech except the final countdown, which always interrupts —
//   in the last ten seconds the clock outranks everything.
//
// RUNNING DETECTION is behavioral: the value must be nonzero AND have
// decreased recently. A stale savemap value (loaded save, finished escape)
// never decreases, so it can never false-start the announcer — the same
// never-trust-a-static-snapshot rule as the wall-tone fix.
//
// KEYS (accessiblity_keys.txt, FF1-6 parity — same focus/edge discipline
// as FieldNavThread): T = announce time left on demand ("No active timer"
// when none). Shift+T = FREEZE toggle — the mod's first gameplay memory
// WRITE: while frozen, the countdown value is rewritten every poll, which
// freezes the on-screen clock (it renders from this value) and keeps
// field-script time checks satisfied indefinitely. The write targets
// plain savemap data, not code — no protection change needed.
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
    // coarse for hotkey EDGE detection — a two-key Shift+T press releases
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

        // ── Freeze: hold the clock every poll while enabled ─────────────
        // v2.34.1: pin BOTH the seconds AND the sub-second accumulator.
        // The seconds alone isn't enough — the game keeps advancing the ms
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

        if (val > kMaxSane) {   // garbage (pre-init) — ignore entirely
            have_last = false;
            running = false;
        } else if (!Hooks::SttimSeen()) {
            // v2.30.8: no live STTIM call observed yet THIS PROCESS RUN —
            // this savemap field can hold a STALE value left over from an
            // earlier session's save (player report 2026-07-20: loading
            // into the slums, well past the No.1 Reactor escape, made the
            // timer "start again immediately" — the escape had ended with
            // time still on the clock, and that value just kept ticking in
            // the background across the save, invisible in vanilla FF7
            // since its on-screen clock window closed with the escape).
            // last_val/have_last still get updated unconditionally below
            // (so a REAL STTIM later doesn't read as a spurious "jump"),
            // but this branch deliberately does NOT touch last_change or
            // `running` — leaving both alone keeps timer_live false (see
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
            // (fresh-launch load of a post-escape save — the suppression
            // demonstrably worked, but only field-trail inference proved a
            // ticking value was even present). It also cannot distinguish
            // the v2.30.8 RESIDUAL (a save made DURING a countdown, loaded
            // fresh — a REAL timer the gate would wrongly silence; only
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
                // Jump (new STTIM, save load, script rewrite) — re-detect.
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

        // ── T / Shift+T (focus-gated edges, as FieldNavThread) ──────────
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
        // v2.34.1: one line per T press — ground truth if anything still
        // misbehaves (shift read, live-detection, freeze state).
        char kdbg[112];
        _snprintf_s(kdbg, sizeof(kdbg), _TRUNCATE,
            "[FF7Access] TIMER key T shift=%d frozen=%d running=%d live=%d val=%lu",
            shift ? 1 : 0, frozen ? 1 : 0, running ? 1 : 0,
            timer_live ? 1 : 0, static_cast<unsigned long>(val));
        Log::Write(kdbg);

        if (!shift) {
            // T: on-demand time readout.
            if (frozen)
                TimerSpeakRemaining(frozen_val, L"Timer frozen. ");
            else if (timer_live)
                TimerSpeakRemaining(val, L"");
            else
                TTS::Speak(L"No active timer", /*interrupt=*/true);
        } else {
            // Shift+T: freeze toggle.
            if (!frozen) {
                if (timer_live) {
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
// once on entry (and again if the viewed character somehow changes) — the
// screen-reader equivalent of what a sighted player takes in at a glance.
//
// Numbers come from two places (provenance: ff7_addresses.h v2.33 notes):
//   savemap record  — level, EXP/next, limit level, equipment ids, and the
//                     BASE stats (fallback only);
//   char-data block — EFFECTIVE stats + derived Attack/Defense/Magic
//                     atk/def (what the screen actually shows; Cloud's
//                     materia made record and screen disagree, so base
//                     stats alone would contradict a sighted helper).
// The block is trusted only when its HP/maxHP words equal the savemap
// record's (staleness guard) — on mismatch the reader speaks base stats
// and skips the derived four, degraded but never wrong.
// Residual: Attack%/Defense%/Magic def% are drawn from kernel equipment
// data and exist nowhere in memory — not spoken (TODO).
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

        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);
        const uint32_t screen =
            *reinterpret_cast<const volatile uint32_t*>(FF7Addr::MENU_DISPATCH_INDEX);
        if (menu_open != 1 || field_id == 0 ||
            screen != FF7Addr::STATUSMENU_SCREEN_INDEX ||
            // v2.35.1: stale dispatch index during victory screens — see
            // the ItemMenuThread gate.
            g_victory_active != 0 ||
            (GetTickCount() - g_last_battle_tick) < 4000 ||
            // v2.30.27: tutorials drive the screens — see ItemMenuThread.
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

        // ── Resolve the character's savemap record ─────────────────────
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

        // ── Char-data block (effective stats), with staleness guard ────
        const uint32_t cbase = FF7Addr::BATTLE_CHAR_BLOCK +
                               slot * FF7Addr::BATTLE_CHAR_SLOT_STRIDE;
        const auto c16 = [&](uint32_t off) {
            return *reinterpret_cast<const volatile uint16_t*>(cbase + off); };
        const bool block_ok =
            c16(FF7Addr::BCHAR_OFF_HP)     == r16(FF7Addr::SAVEMAP_CHAR_HP_OFF) &&
            c16(FF7Addr::BCHAR_OFF_HP + 2) == r16(FF7Addr::SAVEMAP_CHAR_MAXHP_OFF);
        if (!block_ok)
            Log::Write("[FF7Access] STATUS char block stale — base stats only");

        uint8_t stats[6];   // str, vit, mag, spr, dex, luck (internal order)
        for (int i = 0; i < 6; ++i)
            stats[i] = block_ok
                ? *reinterpret_cast<const volatile uint8_t*>(
                      cbase + FF7Addr::BCHAR_OFF_EFF_STATS + i)
                : r8(0x02 + i);

        // ── Compose the sheet (screen order) ───────────────────────────
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
// enemy AI dialogue — the scorpion's "Attack while it's tail's up!" warning
// and every other scene.bin message — a channel no other announcer touches
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
                continue;   // already present last poll — spoken once
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

static DWORD WINAPI BattleActionThread(LPVOID /*unused*/)
{
    uint8_t last_actor_id = 0xFF;   // 0xFF = sentinel; announce on next valid actor change

    // v2.12: per-enemy-slot liveness tracking for defeat announcements.
    // A slot must first be SEEN alive (plausible HP, no Death status) before
    // its death can announce — battle-init zeroes and empty formation slots
    // therefore never produce a false "defeated". Indexed by actor slot 4-9
    // (index 0 = slot 4). Reset whenever the battle module is not active.
    bool enemy_was_alive[6] = {};

    // v2.30: party KO / revival announcements ("Cloud is down" / "Cloud is
    // back up"), user-requested 2026-07-13 and deferred until the party had
    // a second member. Party slots need THREE states where enemies needed a
    // bool: a member can start the battle already KO'd (carried over from
    // the previous fight), and that must be recorded silently — the
    // seen-alive-first rule means no "is down" announce, but a later
    // Phoenix Down still owes the player an "is back up". Reset with the
    // enemy tracker whenever the battle module is not active.
    enum class PartyLife : uint8_t { Unseen, Alive, Dead };
    PartyLife party_life[3] = {};

    // v2.12.1: defeats are NOT spoken at detection time. The v2.12 debug log
    // proved the killing blow's tick also fires action announcements (flash
    // resolution + next-turn) whose interrupt=true cancelled the queued
    // defeat speech within the same millisecond, every time. Instead,
    // detected defeats accumulate here and speak (interrupt=false, so they
    // queue after in-flight playback) once NO thread has issued speech for
    // DEFEAT_QUIET_MS — the first quiet gap after the action burst. The 5s
    // cap guarantees delivery even under pathological continuous chatter.
    std::wstring pending_defeats;
    ULONGLONG    first_defeat_tick = 0;
    constexpr ULONGLONG DEFEAT_QUIET_MS = 600;
    constexpr ULONGLONG DEFEAT_MAX_WAIT_MS = 5000;

    // v2.12.1 diagnostics (debug_log only): last observed (cur, max, status)
    // per enemy slot, so every real change gets one log line — the in-game
    // trail for diagnosing WHY a defeat did or didn't announce.
    int32_t  dbg_last_cur[6]    = {};
    int32_t  dbg_last_max[6]    = {};
    uint32_t dbg_last_status[6] = {};

    // Rate limiter for kernel2 section re-scans while sections are missing.
    ULONGLONG next_scan_tick = 0;

    // Pending flash-message wait state (see ANNOUNCE TIMING above).
    bool      pending           = false;
    uint8_t   pending_cmd       = 0;      // model-state commandID of the pending turn
    uint32_t  pending_s0_cmd    = 0;      // struct snapshot at turn start
    uint32_t  pending_s0_idx    = 0;
    ULONGLONG pending_deadline  = 0;
    wchar_t   pending_actor[64] = {};   // 64: fits a 32-char enemy name + " A" suffix

    // v2.13: announces that land close together must CHAIN, not clobber.
    // The v2.12 traces showed the pending-flash flush ("MP B, attacks") and
    // the next turn's announce ("Cloud, Attack") firing in the SAME 50ms
    // tick — the second's interrupt=true cancelled the first before a
    // syllable played, so enemy actions were routinely inaudible whenever
    // the player's turn arrived at the same instant. An announce within
    // ANNOUNCE_CHAIN_MS of the previous one therefore queues
    // (interrupt=false) behind it instead of interrupting; both are per-turn
    // battle events the player needs to hear, and both are short. Announces
    // farther apart keep interrupt=true (stale leftover speech SHOULD be
    // cut off by a fresh turn).
    ULONGLONG last_announce_tick = 0;
    constexpr ULONGLONG ANNOUNCE_CHAIN_MS = 1500;

    // Announce helper: "[actor], [name-or-generic]".  Written as a lambda so
    // both the immediate path and the deferred flash path share it.
    const auto announce = [&](const wchar_t* actor_label, uint8_t command_id,
                              const std::wstring* exact_name) {
        wchar_t generic_buf[32];
        const wchar_t* action = exact_name ? exact_name->c_str()
            : GenericActionLabel(command_id, generic_buf, _countof(generic_buf));
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
            if (game_mode == 2)
                g_last_battle_tick = GetTickCount();   // v2.35.1, see decl
            if (game_mode != 2) {
                memset(enemy_was_alive, 0, sizeof(enemy_was_alive));
                party_life[0] = party_life[1] = party_life[2] = PartyLife::Unseen;
            } else {
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
            }

            // Speak accumulated defeats at the first quiet gap (or on
            // leaving battle, so a battle-ending kill is never dropped).
            // The gap must be measured FORWARD from detection, not just
            // backward from now: the death tick IS the action-burst tick
            // (v2.12.1 play test — "defeat spoken" and the interrupt=true
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

        // Classify the actor.  Slots 0–2 = party, 4–9 = enemy.  Anything else
        // means the battle module is not active.
        const bool is_party = (actor_id <= 2);
        const bool is_enemy = (actor_id >= 4 && actor_id <= 9);
        if (!is_party && !is_enemy) {
            last_actor_id = 0xFF;
            pending = false;
            continue;
        }

        // commandID == 0 → slot idle (process start / model state cleared):
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

        // Current flash-message struct values (see ff7_addresses.h §1c).
        const uint32_t flash_cmd =
            *reinterpret_cast<const volatile uint32_t*>(FF7Addr::BATTLE_ACTOR_CMD_INDEX);
        const uint32_t flash_idx =
            *reinterpret_cast<const volatile uint32_t*>(FF7Addr::BATTLE_ACTOR_ACTION_INDEX);

        // ── Phase 2: a name-bearing action is waiting for its flash text ──
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
                announce(pending_actor, pending_cmd, ok ? &name : nullptr);
                pending = false;
            } else if (timed_out) {
                // No flash and the struct still describes something else:
                // fall back to the generic label rather than risk a wrong name.
                announce(pending_actor, pending_cmd, nullptr);
                pending = false;
            }
            // While pending and not resolved, fall through only to detect a
            // NEW actor turn below (which flushes the pending announce).
        }

        // ── Phase 1: new turn detection ──
        if (actor_id == last_actor_id)
            continue;
        last_actor_id = actor_id;

        // A newer turn started while the previous one was still waiting for
        // its flash: announce the old one generically now so it isn't lost.
        if (pending) {
            announce(pending_actor, pending_cmd, nullptr);
            pending = false;
        }

        // Build the actor label.  Slots 0-2 = the party member's real savemap
        // name (v2.19 — renames respected, "ally N" only as fallback);
        // slots 4–9 = the real scene.bin enemy name with duplicate-letter
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
        // succeed — the rate limit keeps the scans from wasting cycles).
        if ((!g_k2.magic || !g_k2.item || !g_k2.weapon) &&
            GetTickCount64() >= next_scan_tick) {
            ScanKernel2Sections();
            next_scan_tick = GetTickCount64() + 60000;
        }

        // Does this command have flash text at all?  Branch 9 commands
        // (plain Attack, Steal, …) never write the flash struct — announce
        // their generic label immediately with no wait.
        uint8_t branch = 9;
        if (command_id <= FF7Addr::BATTLE_DISPATCH_MAX_CMD)
            branch = *reinterpret_cast<const uint8_t*>(
                FF7Addr::BATTLE_DISPATCH_BYTE_TABLE + command_id);
        const bool name_possible = (branch != 9) &&
            (g_k2.magic != nullptr || branch == 8 || branch == 4);

        if (!name_possible) {
            announce(actor_label, command_id, nullptr);
            continue;
        }

        // Defer the announce until the flash text appears (Phase 2 above).
        pending          = true;
        pending_cmd      = command_id;
        pending_s0_cmd   = flash_cmd;
        pending_s0_idx   = flash_idx;
        pending_deadline = GetTickCount64() + 2500;
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
// gap left in the mod — battles were playable only by memorizing menu
// layouts and counting presses.
//
// Addresses: ff7_addresses.h SECTION 1c2. Solved by static disassembly
// 2026-07-12 (three failed live-scan sessions prior), live-confirmed the
// same day by investigate/ff7_battle_menu_cursor_live_verify.py.
//
// WHY POLLING (not hooks): same reason as BattleActionThread — FFNx
// trampolines battle menu functions (battle_menu_update's dispatcher call
// site is one of its replace_call_function targets), so entry-point hooks
// would intercept FFNx, not the game. Polling at 50ms reads the same state
// the draw code reads, with zero patching. Cursor repeat-rate in FF7 is
// ~8/s at the fastest; 50ms polling cannot skip a resting position, only
// intermediate positions mid-repeat (which a sighted player also ignores).
//
// LIST NAME RESOLUTION: a list entry's u16 id packs the action index in
// the LOW byte (high byte = flag bits — live: Ice showed 0x41E = spell 30
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
// from) — state 0 is ALSO the idle ATB-wait state, so raw "state == 0"
// cannot gate target announcements. We announce target changes only while
// `targeting` is set, which we arm on a menu-state -> 0 transition and
// disarm on 0xFFFF (turn executing), a new menu opening, or leaving
// battle. The initial target is announced on arming (the game always
// writes TARGET_INDEX at Confirm time — live: it landed the same 50ms
// poll as the state transition).
//
// Target labels: party slots 0-2, enemy slots 4-9 (same actor-slot space
// BattleActionThread uses). Party slots 0-2 = the member's real savemap
// name via PartySlotLabel (v2.19 — pre-v2.19 only slot 0 was named and
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
// not cover 1:1 — the Defend/Change-row pseudo-commands and Limit (which
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
    // on menu open) — revalidate its head signature before every lookup.
    if (id != 0 &&
        SectionEntryText(ValidatedSection(&g_k2.command, "Attack|Magic|"),
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

            // Force a fresh announce of whatever widget we landed in — this
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
            last_state = state;
        }

        // All widget reads index by party slot; anything else means the
        // block is mid-update or we're between menus.
        if (slot > 2)
            continue;

        // v2.37: a turn session spans the command menu + its submenus +
        // targeting. Ending it (menu closed, or ATB idle = state 0 with
        // targeting NOT armed — the same 0-is-ambiguous resolver the
        // targeting logic uses) rearms the whose-turn announce.
        const bool in_turn_session =
            state == FF7Addr::BMENU_STATE_COMMAND     ||
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
        // section is the one this thread depends on most — without it the
        // command menu still speaks via the hardcoded/generic fallbacks.
        if ((!g_k2.magic || !g_k2.item || !g_k2.weapon || !g_k2.command) &&
            GetTickCount64() >= next_scan_tick) {
            ScanKernel2Sections();
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
                // so the cursor only reads one transiently mid-move — stay
                // silent rather than speak "empty" for a cell the cursor
                // will have left by the next frame.
                if (cmd_id == 0xFF || cmd_id == 0)
                    continue;

                std::wstring name;
                // v2.37: prefix the character's name on the FIRST real
                // command announce of a fresh turn ("Cloud's turn. Attack.")
                // so the player knows who to command; later cursor moves and
                // submenu cancels speak the command alone. Attaching to the
                // command announce (one utterance) avoids clobbering — a
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
            // disasm — see the LIST WIDGETS note in ff7_addresses.h). ITEM
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
                    empty = (id16 == 0xFFFF);   // NOT 0 — id 0 = Potion (v2.36)
                    entry_id = id16;
                } else {
                    const uint8_t id8 = *reinterpret_cast<const volatile uint8_t*>(
                        table + index * FF7Addr::BLIST_MAGIC_STRIDE);
                    empty = (id8 == 0xFF);      // magic/summon empty marker
                    entry_id = id8;
                }
                if (empty)
                    continue;   // empty row — silent

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
// Solid-body awareness (v2.30.22).
//
// FF7 field models body-block each other: walking into another character
// stops the player dead, byte-identical (to every signal this mod reads) to
// walking into a wall. The 2026-07-25 hideout play report proved how
// disorienting that is: the route to Barret said "left", but Tifa stood in
// the aisle and the player heard only the wall thud — the log shows them
// pinned at EXACTLY 64.0 units from her center for 3½ minutes (64 = 32+32,
// the classic FF7 collision radius pair; any input with a positive
// component toward her produced zero movement).
//
// The offline dry run of that exact scene (investigate/
// ff7_hideout_firstleg_dryrun.py, logs 20260725_*) established:
//   - the walkmesh route and its quantized directions were CORRECT — the
//     leg was walkable, a body made it unfollowable;
//   - with 64-unit contact this room's aisles SEAL COMPLETELY (flood fill:
//     Barret unreachable from anywhere) yet at 56 they open — so per-model
//     radii differ and body-aware REROUTING is deferred until the real
//     radii are known (see the rc6E/rc70/rc72 diagnostic below and the
//     TODO entry).
// What ships now is the honest layer: NAME the body. The wall-bump thread
// speaks "<Name> is in the way" once per contact episode when a person
// stands in the held direction, and the directions announce appends the
// same caution when the first leg's quantized ray passes through a body.
//
// v2.30.24: per-model collision radii are now REAL — the v2.30.22
// candidate dump confirmed FIELD_EVENT_COLLISION_RADIUS (+0x72; see
// ff7_addresses.h for the two-anchor derivation). Every body test below
// uses live radii: contact = player_radius + body_radius, plus a purpose-
// sized margin. The radius is DYNAMIC (scripts set it; 0 = intangible),
// so it is read fresh per call, never cached.
//
// Constants:
//   BODY_CONE_MIN_COS 0.5 (±60°): at rest ON a body, any direction within
//     90° of the body bearing freezes; ±60° covers every case observed in
//     the hideout log while excluding bodies clearly off to the side.
//   kBodyNameSlack  26: naming search reaches contact + slack — a frozen
//     player rests up to one step OUTSIDE contact, and naming a body a
//     half-body away is still the right answer; farther = a wall problem.
//   kBodyRayMargin   8: route-caution ray width beyond contact — warn
//     only about bodies that will actually stop the walk.
//   kBodyRouteMargin 6: reroute leg test beyond contact — a leg passing
//     within a step of contact is treated as blocked so the reroute
//     doesn't thread the needle.
// ---------------------------------------------------------------------------
constexpr float BODY_CONE_MIN_COS = 0.5f;
constexpr float kBodyNameSlack    = 26.0f;
constexpr float kBodyRayMargin    = 8.0f;
constexpr float kBodyRouteMargin  = 6.0f;
static bool IsReadableSpan(const void* p, size_t len);

// One placed person-class model with a live body. name = translated dev
// label (no dedup ordinal — "shinra guard is in the way" is enough to
// explain a bump; the browser distinguishes guard 2 from guard 3).
struct BodyInfo {
    float        x, y;
    float        radius;   // live +0x72 (DYNAMIC; intangible models are
                           // not collected at all)
    int          slot;
    std::wstring name;
};
static size_t CollectBodies(int exclude_slot, BodyInfo out[32]);
static float  PlayerCollisionRadius();
static bool BodyInDirection(float px, float py, float world_deg,
                            int exclude_slot, std::wstring& out_name,
                            float* out_dist);
static bool BodyOnRay(float px, float py, float world_deg, float length,
                      int exclude_slot, std::wstring& out_name);
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
//     Live-observed values (do NOT trust FFNx's enum here — see the
//     GAME_MODE note in ff7_addresses.h): 0 = field play, 2 = battle,
//     9 = menu. Battle is the critical case: entering a random battle
//     while holding a direction freezes the field module with that
//     direction stuck in current_key_input_status and the position frozen
//     — without this gate the tone plays through the entire battle.
//   - FIELD_UC_LOCK != 0: a field script locked player control (opcode UC)
//     for a scripted scene; input is ignored so a frozen position is not
//     a wall. Address derived from the PSX decomp's exact struct match —
//     see ff7_addresses.h FIELD_UC_LOCK provenance note.
//   - FIELD_MOVIE_PLAYING && !BGMOVIE: a full-screen movie (FMV) is
//     playing. Background movies (BGMOVIE set — e.g. scenery outside a
//     train window) leave the player walkable and stay tone-enabled.
//   - FIELD_ID == 0: title screen / world map. (NOT sufficient for battle,
//     despite earlier belief — live-tested: it keeps its field value while
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
//   Beep(220 Hz, 60 ms) — kernel32's synthesized tone through the default
//   audio device. Chosen over TTS because a tone is instant, language-free,
//   and doesn't interrupt any speech in progress. 220 Hz sits well below
//   both the cue beeps used by investigation scripts (800/1400 Hz) and
//   typical screen reader speech fundamentals, so it reads as a distinct
//   "thud". Beep() blocks this thread for the 60ms duration — acceptable,
//   since the next poll simply happens a frame later. Repeats every 300ms
//   for as long as contact continues (continuous-but-not-frantic feedback).
//
// MEMORY SAFETY:
//   Every poll re-reads the array pointer (the engine owns it; on this
//   build it points into static BSS at 0xCC1670, but a field could in
//   principle relocate it) and bounds-checks the player index against
//   FIELD_N_MODELS. The computed element range is then verified readable
//   via VirtualQuery before dereferencing — during field transitions the
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
    // game-over screen — that state reads as field mode with the input
    // status frozen at whatever direction was held when the fatal battle
    // triggered, i.e. exactly the Gate-2 stale-input scenario, but with no
    // mode change for Gate 2 to catch. No gate on module state can be
    // trusted to close there, so gate on the one thing a frozen module can
    // never fake: the player actually walking. Reaching a wall always takes
    // at least one step first, so the cost is only a missed tone in the
    // rare "battle ended flush against a wall, direction never released"
    // case — and that clears the moment the player moves.
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
        // NOT reliably zero during battle — the field stays loaded behind the
        // battle module — so this gate alone is insufficient; see Gate 2.
        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);

        // Gate 2: the FIELD module must be the ACTIVE engine module.
        // When a random battle starts, the field module freezes with
        // current_key_input_status stuck at the direction the player was
        // holding and the position frozen — the wall predicate would stay
        // true for the entire battle (observed live: continuous tone until
        // the victory screen). Live-observed values: 0 = field play,
        // 2 = battle, 9 = menu (FFNx's enum does not apply to this byte).
        const uint8_t game_mode =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::GAME_MODE);

        // Gate 3: main menu overlay closed. Arrow keys navigate the menu
        // while the character stands frozen underneath — not a wall.
        const uint8_t menu_open =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_OPEN);

        // Gate 4: player control not locked by a field script (opcode UC).
        // Scripted scenes freeze the player while ignoring input; holding a
        // direction there is not a wall. Offset provenance: PSX decomp
        // struct match — see FIELD_UC_LOCK in ff7_addresses.h.
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

        // Log gate transitions (debug_log builds only — Log::Write is a
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

        if (field_id == 0 || game_mode != FF7Addr::GAME_MODE_FIELD ||
            menu_open != 0 || uc_lock != 0 || movie_playing) {
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
        // dereferencing — a field transition can tear the array down between
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
        // samples counts as movement for arming (v2.30.1) — the first-sample
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
        // so a suppressed episode logs once, not 20×/second).
        if (!armed && blocked_streak == kConsecBlocked) {
            Log::Write("[FF7Access] WALL tone suppressed: dir held + frozen "
                       "but no movement seen this episode (frozen module?)");
        }

        if (armed && blocked_streak >= kConsecBlocked &&
            now - last_beep_tick >= kBeepPeriodMs) {
            last_beep_tick = now;
            // One-time log per contact episode would require more state; log
            // nothing here — at 3+ beeps/second even debug logging would spam.
            Beep(kBeepFreqHz, kBeepDurMs);

            // v2.30.22: if a PERSON stands in the held direction, this
            // "wall" is a body — say who, once per contact episode (see the
            // solid-body block above WallBumpThread for the derivation).
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
                    std::wstring bname;
                    float bdist = 0.0f;
                    if (BodyInDirection(static_cast<float>(x >> 12),
                                        static_cast<float>(y >> 12),
                                        world, /*exclude_slot=*/-1,
                                        bname, &bdist)) {
                        std::wstring msg = bname + L" is in the way.";
                        TTS::Speak(msg, /*interrupt=*/false);
                        if (Config::Get().debug_log) {
                            char dbg[160];
                            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                                "[FF7Access] WALL body: '%ls' dist=%.1f "
                                "held_input=%.0f world=%.1f player=(%ld,%ld)",
                                bname.c_str(), bdist, held_input, world,
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
// frame and can only SET edge-triggered flags — Beep() blocks for its whole
// duration, so calling it directly from an opcode hook would stall the game
// itself every time it fires (the same reasoning behind every other tone in
// this file: WallBumpThread above, and the proximity/wander chirps further
// down, all poll a background thread instead of beeping inline from a
// hook). This thread just polls Hooks::ConsumeDialogWaitTone/
// ConsumeDialogChoiceTone and does the actual (blocking, but only THIS
// thread blocks) Beep() calls.
//
// Both cues use the SAME pitch (1568 Hz, distinct from every other tone in
// this mod: 220 Hz wall thud, 880 Hz wandering cue, 1175 Hz proximity
// chirp) and differ only in COUNT — one beep for "waiting for the confirm
// button", two quick beeps for "a choice was just presented" — matching
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
            Beep(kToneHz, kToneMs);

        if (Hooks::ConsumeDialogChoiceTone()) {
            Beep(kToneHz, kToneMs);
            Sleep(kDoubleGapMs);
            Beep(kToneHz, kToneMs);
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Field navigation — PATHFINDER BROWSER thread (v2.14, reworked to the
// FF1-6 accessibility key scheme the same day). First interactable-tracking
// feature of the navigation system.
//
// KEY BINDINGS follow accessiblity_keys.txt (repo root) — the FF4 Pixel
// Remaster screen-reader scheme — so users of the FF1-6 accessibility mods
// can transfer their muscle memory directly (user requirement, 2026-07-13):
//   J / L   (or [ / ])  cycle destinations in the current category
//   Shift+J / Shift+L (or - / =)  cycle destination categories
//   K                  announce the selected destination's name
//   Shift+K            reset category to All
//   \ or P             directions to the selected destination
//   M                  announce the current map's name
// Categories: All, Exits, People (v2.15 — every non-player model on the
// walkmesh, named from the model-loader section's dev names in v2.16),
// Save points (v2.16 — "save" labels; CONFIRMED game-wide by the v2.18
// flevel catalog: "fieldbg saveicn" is the only save label in all 720
// fields), Triggers (v2.17 — script-created LINE zones: ladders,
// elevators, touch/cross zones, named by owning entity's dev name), and
// Items (v2.18 — chests/materia/pickups/keys classified by the
// catalog-confirmed "fieldbg" prop labels; collected floor pickups
// despawn off-mesh and drop out of the list automatically, which IS the
// taken/remaining state for them — chest open/closed state is a live
// investigation TODO). Unimplemented FF4 keys
// (Shift+\ valid-path filter, Ctrl+\ layer filter, Ctrl+arrows teleport,
// Shift+M exit filter) are silently ignored; listed in TODO.txt for when
// prerequisites exist.
//
// DATA SOURCE (ff7_addresses.h SECTION 1e): the engine's parsed field-file
// section 8 behind FIELD_TRIGGERS_HEADER_PTR (0xCFF454, resolved statically
// via FFNx's chain with three name-embedded cross-checks). Each of the 12
// gateway slots holds an exit LINE (two walkmesh-coord vertices) and the
// destination field id (0x7FFF = unused slot). Destinations are numbered by
// gateway SLOT order ("Exit 1".."Exit n") so a destination keeps its name
// while the player moves — never renumbered by distance.
//
// GEOMETRY: player walkmesh position = field_event_data model_pos >> 12
// (FFNx: "model_pos.x / 4096.f"). Distance = player to the NEAREST POINT of
// the exit line segment, in the XY plane (Z left out: fields are drawn from
// a fixed camera and exits are reached by 2D walking; a stacked-walkway
// field could understate distance, acceptable for v1). Walking covers ~160
// walkmesh units/sec (v2.6 measurement), so seconds = distance / 160.
//
// DIRECTION: world angle of (player -> nearest point), then rotated by the
// header's control_direction byte — the SAME per-field value the engine
// uses to rotate d-pad input to match the camera — and mapped to 8 d-pad
// sectors. CONVENTION FULLY CONFIRMED 2026-07-13: the calibration
// walkabout fixed the rotation (control_direction is the world bearing of
// screen-DOWN, screen angle = world + control−180), and the user's
// follow-up play test confirmed left/right land correctly too — the
// mapping is a pure rotation, no mirror.
//
// DIRECTION STYLES (v2.22): the above single-bearing announcement is now
// the "line" style (direction_style=line, and the automatic fallback).
// The default "turns" style routes over the field's WALKMESH instead —
// A* + funnel over the triangle graph, spoken as d-pad moves: "Exit 2:
// up 4 seconds, then right 2 seconds" — see the WALKMESH pathfinding
// block above for the full pipeline and its fail-closed guards.
//
// HOTKEYS use GetAsyncKeyState edges, gated on the game window being
// focused (GetForegroundWindow's process == ours) so typing in another app
// can't trigger them, and on normal field control (GAME_MODE==0,
// FIELD_ID!=0, MENU_OPEN==0) so they can't talk over battles/menus.
// Config::Get().pathfinder_keys turns the whole set off.
//
// GAMEPAD (v2.21): the RIGHT ANALOG STICK is a second trigger path for the
// same browser — up/down = category, left/right = destination, R3 click =
// directions. Identical gates (focus + field control + pathfinder_keys);
// gamepad_nav=false switches just the stick off. The stick and R3 carry no
// native game function, so nothing is stolen from gameplay — full evidence
// trail in gamepad.h.
// ---------------------------------------------------------------------------

// Map an input-relative angle (degrees, 0 = the Up d-pad, clockwise) to an
// 8-way d-pad sector. Split into index + name (v2.22) because the
// turn-by-turn route builder merges consecutive same-SECTOR legs — it
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
// LINE trigger zone (v2.17 — script-created lines: ladders, elevators,
// touch/cross zones — a real segment, exactly like an exit).
struct NavDest {
    wchar_t name[64];      // spoken name, e.g. "To Platform" / "shinra
                           // guard 3, talk disabled" (widened 32→48 in
                           // v2.26 for the talk suffix on long labels;
                           // 48→64 in v2.30.23 for trigger-behavior
                           // suffixes like ", exit to Seventh Heaven")
    int16_t line_x1, line_y1, line_x2, line_y2;   // exit line (walkmesh)
    int16_t line_z1, line_z2;   // line endpoint HEIGHTS (v2.23) — lets the
                                // route builder locate the target on the
                                // correct STACKED layer when no triangle
                                // hint exists (exits/triggers on walkways)
    int     model_slot;    // field model index for people; -1 for exits
    int16_t target_tri;    // walkmesh triangle the target stands on (models:
                           // their live +0x78 id — exact even on stacked
                           // layers); -1 = unknown, turn-by-turn locates the
                           // target point geometrically instead (v2.22)
};

// ---------------------------------------------------------------------------
// Readability probe for an arbitrary byte span (v2.18.2).
//
// Replaces the per-site VirtualQuery idiom that had accumulated many inline
// copies (2026-07-14 code review): walks the regions covering [p, p+len) and
// requires every one committed and readable — strictly stronger than the
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
// WALKMESH pathfinding — turn-by-turn directions (v2.22).
//
// WHY: the v2.14 directions are one straight-line bearing, which happily
// points through walls and pits. Turn-by-turn plans a real route over the
// field's WALKMESH — the triangle mesh the engine itself moves characters
// on — and speaks it as a sequence of d-pad moves with walking times:
// "Exit 2: up 4 seconds, then right 2 seconds." The straight-line style
// remains available (direction_style=line) and is the automatic fallback
// whenever a route cannot be computed.
//
// DATA: field-file section 5 behind FIELD_FILE_BUFFER — layout, sources,
// and the access-pool confidence caveat are documented at ff7_addresses.h
// SECTION 1h. Everything runs on the directions keypress, nothing is
// cached: a field mesh is at most a few hundred triangles, and per-press
// rebuilding is the same simplicity/freshness tradeoff the destination
// list itself makes.
//
// PIPELINE:
//   1. LoadWalkmesh    — snapshot triangles + adjacency, SELF-GUARDED
//                        (id-range + reciprocity checks) because the
//                        access pool is the one layout fact FFNx's code
//                        does not confirm — a wrong guess must fail the
//                        parse, never route the player into a wall
//   2. locate ends     — player: live triangle id (+0x78); target: its
//                        model's triangle id, else point-location
//   3. WalkmeshAStar   — A* over the adjacency graph, centroid costs
//   4. BuildPortals    — the crossed edges, endpoints recovered by
//                        GEOMETRIC shared-vertex match (never by the
//                        access pool's edge-order convention, which is
//                        not runtime-verifiable)
//   5. FunnelPath      — string-pulling: the taut path through the
//                        corridor, so corners exist only where the route
//                        actually bends around geometry
//   6. RouteToSpeech   — legs quantized to the 8 d-pad sectors,
//                        same-direction legs merged, sub-step jogs folded
//                        into their predecessor
// ---------------------------------------------------------------------------

// One walkmesh triangle, snapshot form. Routing is 2D (the same
// convention as exits/distance since v2.14) — adjacency routes stacked
// layers correctly because two overlapping walkways are far apart in the
// GRAPH even when they overlap in XY. The centroid HEIGHT is kept
// (v2.23) so point-location can resolve WHICH stacked layer a target
// with a known Z is on (ladder endpoints, exits on walkways).
struct WalkTri {
    float    vx[3], vy[3];  // vertex XY, walkmesh units
    uint16_t nbr[3];        // triangle across edge slot e; 0xFFFF = wall
    float    cx, cy;        // centroid — the triangle's A* node position
    float    cz;            // centroid height — layer disambiguation only
};

// A 2D point on the route (funnel corners, portal midpoints).
struct NavPt { float x, y; };

// Snapshot and validate the current field's walkmesh. False = caller must
// fall back to straight-line directions (buffer mid-transition, count
// implausible, or the access pool failed its self-guard).
static bool LoadWalkmesh(std::vector<WalkTri>& out)
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
    // padding — out-of-range ids and broken reciprocity — not a mostly
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
    // to Tifa led into the bar counter — her triangle is mesh-connected
    // but script-locked). Cut every edge INTO a locked triangle — the
    // exact test the game's own movement code performs per crossing
    // (destination-side only, so leaving a locked triangle stays
    // possible, mirroring the game). Applied AFTER the reciprocity
    // self-guard above: locks legitimately make the graph asymmetric,
    // and the guard validates the RAW pool's layout, not the overlay.
    // A route target standing on a locked triangle (Tifa) becomes
    // unreachable — A* fails and the caller falls back to the
    // straight-line announce, which walks the player TO the counter,
    // where the talk radius already reaches across (matching how a
    // sighted player interacts).
    uint32_t locked = 0;
    for (uint32_t t = 0; t < ntris; ++t) {
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

// Squared distance from point (px,py) to segment (x1,y1)-(x2,y2) — the
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

// Twice the signed area of triangle (a,b,c) — the funnel algorithm's
// orientation primitive. Sign says which side of a->b the point c is on:
// POSITIVE = the side BuildPortals labels "left". ⚠ This is cross(ab,ac),
// the NEGATIVE of Recast's triArea2D (cross(ac,ab)) — every comparison in
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
        return 0.0f;   // inside (either winding — field meshes vary)
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
// point (or whose boundary is nearest — target points sit exactly ON
// portal edges; point targets can be a hair off-mesh), with the HEIGHT
// difference to the triangle's centroid as a tie-breaker term so a field
// with STACKED walkways resolves to the layer the point is actually on
// (v2.23 — ladder endpoints made this matter; before that the 2D pick
// was an accepted limitation). The score sums XY boundary distance² and
// height difference²: zero for "inside, same height", and a triangle
// directly underfoot always beats the same spot on another layer.
static int WalkmeshLocate(const std::vector<WalkTri>& m,
                          float x, float y, float z);

// A model's live triangle id (+0x78) is only a HINT (v2.30.25): scripted
// idle models never update it — the hideout's Biggs stood at (-191,46)
// while his field still read triangle 0 from the bottom corridor, so
// every route to him planned to the wrong corner and then "spoke" a
// straight line through walls (the 2026-07-25 evening log's
// `start=0 goal=0 'left 2 seconds'` line is the smoking gun; Jessie's
// routes carried the same stale 0). Trust a hint ONLY when the hinted
// triangle actually contains (within a small slack) the position it
// claims to locate; otherwise geometry-locate from the position, which
// also handles off-mesh targets (nearest triangle + height score).
// Known residual: on STACKED layers a stale hint that happens to name
// the other layer's triangle under the same 2D point would pass — a
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
// crow's flight). Linear-scan open "list" — n is a few hundred, and this
// runs once per keypress; a heap would be pure ceremony. Returns the
// triangle sequence start..goal, or false when the goal is in a region
// the graph cannot reach (locked-off area, different layer group).
static bool WalkmeshAStar(const std::vector<WalkTri>& m, int start, int goal,
                          std::vector<uint16_t>& out_path,
                          const std::vector<uint8_t>* avoid = nullptr)
{
    // avoid (v2.30.24): optional per-triangle mask — crossings INTO
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
// vertices compare equal) — deliberately NOT via the access pool's
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
            // must-pass point — the route stays walkable, just less taut.
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
// back EMPTY and the caller degrades to portal midpoints — a valid,
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
    // corner, making it O(n^2) worst case — fine at field sizes, but a
    // subtle orientation bug could in principle cycle, so a hard guard
    // converts "cannot happen" into "falls back audibly correct".
    int guard = static_cast<int>(p.size()) * 16 + 64;

    for (size_t i = 1; i < p.size(); ++i) {
        if (--guard < 0) { corners.clear(); return; }

        // Tighten the RIGHT side: the new right endpoint narrows the
        // funnel if it lies left of (or on) the current right boundary.
        // (Signs flipped vs. the classic Recast listing — see Tri2.)
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
// predecessor rather than being spoken — "then left 1 second" for a
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
    if (total < FF7Addr::WALKMESH_UNITS_PER_SEC * 0.5f)
        return L"very close";

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

// Outcome of a turn-by-turn attempt — the caller's fallback decision.
enum class RouteOutcome {
    SPOKEN_ROUTE,   // out_route holds the spoken route body
    NO_PATH,        // mesh fine, target genuinely unreachable: say so
    UNAVAILABLE,    // mesh unreadable/failed guards: silent fallback
};

// Full pipeline for one directions request. (px,py,pz) player, (tx,ty,tz)
// the target point (nearest point of the destination's line — the same
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
    // to_nearest (v2.30.25): when the target is graph-unreachable
    // (off the walkable floor — Biggs sitting on the hideout crates,
    // Tifa behind the locked bar counter), route to the REACHABLE
    // triangle nearest the target instead of giving up, aiming the walk
    // at that triangle's closest point. The caller words the result as
    // "off the walkable area" and the talk radius covers the last gap.
    // exclude_model_slot (v2.30.24): the destination's own model when
    // routing to a person — their body always sits at the route's end
    // and must not count as a blocker.
    // target_reach (v2.30.25): how far short of the target the walk may
    // END and still succeed — a person is "reached" at their talk
    // radius. Body tests ignore the final reach-length of the route, so
    // a companion standing shoulder-to-shoulder with the target (Barret
    // 73 units from Biggs) neither blocks the route nor triggers a
    // reroute the room can't satisfy.
    std::vector<WalkTri> mesh;
    if (!LoadWalkmesh(mesh)) {
        Log::Write("[FF7Access] NAV route: walkmesh unavailable, "
                   "falling back to straight-line");
        return RouteOutcome::UNAVAILABLE;
    }
    const int n = static_cast<int>(mesh.size());
    // v2.30.25: hints validated against their positions (stale-triangle
    // fix — see ResolveTriHint).
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
        // point 6 units from him — well inside talk radius.
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
            // point (tx/ty are by-value — safe to overwrite)
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
        // Funnel guard tripped — degrade to portal midpoints: every
        // doorway on the route in order, so still a walkable description.
        for (const PathPortal& p : portals)
            corners.push_back({ (p.lx + p.rx) * 0.5f, (p.ly + p.ry) * 0.5f });
        corners.push_back({ tx, ty });
    }

    // ---- body-aware reroute (v2.30.24) --------------------------------
    // Solid people block movement exactly like walls (v2.30.22), and the
    // collision radii are now live-readable, so the route can be tested
    // against bodies and REROUTED around them when another corridor
    // exists. Method (validated offline in the 2026-07-25 dry run):
    // temp-avoid every triangle a blocking body's contact circle
    // overlaps (start/goal exempt — pinning the player or target inside
    // an avoided triangle would only manufacture failure) and re-run A*.
    // The reroute is adopted ONLY if its own funnel comes back clear of
    // ALL bodies; otherwise the original route stands and the v2.30.22
    // caution names the blocker — a clear route or the honest truth,
    // never a guess. Triangle granularity is a known limit: a body in a
    // large doorway triangle can seal a corridor a foot-width gap would
    // technically allow (the hideout's Tifa case) — that outcome is the
    // caution, which is correct enough for a squeeze a player must
    // shimmy through anyway.
    {
        BodyInfo bodies[32];
        const size_t nb = CollectBodies(exclude_model_slot, bodies);
        const float pr = PlayerCollisionRadius();
        // Pull the route's END back by target_reach before testing (the
        // v2.30.25 rule above): walk backward along the corners removing
        // reach-length of polyline.
        const auto truncate_reach = [&](std::vector<NavPt> cs) {
            float cut = target_reach;
            while (cut > 0.0f && !cs.empty()) {
                const NavPt prev = (cs.size() >= 2)
                                       ? cs[cs.size() - 2] : NavPt{ px, py };
                const float lx = cs.back().x - prev.x;
                const float ly = cs.back().y - prev.y;
                const float len = sqrtf(lx * lx + ly * ly);
                if (len > cut && len > 0.0f) {
                    cs.back().x -= lx / len * cut;
                    cs.back().y -= ly / len * cut;
                    break;
                }
                cut -= len;
                cs.pop_back();
            }
            return cs;
        };
        const auto blocked_by = [&](const std::vector<NavPt>& corners_in) {
            // indices of bodies whose contact circle some leg enters
            const std::vector<NavPt> cs = truncate_reach(corners_in);
            std::vector<int> hits;
            for (size_t b = 0; b < nb; ++b) {
                const float rr = pr + bodies[b].radius + kBodyRouteMargin;
                float ax = px, ay = py;
                for (const NavPt& c : cs) {
                    if (PointSegDist2(bodies[b].x, bodies[b].y,
                                      ax, ay, c.x, c.y) < rr * rr) {
                        hits.push_back(static_cast<int>(b));
                        break;
                    }
                    ax = c.x; ay = c.y;
                }
            }
            return hits;
        };
        const std::vector<int> hits = blocked_by(corners);
        if (!hits.empty()) {
            std::vector<uint8_t> avoid(n, 0);
            for (int b : hits) {
                const float rr = pr + bodies[b].radius;
                for (int t = 0; t < n; ++t) {
                    if (t == start || t == goal)
                        continue;
                    if (TriangleDistance(mesh[t], bodies[b].x,
                                         bodies[b].y) < rr)
                        avoid[t] = 1;
                }
            }
            std::vector<uint16_t> path2;
            if (WalkmeshAStar(mesh, start, goal, path2, &avoid)) {
                std::vector<PathPortal> portals2;
                BuildPortals(mesh, path2, portals2);
                std::vector<NavPt> corners2;
                FunnelPath(px, py, tx, ty, portals2, corners2);
                if (!corners2.empty() && blocked_by(corners2).empty()) {
                    corners.swap(corners2);
                    path.swap(path2);
                    if (Config::Get().debug_log) {
                        char dbg[128];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                            "[FF7Access] NAV route: rerouted around %u "
                            "bod%s (player_r=%.0f)",
                            static_cast<unsigned>(hits.size()),
                            hits.size() == 1 ? "y" : "ies", pr);
                        Log::Write(dbg);
                    }
                }
            }
        }
    }

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
// model class to its category — previously the enum lived inside the key
// handler and classification knowledge was spread across three sites (the
// 2026-07-14 code review's altitude finding).
// ---------------------------------------------------------------------------
enum { CAT_ALL = 0, CAT_EXITS = 1, CAT_PEOPLE = 2, CAT_SAVE = 3,
       CAT_TRIGGERS = 4, CAT_ITEMS = 5 };

// What a field model IS, decided in exactly one place from its dev label.
enum ModelClass : uint8_t {
    MC_PERSON = 0,   // any other model — browsable under People
    MC_SAVE,         // save point icon
    MC_CHEST,        // treasure box (lid state tracked via lastFrame)
    MC_ITEM,         // materia orb / pickup bottle / sparkle / key item
    MC_SCENERY,      // background prop — not browsable under ANY category
                     // (v2.30.18: unknown "fieldbg" labels + a small list
                     // of observed non-fieldbg props; see ClassifyModelLabel)
};

// Classify a model's speakable label and pick its spoken base name.
// Evidence (offline catalog of ALL 720 fields' model labels,
// ff7_flevel_models_catalog.py, 2026-07-14): the devs prefixed every
// interactable prop "fieldbg" and named item props consistently — "trb *" =
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
        // clearly not people — observed listed as "People" with no
        // walkable path in 7th Heaven (player report 2026-07-23):
        // "camera" (cutscene camera dummy, 1 occurrence game-wide in the
        // flevel catalog) and "swordc"/"swordc00"/"swordc09" (sword
        // props, 3 occurrences). v2.30.19: CONTAINS-matched, not
        // exact/prefix — the .char labels arrive with location-word
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
    // flevel catalog shows dozens of these game-wide (doors "…dr", the
    // train "kisya", cosmetics "cos"/"props"/"v2"/"zuta"…), and the
    // 2026-07-23 player report caught three of them listed as unreachable
    // "People" in 7th Heaven alone (hana = flower vase, cash = register,
    // pinbl = pinball machine). The pinball elevator's INTERACTION is a
    // separate line trigger (Triggers category) — the model is just its
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
        default:       return CAT_PEOPLE;
    }
}

// ---------------------------------------------------------------------------
// Dev-label translation: romaji/shorthand -> speakable English (v2.20).
//
// The v2.16 People names and v2.17 Trigger names are the developers' own
// dev names — terse romaji ("hei" = soldier, "ballet" = Barret, "ladd0" =
// a ladder line) that a blind player would have to memorize. This block
// translates them, word by word, into plain English, and resolves party-
// character words to the character's LIVE savemap name (v2.19 machinery,
// so player renames carry through to the field browser too).
//
// EVIDENCE (both TODO.txt residuals planned this table "from the complete
// label list, no play collection needed"):
//   - models:   investigate/flevel_models_catalog_20260714_130007.log —
//     all 557 distinct model labels in the game's 720 fields.
//   - entities: investigate/flevel_entity_names_20260715_122652.log —
//     all 2412 distinct script entity names (new game-wide catalog,
//     2026-07-15; nmkin_2 validation showed the reactor ladder lines
//     themselves: 'ladu0'/'ladd0'/'slp0', with Jessie as 'av j').
//   - per-field context for the short stems (v2.28 second pass):
//     investigate/short_entity_context_20260717 log — the COMPLETE
//     entity list of every field where each cryptic 2-3 letter stem
//     occurs; the neighbouring names are the identification evidence
//     (e.g. 'dr' beside 'door1..door6' in the same field = door).
// Every entry below appears in those catalogs; words NOT in the tables
// are spoken unchanged (parity: better to hear the dev word than nothing,
// and a wrong translation is worse than a terse one — same principle as
// the v2.18.2 stale-name guard).
//
// MECHANICS: a label is split on spaces; each token is stripped of
// leading/trailing digits ("man401" -> "man", "22main" -> "main"), then
// looked up. Single-character stems are dropped (the "n" in "main n
// cloud", stray "l"/"r" side markers). Digit suffixes are deliberately
// discarded — the browser's own duplicate ordinals ("man 2") number
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
// entity or model label contains these as a stray token — except 'op cl'
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
// like "main"/"std"/"midgal" carry no information a blind player needs —
// the browser's category already says "person"). Named NPCs are romaji or
// misspellings of their localized names (lude=Rude, hyde=Heidegger,
// esto=Ester, siera=Shera, irena=Elena, tuon=Tseng, korneo=Don Corneo...).
// avaman/avawoman/avafat = Biggs/Jessie/Wedge: the entity catalog shows
// 'av j/av b/av w' (AVALANCHE Jessie/Biggs/Wedge) on the exact bombing-
// mission fields where those three models stand (md1stin/md1_1/nmkin/
// elevtr1) — watch item in TODO.txt for the cargo-ship model reuse.
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
    // in the flevel model catalog — the 7th Heaven bar (player report
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
    { L"ladd", L"ladder down" }, { L"ladu", L"ladder up" },
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
    //   ev  = event (used interchangeably with 'event1/event2' — rcktin6
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
    { L"ldu", L"ladder up" }, { L"ldd", L"ladder down" },
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
    // 'door1/door2' — 'cl' there is NOT Cloud, so intercept before the
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
            // .char files) — the browser's slot-order ordinals are the
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
// section's size prefix — a torn buffer mid field-transition returns false
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
            // byte inside the name means we're reading the wrong data —
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
// Solid-body helpers (v2.30.22) — implementations for the declarations
// above WallBumpThread; the derivation and constants live in that block.
//
// All of this is self-contained reading (event array, triggers header,
// model-loader labels) so it can be called from BOTH the wall-bump thread
// and the pathfinder thread without shared state: FieldModelLabel /
// ClassifyModelLabel / TranslateDevLabel are pure per-call parsers over
// the (engine-owned, read-only to us) field file buffer. Cost is one
// section-2 parse per model per call — called once per contact episode or
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

// Fill out[] with every placed MC_PERSON model except the player and
// exclude_slot. Same filters as the destination-list build: the parked
// signature (tri==0 AND pos==(0,0), v2.30.19) is skipped, but OFF-mesh
// models (tri<0) are kept — Marlene behind the bar counter is off-mesh
// yet very much a solid body. v2.30.24: each body carries its LIVE
// collision radius; a radius of 0 (script-set intangible) or negative
// means the model cannot block anything right now and is not collected.
static size_t CollectBodies(int exclude_slot, BodyInfo out[32])
{
    const uint32_t arr = *reinterpret_cast<const volatile uint32_t*>(
        FF7Addr::FIELD_EVENT_DATA_PTR);
    const uint16_t pmid = *reinterpret_cast<const volatile uint16_t*>(
        FF7Addr::FIELD_PLAYER_MODEL_ID);
    const uint16_t nmod = *reinterpret_cast<const volatile uint16_t*>(
        FF7Addr::FIELD_N_MODELS);
    if (arr < 0x401000 || pmid > 0x20)
        return 0;
    const uint32_t n = (nmod < 32u) ? nmod : 32u;
    if (!IsReadableSpan(reinterpret_cast<const void*>(arr),
                        n * FF7Addr::FIELD_EVENT_DATA_STRIDE))
        return 0;

    // Field name for the label lookup (same sanitize as the nav thread).
    const uint32_t hdr = *reinterpret_cast<const volatile uint32_t*>(
        FF7Addr::FIELD_TRIGGERS_HEADER_PTR);
    if (hdr < 0x401000 ||
        !IsReadableSpan(reinterpret_cast<const void*>(hdr), 10))
        return 0;
    char fname[10] = {};
    memcpy(fname, reinterpret_cast<const void*>(
        hdr + FF7Addr::FTRIG_OFF_FIELD_NAME), 9);
    for (char& c : fname)
        if (c != '\0' && (c < 0x20 || c > 0x7E)) c = '\0';

    size_t cnt = 0;
    for (uint16_t m = 0; m < n && cnt < 32; ++m) {
        if (m == pmid || static_cast<int>(m) == exclude_slot)
            continue;
        const uint8_t* me = reinterpret_cast<const uint8_t*>(
            arr + m * FF7Addr::FIELD_EVENT_DATA_STRIDE);
        const int32_t* mpos = reinterpret_cast<const int32_t*>(
            me + FF7Addr::FIELD_EVENT_MODEL_POS);
        const int16_t tri = *reinterpret_cast<const int16_t*>(
            me + FF7Addr::FIELD_EVENT_TRIANGLE_ID);
        const int32_t mx = mpos[0] >> 12;
        const int32_t my = mpos[1] >> 12;
        if (tri == 0 && mx == 0 && my == 0)
            continue;                       // parked (v2.30.19)
        // Live collision radius (v2.30.24). <=0 = intangible right now
        // (script-cleared) — no body to block or name. Implausibly large
        // values (torn read) clamp to the common default 30.
        const int16_t rr = *reinterpret_cast<const int16_t*>(
            me + FF7Addr::FIELD_EVENT_COLLISION_RADIUS);
        if (rr <= 0)
            continue;
        std::wstring lbl;
        if (!FieldModelLabel(m, fname, lbl))
            continue;
        const wchar_t* friendly = nullptr;
        if (ClassifyModelLabel(lbl, &friendly) != MC_PERSON)
            continue;                       // props/chests never named here
        out[cnt].x      = static_cast<float>(mx);
        out[cnt].y      = static_cast<float>(my);
        out[cnt].radius = (rr > 200) ? 30.0f : static_cast<float>(rr);
        out[cnt].slot   = m;
        out[cnt].name   = TranslateDevLabel(lbl);
        ++cnt;
    }
    return cnt;
}

// The player's own live collision radius (same +0x72 field on the player's
// element). Falls back to 32 — the value both 2026-07-25 contact anchors
// solved for — when the element is unreadable or the value implausible.
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

// Nearest person within its contact distance (+ naming slack) whose
// bearing lies within the blocking cone of the given world direction.
// The d<1 case (standing literally on the body's coordinates — scripted
// overlaps) counts as a hit regardless of bearing.
static bool BodyInDirection(float px, float py, float world_deg,
                            int exclude_slot, std::wstring& out_name,
                            float* out_dist)
{
    BodyInfo bodies[32];
    const size_t n = CollectBodies(exclude_slot, bodies);
    const float pr = PlayerCollisionRadius();
    const float rad = world_deg * (3.14159265f / 180.0f);
    const float ux = sinf(rad), uy = cosf(rad);
    float best = FLT_MAX;
    bool  hit  = false;
    for (size_t i = 0; i < n; ++i) {
        const float dx = bodies[i].x - px;
        const float dy = bodies[i].y - py;
        const float d  = sqrtf(dx * dx + dy * dy);
        if (d >= pr + bodies[i].radius + kBodyNameSlack || d >= best)
            continue;
        if (d >= 1.0f && (dx * ux + dy * uy) / d < BODY_CONE_MIN_COS)
            continue;
        best     = d;
        hit      = true;
        out_name = bodies[i].name;
    }
    if (hit && out_dist)
        *out_dist = best;
    return hit;
}

// First person (smallest advance along the ray) whose contact circle the
// segment from (px,py) of the given length enters — "will walking this
// quantized leg run into somebody?"
static bool BodyOnRay(float px, float py, float world_deg, float length,
                      int exclude_slot, std::wstring& out_name)
{
    BodyInfo bodies[32];
    const size_t n = CollectBodies(exclude_slot, bodies);
    const float pr = PlayerCollisionRadius();
    const float rad = world_deg * (3.14159265f / 180.0f);
    const float ux = sinf(rad), uy = cosf(rad);
    float best_t = FLT_MAX;
    bool  hit    = false;
    for (size_t i = 0; i < n; ++i) {
        const float dx = bodies[i].x - px;
        const float dy = bodies[i].y - py;
        const float t  = dx * ux + dy * uy;        // advance along the ray
        const float tc = (t < 0.0f) ? 0.0f : (t > length ? length : t);
        const float cx = px + ux * tc - bodies[i].x;
        const float cy = py + uy * tc - bodies[i].y;
        const float rr = pr + bodies[i].radius + kBodyRayMargin;
        if (cx * cx + cy * cy >= rr * rr)
            continue;
        if (tc < best_t) {
            best_t   = tc;
            hit      = true;
            out_name = bodies[i].name;
        }
    }
    return hit;
}

// ---------------------------------------------------------------------------
// Script entity dev-names from field-file section 0 (v2.17, reworked
// 2026-07-14 after code review).
//
// The script section header carries an 8-char ASCII name per entity at
// +0x20 + id*8 ("cloud", "svisen1", "yubiwa"...) — the same
// developer-naming trick that labels people (v2.16), applied to the entity
// that OWNS a LINE trigger zone.
//
// Split into resolve-once + read-per-entity so the trigger build validates
// the WHOLE name table span exactly once per keypress instead of
// re-reading the script pointer and re-probing pages for every line (the
// review's efficiency finding), and so the validation actually covers
// every byte that gets read — the old single function probed only the
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
// ASCII — same reject-garbage policy as FieldModelLabel.
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
// Cross-layer JOURNEY planning (v2.23) — "which ladder first?"
//
// User request 2026-07-16: when a destination sits on another walkmesh
// LEVEL, "No walkable path found" says WHAT but not HOW — the player wants
// the connector sequence: which ladder/slide to take FIRST, then next, in
// order.
//
// The walkmesh alone cannot answer: levels are DISCONNECTED graph
// components by design, and the join is a scripted LINE trigger (ladder,
// slide, elevator) that MOVES the player. The script's destination is not
// readable statically — but the geometry is: a ladder's bottom zone and
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
// each connector recomputes from the new level — the same re-query flow
// the pathfinder already teaches.
//
// A false pairing (two unrelated triggers stacked in XY) would give a
// wrong-but-harmless hint: the journey only runs AFTER a direct route
// failed, every hop is spoken BY NAME so the player can judge it, and the
// fallback ("No walkable path found" + straight line) still exists when
// no connector chain is found.
// ---------------------------------------------------------------------------

// Connected components of the walkmesh adjacency graph — each component is
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

// Spoken name for a LINE trigger — the same naming rules as the Triggers
// category (owning entity's dev name, translated; stale-guarded by the
// entity→slot map; "Trigger N" fallback).
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
        return;
    }
    wchar_t buf[24];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"Trigger %u", line_idx + 1u);
    out = buf;
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
    const int n = static_cast<int>(mesh.size());
    const int start = ResolveTriHint(mesh, start_hint, px, py, pz);
    const int goal  = ResolveTriHint(mesh, goal_hint, tx, ty, tz);
    if (start < 0 || goal < 0)
        return false;

    std::vector<int> comp;
    const int n_comps = WalkmeshComponents(mesh, comp);
    if (n_comps < 2 || comp[start] == comp[goal])
        return false;   // same level — not a journey problem

    // Snapshot enabled LINE triggers: standing point (line midpoint, with
    // height), its component, and identity. Same array and enabled-guard
    // as the Triggers category.
    struct JLine {
        float   mx, my, mz;
        int     tri, comp;
        int     comp2;      // component of the SECOND endpoint (a line
                            // drawn up a wall spans levels by itself)
        uint8_t idx, ent;
    };
    JLine jl[FF7Addr::FLINE_MAX];
    int n_jl = 0;
    const uint16_t n_lines = *reinterpret_cast<const volatile uint16_t*>(
        FF7Addr::FIELD_LINE_COUNT);
    for (uint32_t i = 0; i < n_lines && i < FF7Addr::FLINE_MAX; ++i) {
        const uint8_t* le = reinterpret_cast<const uint8_t*>(
            FF7Addr::FIELD_LINE_ARRAY + i * FF7Addr::FLINE_STRIDE);
        if (le[FF7Addr::FLINE_OFF_ENABLED] == 0)
            continue;
        const int16_t* v = reinterpret_cast<const int16_t*>(le);
        JLine& j = jl[n_jl];
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
        ++n_jl;
    }

    // Connector edges between components (see header comment):
    //   pair rule — two triggers on different components, XY-close;
    //   span rule — one trigger whose own endpoints are on two components.
    constexpr float JOURNEY_PAIR_DIST = 300.0f;
    struct JEdge { int ca, cb; int via; };   // stand on jl[via] (in ca)
    std::vector<JEdge> edges;
    for (int a = 0; a < n_jl; ++a) {
        if (jl[a].comp2 != jl[a].comp) {
            edges.push_back({ jl[a].comp,  jl[a].comp2, a });
            edges.push_back({ jl[a].comp2, jl[a].comp,  a });
        }
        for (int b = a + 1; b < n_jl; ++b) {
            if (jl[a].comp == jl[b].comp)
                continue;
            const float dx = jl[a].mx - jl[b].mx;
            const float dy = jl[a].my - jl[b].my;
            if (dx * dx + dy * dy >
                JOURNEY_PAIR_DIST * JOURNEY_PAIR_DIST)
                continue;
            edges.push_back({ jl[a].comp, jl[b].comp, a });
            edges.push_back({ jl[b].comp, jl[a].comp, b });
        }
    }
    if (edges.empty())
        return false;

    // BFS over components: fewest connectors from the player's level to
    // the target's. prev_edge reconstructs the trigger sequence.
    std::vector<int>     prev_edge(n_comps, -1);
    std::vector<uint8_t> seen(n_comps, 0);
    std::vector<int>     queue;
    seen[comp[start]] = 1;
    queue.push_back(comp[start]);
    for (size_t qi = 0; qi < queue.size() && !seen[comp[goal]]; ++qi) {
        const int c = queue[qi];
        for (size_t e = 0; e < edges.size(); ++e) {
            if (edges[e].ca != c || seen[edges[e].cb])
                continue;
            seen[edges[e].cb] = 1;
            prev_edge[edges[e].cb] = static_cast<int>(e);
            queue.push_back(edges[e].cb);
        }
    }
    if (!seen[comp[goal]])
        return false;   // levels exist but nothing connects them

    // Trigger sequence, player's level first.
    std::vector<int> hops;   // jl indices to take, in order
    for (int c = comp[goal]; c != comp[start]; ) {
        const JEdge& e = edges[prev_edge[c]];
        hops.push_back(e.via);
        c = e.ca;
    }
    for (size_t i = 0, j = hops.size() - 1; i < j; ++i, --j) {
        const int t = hops[i]; hops[i] = hops[j]; hops[j] = t;
    }

    // Walking route to the FIRST connector (same pipeline as a direct
    // route; the connector is in the player's own component by
    // construction, so A* cannot fail — guarded anyway).
    std::wstring route;
    {
        const JLine& first = jl[hops[0]];
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
    TriggerLineSpokenName(jl[hops[0]].idx, jl[hops[0]].ent, nm);
    out += nm;
    if (!route.empty()) {
        out += L", ";
        out += route;
    }
    for (size_t h = 1; h < hops.size(); ++h) {
        TriggerLineSpokenName(jl[hops[h]].idx, jl[hops[h]].ent, nm);
        out += L". Then ";
        out += nm;
    }
    out += L". Then ask again.";

    if (Config::Get().debug_log) {
        char dbg[224];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] NAV journey comps=%d hops=%u first_line=%u '%ls'",
            n_comps, static_cast<unsigned>(hops.size()),
            static_cast<unsigned>(jl[hops[0]].idx), out.c_str());
        Log::Write(dbg);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Friendly location name (v2.24): the game's own menu caption ("Sector 1
// Station"), read from the MPNAM buffer — full derivation and the live
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
            break;   // ⚠ bytes past the terminator hold the PREVIOUS
                     // name's tail (live-observed) — never read on
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
// Visited-places cache (v2.25) — friendly captions BY FIELD ID, learned
// from the v2.24 MPNAM buffer as the player travels and persisted to
// ffvii_accessibility_places.txt next to the DLL.
//
// WHY: gateways know their destination FIELD ID, and the maplist gives
// every id an internal name ("nmkin_2") — but the FRIENDLY caption
// ("No. 1 Reactor") for another field cannot be read at runtime (each
// field's caption lives in its own script). It CAN be remembered: while
// the player stands on field X, the mod sees both X and X's caption, so
// exits to anywhere the player has ever been speak the friendly name.
// New games start with what previous sessions learned — the file is the
// player's own map knowledge, growing as they explore.
//
// INHERITANCE CAVEAT (documented, accepted): a field whose script sets no
// MPNAM keeps the PREVIOUS field's caption, and the cache records that
// inherited caption for it — which is exactly what the sighted menu
// displays while standing there, so parity holds.
//
// THREADING: everything here runs on FieldNavThread only (load at thread
// start, learn in its poll, lookups in its list build) — no locks needed.
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

// Spoken destination name for a gateway's target field id (v2.25):
//   1. the player's own learned caption ("No. 1 Reactor");
//   2. the game's maplist internal name ("nmkin 2"; underscores spoken
//      as spaces; wm* entries are the world map);
//   3. false -> caller keeps the positional "Exit N" label.
static bool DestinationName(int dest_id, std::wstring& out)
{
    if (dest_id > 0 && dest_id < FF7FieldNames::kCount &&
        g_places[dest_id][0]) {
        out = g_places[dest_id];
        return true;
    }
    const char* nm = FF7FieldNames::Get(dest_id);
    if (!nm)
        return false;
    if (nm[0] == 'w' && nm[1] == 'm') {
        out = L"World map";
        return true;
    }
    out.clear();
    for (const char* p = nm; *p; ++p)
        out += (*p == '_') ? L' ' : static_cast<wchar_t>(*p);
    return !out.empty();
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
    };
    enum { KJ, KL, KK, KP, KM, KLBRACKET, KRBRACKET, KBACKSLASH, KMINUS, KPLUS,
           KEY_COUNT };
    bool was_down[KEY_COUNT] = {};

    // Browser state. Selection and category persist while the player stays
    // on one field (opening the menu or fighting a battle does NOT reset
    // them); a field change resets both.
    static const wchar_t* const kCategoryNames[] = {
        L"All", L"Exits", L"People", L"Save points", L"Triggers", L"Items"
    };
    constexpr int kCategoryCount = 6;
    int16_t nav_field_id = 0;
    int     category     = 0;
    int     selection    = 0;

    // Screen-change announcement tracker (v2.23) — separate from
    // nav_field_id, which only updates on the KEYPRESS path; this one runs
    // every poll so the announcement fires the moment control returns on
    // the new screen. 0 = nothing announced yet this session.
    int16_t announced_field_id = 0;

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
    // beep appended to their announcements — the cue that this target is
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
        // minus the dialog-activity window — a scan DURING dialog is
        // harmless, the announce just queues after the dialog speech).
        const int16_t field_id = *reinterpret_cast<const volatile int16_t*>(
            FF7Addr::FIELD_ID);
        const uint8_t game_mode = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::GAME_MODE);
        const uint8_t menu_open = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::MENU_OPEN);
        if (field_id == 0 || game_mode != FF7Addr::GAME_MODE_FIELD ||
            menu_open != 0) {
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
        // start node — exact even on stacked layers. <0 (briefly off-mesh,
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

        // ---- screen-change announcement (v2.23) ---------------------------
        // Fires the first poll after control returns on a NEW screen. Each
        // screen has its own fixed camera, so an exit crossing REBASES what
        // "up" means (control_direction changed) — the user experienced
        // this as directions "shifting as if the perspective changed" and
        // found it disorienting. Sighted players get the camera cut as
        // their cue; this is the audio equivalent. interrupt=false: a
        // transition often follows dialog or an announcement — queue behind
        // it, never clobber. Also announces the first screen after launch/
        // load (announced_field_id starts 0), which doubles as a "you're on
        // the field now" orientation cue.
        if (field_id != announced_field_id) {
            announced_field_id = field_id;
            if (Config::Get().announce_map_change) {
                // v2.24: prefer the game's own menu caption ("Sector 1
                // Station") from the MPNAM buffer — the friendly name a
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
                        // synthesizers — say them as spaces.
                        msg += (c == '_') ? L' ' : static_cast<wchar_t>(c);
                        have_name = have_name || c != '_';
                    }
                }
                if (have_name)
                    TTS::Speak(msg, /*interrupt=*/false);
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
        // fields — without the reset every model would read as "wandering"
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
        // larger (v2.30.26). ⚠ The original "talk_radius = the exact
        // circle the OK button tests" reading is WRONG for large-bodied
        // models: Barret's talk radius is 70 but his collision radius is
        // 48 — the player's center bottoms out at ~80 from his and can
        // NEVER enter the 70 circle, yet talking at contact works (the
        // 2026-07-25 street scene: blocked at 81, talk ushered the
        // player into the bar; play report: "it does not beep when I
        // get near him"). The engine-side check reader was hunted
        // statically (ff7_talk_range_static.py — found the TALKR/TLKR2
        // handlers 0x618253/0x6182DF and the scale-based defaults
        // col=30·s>>9 / talk=80·s>>9, but not the reader), so the rule
        // shipped is the behaviorally PROVEN one: body contact always
        // suffices to interact → chirp at
        //   max(talk_radius, player_col + model_col + one step).
        // Unchanged for default-sized NPCs (talk 70 > contact ~62).
        // Skips talk-disabled people (the +0x61 byte — the Jessie lesson:
        // no ping for someone who won't respond), off-mesh models, and
        // anything on another LAYER (z gate — a walkway overhead must not
        // ping the floor below). Suppressed during scripted scenes
        // (uc_lock) and while a dialog is up, so it never plays over
        // conversation; the armed state still updates then, so no
        // spurious ping fires when the dialog closes.
        if (Config::Get().proximity_tone) {
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
                if (quiet_ok &&
                    GetTickCount64() - last_prox_beep >= PROX_MIN_GAP_MS) {
                    Beep(PROX_BEEP_HZ, PROX_BEEP_MS);
                    last_prox_beep = GetTickCount64();
                }
            };

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
                // contact + one step) — see the header comment above.
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
                const bool reachable = tri >= 0 && radius > 0 && !talk_off &&
                                       dz > -PROX_Z_GATE && dz < PROX_Z_GATE;
                if (reachable && dist <= eff) {
                    if (prox_armed_m[m]) {
                        prox_armed_m[m] = false;
                        try_beep();
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

        bool pressed[KEY_COUNT] = {};
        bool any_pressed = false;
        for (int k = 0; k < KEY_COUNT; ++k) {
            const bool down = (GetAsyncKeyState(kVKs[k]) & 0x8000) != 0;
            pressed[k] = focused && down && !was_down[k];
            was_down[k] = down;
            any_pressed = any_pressed || pressed[k];
        }

        // Right-analog-stick input (v2.21): polled every tick like the keys
        // so held-state tracking stays fresh, with edges suppressed while
        // unfocused — the exact focus rule the keyboard uses. XInput is a
        // read-only shared query, so the game (and FFNx) see the controller
        // exactly as before; the stick and R3 carry no native function
        // (verified — see gamepad.h). gamepad_nav=false skips even the poll.
        GamepadNav::Actions pad = {};
        if (Config::Get().gamepad_nav)
            pad = GamepadNav::Poll(focused);

        if (!any_pressed && !pad.Any())
            continue;

        const bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
        const bool ctrl  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        if (ctrl)
            memset(pressed, 0, sizeof(pressed));   // Ctrl+\ (layer filter)
                // etc. not applicable yet — Ctrl suppresses only the KEYS;
                // a simultaneous stick action is unrelated and proceeds.

        // Decode key presses into browser actions (accessiblity_keys.txt),
        // then OR in the stick's alternate triggers (v2.21 — same actions,
        // second input path):
        //   J/[ prev dest, L/] next dest (unshifted)   | stick left/right
        //   Shift+J/- prev category, Shift+L/= next    | stick up/down
        //   K announce selection, Shift+K reset category
        //   \/P directions (unshifted; Shift+\ filter  | R3 click
        //       not applicable yet)
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
        const bool act_map_name  = pressed[KM] && !shift;

        if (!(act_prev_dest || act_next_dest || act_prev_cat || act_next_cat ||
              act_announce || act_reset_cat || act_directions || act_map_name))
            continue;

        // ---- field name (plain ASCII in the header, not FF7-encoded) -----
        char fname[10] = {};
        memcpy(fname, reinterpret_cast<const void*>(hdr + FF7Addr::FTRIG_OFF_FIELD_NAME), 9);
        for (char& c : fname)
            if (c != '\0' && (c < 0x20 || c > 0x7E)) c = '\0';

        if (act_map_name) {
            // v2.24: friendly menu caption first, then the internal name
            // as the unique per-screen identifier ("Sector 1 Station,
            // md1stin") — several screens share one caption, and M is the
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
        // arriving from All, "Exits, 6" when arriving from People — the
        // reported direction-dependent numbers). Category/field mutations
        // now happen first and the list is built for the NEW state.
        // (CAT_* constants are file-scope since v2.18.2 — see
        // CategoryForModelClass above.)

        // Field change invalidates selection and category.
        if (field_id != nav_field_id) {
            nav_field_id = field_id;
            category  = 0;
            selection = 0;
        }

        bool announce_cat = false;
        if (act_prev_cat || act_next_cat) {
            category += act_next_cat ? 1 : -1;
            if (category < 0) category = kCategoryCount - 1;
            if (category >= kCategoryCount) category = 0;
            selection = 0;
            announce_cat = true;
        } else if (act_reset_cat) {
            category  = 0;
            selection = 0;
            announce_cat = true;
        }

        // ---- rebuild the destination list (fresh every keypress) ---------
        // Max 12 gateways + 32 models — rebuilding on demand is cheaper
        // than any caching scheme and always reflects the live field
        // (NPCs move; a fresh read gives their current position). Slot
        // order is the destination's IDENTITY: "Exit 2" / "Person 3" keep
        // their names as the player moves — never renumbered by distance.
        constexpr int kMaxDests =
            FF7Addr::FTRIG_GATEWAY_COUNT + 32    // exits + model cap
            + FF7Addr::FLINE_MAX;                // + LINE trigger zones
        NavDest dests[kMaxDests];
        int n_dests = 0;

        if (category == CAT_ALL || category == CAT_EXITS) {
            // v2.25: exits are named by DESTINATION — "To No. 1 Reactor"
            // (visited-place caption), "To nmkin 2" (maplist internal
            // name), "To World map" — with "Exit N" only when the id
            // resolves to nothing (see DestinationName). Two passes so
            // duplicate destinations get ordinals ("To Platform 2"), the
            // same slot-order identity rule as every other category. A
            // name can UPGRADE mid-session (internal -> caption once the
            // place is visited) — slot order still never changes.
            struct GwTmp {
                const int16_t* v;
                std::wstring   base;
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
                std::wstring dn;
                if (DestinationName(dest_id, dn)) {
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
                NavDest& d = dests[n_dests++];
                if (total > 1)
                    _snwprintf_s(d.name, _countof(d.name), _TRUNCATE,
                                 L"%ls %d", gws[a].base.c_str(), ordinal);
                else
                    _snwprintf_s(d.name, _countof(d.name), _TRUNCATE,
                                 L"%ls", gws[a].base.c_str());
                const int16_t* v = gws[a].v;
                d.line_x1 = v[0]; d.line_y1 = v[1];
                d.line_x2 = v[3]; d.line_y2 = v[4];
                d.line_z1 = v[2]; d.line_z2 = v[5];
                d.model_slot = -1;
                d.target_tri = -1;   // exits carry no triangle id — the
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
        // the model as a SAVE POINT — originally a heuristic, CONFIRMED
        // game-wide by the v2.18 offline flevel catalog ("fieldbg saveicn"
        // ×57 is the only save label in all 720 fields). Item props
        // (chests, materia, pickups, keys) classify into the ITEMS
        // category the same way — catalog evidence at the classification
        // block in pass 1 below. v2.15.2 note kept for history: the
        // character_id (+0x6C) naming idea was live-DISPROVED (an NPC read
        // as "Red XIII") — never name from that field.
        if (category == CAT_ALL || category == CAT_PEOPLE ||
            category == CAT_SAVE || category == CAT_ITEMS) {
            // The array span was not fully validated above (only the
            // player's element) — validate every element this walk reads.
            const uint32_t n_walk = (nmod < 32u) ? nmod : 32u;
            const bool span_ok = IsReadableSpan(
                reinterpret_cast<const void*>(arr),
                n_walk * FF7Addr::FIELD_EVENT_DATA_STRIDE);

            // Pass 1: labels/classification for EVERY model, eligibility
            // and positions for on-mesh ones. Labels and class are
            // assigned regardless of eligibility (v2.18.2): the ordinal
            // pass counts by label over ALL labeled models so a collected
            // pickup's despawn cannot rename its surviving sibling
            // ("Item 2" stays "Item 2" after "Item" is taken — the
            // identity-stability rule; the review confirmed the old
            // eligible-only counting silently renumbered). Corollary: a
            // never-on-mesh labeled model still reserves its ordinal, so a
            // field can list "guard 2" with no "guard" — accepted, slot
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

                std::wstring lbl;
                const bool have_lbl = FieldModelLabel(m, fname, lbl);

                if (Config::Get().debug_log) {
                    // col = live collision radius (+0x72, confirmed
                    // v2.30.24 — the rc6E/rc70 candidates are retired,
                    // both rejected by the 2026-07-25 dump).
                    char dbg[224];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] NAV person m=%u tri=%d ent=%u talk=%d "
                        "col=%d pos=(%ld,%ld) label='%ls'",
                        m, tri,
                        *reinterpret_cast<const uint8_t*>(me + FF7Addr::FIELD_EVENT_ENTITY_ID),
                        *reinterpret_cast<const int16_t*>(me + FF7Addr::FIELD_EVENT_TALK_RADIUS),
                        *reinterpret_cast<const int16_t*>(me + FF7Addr::FIELD_EVENT_COLLISION_RADIUS),
                        static_cast<long>(mx), static_cast<long>(my),
                        have_lbl ? lbl.c_str() : L"(none)");
                    Log::Write(dbg);
                }

                if (have_lbl) {
                    // One classifier decides class AND spoken base name
                    // (v2.18.2 — see ClassifyModelLabel for the catalog
                    // evidence). The friendly name replaces the label so
                    // the ordinal pass yields "Chest 2", "Materia 3".
                    // People (no friendly name) get the v2.20 dev-label
                    // translation instead: romaji -> English, character
                    // words -> live savemap names. Translation runs BEFORE
                    // the ordinal pass, so duplicates group on the SPOKEN
                    // name ("man", "man 2" — even when the dev names
                    // differed only by their meaningless digit suffixes).
                    const wchar_t* friendly = nullptr;
                    cls[m] = ClassifyModelLabel(lbl, &friendly);
                    wcsncpy_s(labels[m],
                              friendly ? friendly
                                       : TranslateDevLabel(lbl).c_str(),
                              _TRUNCATE);
                    if (cls[m] == MC_CHEST) {
                        // Chest lid state (v2.18.1, tightened v2.18.2):
                        // opened = lid animation held AT its final frame —
                        // lastFrame != 0 AND currentFrame == lastFrame<<4
                        // (the subframe scale both confirmed states showed:
                        // 0x1D0 == 0x1D << 4 after settle AND after field
                        // re-entry; see ff7_addresses.h state matrix). The
                        // extra currentFrame term keeps a non-lid animation
                        // that RETURNS to rest (deny rattle, cutscene pose)
                        // from reading as opened; the residual risk flips
                        // to a missed "opened" — the safer direction, a
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
                // placed yet sit at EXACTLY (0,0) with triangle id 0 —
                // the 2026-07-23 hideout log showed Tifa (upstairs at the
                // time), the camera dummy, and a not-yet-granted materia
                // all with this exact signature, while every VISIBLE
                // model had a nonzero position (three of them also read
                // tri=0, which is why tri alone can't tell — 0 is a valid
                // triangle id, only the tri==0 AND pos==(0,0) combination
                // marks "parked"). Listing them produced unreachable
                // ghost "people"/"items". The scan re-runs continuously,
                // so the moment the script actually places the model it
                // gains a real position and appears — hiding is dynamic,
                // not permanent.
                if (tri == 0 && mx == 0 && my == 0)
                    continue;

                eligible[m] = true;
                ex[m] = static_cast<int16_t>(mx);
                ey[m] = static_cast<int16_t>(my);
                ez[m] = static_cast<int16_t>(mpos[2] >> 12);
                etri[m] = tri;
                // v2.26: TLKON state — see FIELD_EVENT_TALK_OFF for the
                // derivation and the Jessie incident that motivated it.
                talk_off[m] = *reinterpret_cast<const uint8_t*>(
                    me + FF7Addr::FIELD_EVENT_TALK_OFF) != 0;
            }

            // Pass 2: duplicate-label counts (so "shinra guard" ×3 becomes
            // "shinra guard", "shinra guard 2", "shinra guard 3").
            // Counted over ALL labeled models, eligible or not (v2.18.2)
            // — despawned pickups keep reserving their ordinal so
            // survivors are never renamed.
            // Pass 3: emit destinations in slot order. The category
            // filter is ONE comparison against the class→category map —
            // mutual exclusion is structural, not hand-maintained
            // (v2.18.2; the old sv/it boolean chain was the review's
            // drift-risk finding).
            for (uint16_t m = 0; m < 32; ++m) {
                if (!eligible[m])
                    continue;
                // v2.30.18: scenery is browsable NOWHERE — not even All.
                // A sighted player doesn't "navigate to" the cash register
                // or the camera dummy; listing them (usually with no
                // walkable path — they sit inside furniture) is pure noise.
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
                // TLKON-off byte — the Jessie ladder-tutorial incident:
                // the pathfinder placed the player 17 units from her,
                // inside her talk radius, and OK did nothing because her
                // dialog was script-disabled). People only, and only the
                // DISABLED side: an enabled byte does not guarantee the
                // entity has a talk script, so silence stays honest.
                if (cls[m] == MC_PERSON && talk_off[m])
                    wcsncat_s(d.name, _countof(d.name), L", talk disabled",
                              _TRUNCATE);
                d.line_x1 = d.line_x2 = ex[m];
                d.line_y1 = d.line_y2 = ey[m];
                d.line_z1 = d.line_z2 = ez[m];
                d.model_slot = m;
                d.target_tri = etri[m];
            }
        }

        // LINE trigger zones (v2.17): script-created lines — ladders,
        // elevators, touch/cross zones. Stored in the engine's static line
        // array (see ff7_addresses.h SECTION 1g for the full derivation:
        // three opcode handlers disassembled, all agreeing on the layout).
        // Disabled lines (LINON 0) are skipped — the script has switched
        // that zone off, so walking to it does nothing; this also gives
        // information parity with what the zone would DO for a sighted
        // player right now. Named by the owning entity's dev name
        // ("yubiwa", "svisen1"); slot order is the identity, so "Trigger 3"
        // keeps its number as the player moves, same rule as exits.
        if (category == CAT_ALL || category == CAT_TRIGGERS) {
            const uint16_t n_lines = *reinterpret_cast<const volatile uint16_t*>(
                FF7Addr::FIELD_LINE_COUNT);

            // Entity-name table resolved and span-validated ONCE per
            // build, not per line (v2.18.2 — review efficiency finding).
            const uint8_t* ent_table = nullptr;
            uint8_t        ent_count = 0;
            const bool have_names =
                FieldEntityNameTable(&ent_table, &ent_count);

            // Gather first, then emit: names must all be known before
            // duplicate ordinals can be computed (v2.18.2 — the review
            // confirmed two same-named lines used to speak identically,
            // which J/L cycling cannot disambiguate by ear).
            struct TrigLine {
                int16_t x1, y1, x2, y2;
                int16_t z1, z2;     // heights (v2.23, layer locates)
                uint8_t line_idx;
                wchar_t name[24];   // translated entity name (v2.20 —
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
                // x1,y1,z1,x2,y2,z2 — heights kept since v2.23 (layer
                // location for turn-by-turn); routing itself stays 2D.
                t.x1 = v[0]; t.y1 = v[1]; t.z1 = v[2];
                t.x2 = v[3]; t.y2 = v[4]; t.z2 = v[5];
                t.line_idx = static_cast<uint8_t>(i);
                t.name[0] = L'\0';
                // v2.30.23: what this line DOES, from the offline script
                // catalog — keyed by the same (field, owning entity)
                // identity the engine's own line array carries. A field
                // mid-transition can briefly pair the OLD array with the
                // NEW field id; a mismatched key then simply finds no
                // row (or a same-field stale row for one keypress), the
                // identical tradeoff the name lookup above accepts.
                t.info = FF7LineCatalog::Find(
                    static_cast<uint16_t>(field_id), ent);

                // Name only when the engine's own entity→line-slot map
                // agrees this slot belongs to that entity (the LINE
                // handler writes both together). During a field
                // transition the line array can briefly hold the OLD
                // field's entries while the script pointer already serves
                // the NEW field's names — the review's cross-field
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

                // v2.30.23: behavior suffix from the offline catalog —
                // the 2026-07-25 hideout lesson (player hunted the way
                // upstairs on a cutscene 'border' line while the real
                // exit was the 'pinball' lift line). A sighted player
                // SEES lift platform vs floor patch; this suffix is that
                // glance: "pinball, exit to Seventh Heaven" / "border,
                // scene". Suffixes state only what the SCRIPTS contain —
                // an exit may still be story-gated at any given moment.
                if (tl[a].info != nullptr) {
                    using namespace FF7LineCatalog;
                    const LineInfo* li = tl[a].info;
                    std::wstring sfx;
                    switch (li->kind) {
                    case LK_EXIT:
                    case LK_EXIT_OK: {
                        std::wstring dn;
                        if (li->dest_field >= 0 &&
                            DestinationName(li->dest_field, dn)) {
                            sfx = L", exit to ";
                            sfx += dn;
                        } else {
                            sfx = L", exit";   // multi/unknown destination
                        }
                        if (li->kind == LK_EXIT_OK)
                            sfx += L", press OK";
                        break;
                    }
                    case LK_CLIMB:
                        // Ladder names already say "ladder up/down"
                        // (v2.20 translation) — only unnamed/odd climbs
                        // need the word.
                        if (wcsstr(d.name, L"ladder") == nullptr)
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
        }

        if (selection >= n_dests)
            selection = (n_dests > 0) ? n_dests - 1 : 0;

        // Announce helpers ---------------------------------------------------
        const auto speak_category = [&]() {
            wchar_t msg[64];
            _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"%ls. %d %ls.",
                         kCategoryNames[category], n_dests,
                         n_dests == 1 ? L"destination" : L"destinations");
            TTS::Speak(msg, /*interrupt=*/true);
        };
        const auto speak_selection = [&](bool with_position) {
            if (n_dests == 0) {
                TTS::Speak(L"No destinations.", /*interrupt=*/true);
                return;
            }
            wchar_t msg[96];   // name is up to 63 chars since v2.30.23
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
                Beep(WANDER_BEEP_HZ, WANDER_BEEP_MS);
        };

        // Category changes were applied BEFORE the list build (v2.15.2 fix)
        // — only the announcement remains to be made here, with the count
        // of the list actually built for the new category.
        if (announce_cat) {
            speak_category();
            continue;
        }
        if (act_prev_dest || act_next_dest) {
            if (n_dests == 0) {
                TTS::Speak(L"No destinations.", /*interrupt=*/true);
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
        if (n_dests == 0) {
            TTS::Speak(L"No destinations.", /*interrupt=*/true);
            continue;
        }
        const NavDest& d = dests[selection];

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
        // calibration walkabout (md1stin, control_dir=124 -> 174.4°:
        // pressing Up moved the player at world bearing 5.6° = 180° −
        // control_deg exactly, Down at 185.6°) fixed the rotation —
        // control_direction is the world bearing of screen-DOWN — and the
        // follow-up play test confirmed left/right land correctly, so the
        // mapping is a pure rotation with no mirror. (The first guess,
        // world − control, was 180° off: "down" for a dead-ahead exit.)
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
        //   SPOKEN_ROUTE — the route is the announcement, done;
        //   NO_PATH      — mesh healthy but the target is graph-unreachable:
        //                  usually ANOTHER LEVEL — try the v2.23 journey
        //                  planner ("first take ladder up..."); only when
        //                  that also finds no connector chain, fall back to
        //                  straight-line + an explicit "no walkable path"
        //                  prefix (the FF4 mod's out-of-range behavior);
        //   UNAVAILABLE  — mesh unreadable or failed its self-guards:
        //                  silent straight-line fallback.
        // v2.30.25: how far short of the target the walk may stop — a
        // person is reached at their TALK RADIUS (read live; floor 20 so
        // talk=0/1 models still get approached, cap 90). v2.30.26: OR at
        // body contact, whichever is larger — the same behaviorally
        // proven rule as the proximity chirp (Barret: contact 80 > talk
        // 70, and talking at contact works). Exits/lines keep 0: those
        // must be stepped on. Used by the route builder's body tests AND
        // both cautions below.
        float target_reach = 0.0f;
        if (d.model_slot >= 0) {
            int16_t tr = 40;
            int16_t mc = 0;
            const uint8_t* tme = reinterpret_cast<const uint8_t*>(
                arr + d.model_slot * FF7Addr::FIELD_EVENT_DATA_STRIDE);
            if (IsReadableSpan(tme, FF7Addr::FIELD_EVENT_DATA_STRIDE)) {
                tr = *reinterpret_cast<const int16_t*>(
                    tme + FF7Addr::FIELD_EVENT_TALK_RADIUS);
                mc = *reinterpret_cast<const int16_t*>(
                    tme + FF7Addr::FIELD_EVENT_COLLISION_RADIUS);
            }
            if (tr < 20) tr = 20;
            if (tr > 90) tr = 90;
            target_reach = static_cast<float>(tr);
            if (mc > 0 && mc <= 200) {
                const float contact = PlayerCollisionRadius()
                                      + static_cast<float>(mc) + 8.0f;
                if (contact > target_reach)
                    target_reach = contact;
            }
        }

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
            int   first_sector = -1;
            float first_len    = 0.0f;
            const RouteOutcome ro = BuildTurnByTurnRoute(
                fpx, fpy, fpz, player_tri, ftx, fty, ftz,
                d.target_tri, control_deg, d.model_slot, target_reach,
                route, &first_sector, &first_len);
            if (ro == RouteOutcome::SPOKEN_ROUTE) {
                std::wstring rmsg(d.name);
                rmsg += L": ";
                rmsg += route;
                rmsg += L'.';
                // v2.30.22 body caution: the route is walkmesh-correct,
                // but a solid PERSON standing on the first quantized leg
                // stops the player exactly like a wall (the 2026-07-25
                // hideout report — Tifa in the aisle to Barret). Warn in
                // the same utterance so "left 1 second" comes with the
                // reason it may thud. The destination model itself is
                // excluded — routes TO a person always end at their body.
                if (first_sector >= 0) {
                    const float ray_world = first_sector * 45.0f
                                            - control_deg + 180.0f;
                    // v2.30.25: never probe INSIDE the target's reach
                    // bubble — a companion standing next to the target
                    // is not "in the way" of a walk that stops at talk
                    // range. dist = straight-line distance to target.
                    float clen = first_len + 40.0f;
                    const float cap = dist - target_reach + 40.0f;
                    if (clen > cap) clen = cap;
                    std::wstring bname;
                    if (clen > 0.0f &&
                        BodyOnRay(fpx, fpy, ray_world, clen,
                                  d.model_slot, bname)) {
                        rmsg += L' ';
                        rmsg += bname;
                        rmsg += L" is in the way.";
                    }
                }
                TTS::Speak(rmsg, /*interrupt=*/true);
                spoke_route = true;
            } else if (ro == RouteOutcome::NO_PATH) {
                std::wstring jmsg;
                if (BuildJourneySpeech(fpx, fpy, fpz, player_tri,
                                       ftx, fty, ftz, d.target_tri,
                                       control_deg, d.name, jmsg)) {
                    TTS::Speak(jmsg, /*interrupt=*/true);
                    spoke_route = true;
                } else {
                    // v2.30.25: no journey either — the target stands
                    // OFF the walkable floor (Biggs on the crates, Tifa
                    // behind the locked counter). Route to the nearest
                    // reachable point instead of a bare straight-line
                    // shrug; the talk radius covers the last gap.
                    std::wstring nroute;
                    int   nsec = -1;
                    float nlen = 0.0f;
                    if (BuildTurnByTurnRoute(fpx, fpy, fpz, player_tri,
                            ftx, fty, ftz, d.target_tri, control_deg,
                            d.model_slot, target_reach, nroute,
                            &nsec, &nlen, /*to_nearest=*/true)
                        == RouteOutcome::SPOKEN_ROUTE) {
                        std::wstring rmsg(d.name);
                        rmsg += L", off the walkable area: ";
                        rmsg += nroute;
                        rmsg += L'.';
                        if (nsec >= 0) {   // same caution + reach cap
                            const float ray_world = nsec * 45.0f
                                                    - control_deg + 180.0f;
                            float clen = nlen + 40.0f;
                            const float cap = dist - target_reach + 40.0f;
                            if (clen > cap) clen = cap;
                            std::wstring bname;
                            if (clen > 0.0f &&
                                BodyOnRay(fpx, fpy, ray_world, clen,
                                          d.model_slot, bname)) {
                                rmsg += L' ';
                                rmsg += bname;
                                rmsg += L" is in the way.";
                            }
                        }
                        TTS::Speak(rmsg, /*interrupt=*/true);
                        spoke_route = true;
                    } else {
                        fallback_prefix = L"No walkable path found. ";
                    }
                }
            }
        }

        // ---- straight-line announcement (style "line", and the fallback) --
        if (!spoke_route) {
            wchar_t msg[192];
            const int secs = static_cast<int>(
                dist / FF7Addr::WALKMESH_UNITS_PER_SEC + 0.5f);
            if (secs < 1)
                _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                             L"%ls%ls: %ls, very close.",
                             fallback_prefix, d.name, DpadSectorName(input_deg));
            else
                _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                             L"%ls%ls: %ls, %d %ls.",
                             fallback_prefix, d.name, DpadSectorName(input_deg),
                             secs, secs == 1 ? L"second" : L"seconds");
            // v2.30.22 body caution, straight-line flavor: test the
            // QUANTIZED direction the announcement names (not the exact
            // bearing — the player walks the d-pad word they heard),
            // over the first ~2 seconds of travel.
            {
                const float ray_world =
                    DpadSectorIndex(input_deg) * 45.0f - control_deg + 180.0f;
                // v2.30.25: capped at the target's reach bubble, same
                // rule as the turn-by-turn caution.
                float ray_len = (dist < 320.0f ? dist : 320.0f) + 40.0f;
                const float cap = dist - target_reach + 40.0f;
                if (ray_len > cap) ray_len = cap;
                std::wstring bname;
                if (ray_len > 0.0f &&
                    BodyOnRay(static_cast<float>(px), static_cast<float>(py),
                              ray_world, ray_len, d.model_slot, bname)) {
                    wcsncat_s(msg, _countof(msg), L" ", _TRUNCATE);
                    wcsncat_s(msg, _countof(msg), bname.c_str(), _TRUNCATE);
                    wcsncat_s(msg, _countof(msg), L" is in the way.", _TRUNCATE);
                }
            }
            TTS::Speak(msg, /*interrupt=*/true);
        }
        // Wandering cue on the directions query too — a moving target's
        // direction is a snapshot, and the beep says exactly that.
        if (is_wandering(d.model_slot))
            Beep(WANDER_BEEP_HZ, WANDER_BEEP_MS);
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
// ff7_name_entry_verify.py) — see ff7_addresses.h name-entry section for the
// full discovery story, including why the buffer base is 0xDD45F0 and why
// 0xDD46F8 is the char index (not a cursor, despite the Echo mod's label).
//
// GATE: GAME_MODE == 6 (name entry, new live-observed value) AND
// NAME_ENTRY_ACTIVE == 1, held for 2 consecutive polls (same streak pattern
// as MenuCursorThread's MENU_OPEN debounce — a single stale poll of either
// byte never triggers the announce logic).
//
// WHY WE NEVER PREDICT CURSOR MOVEMENT: the cursor does not wrap at the
// right grid edge — it JUMPS to the side panel (player-observed, then
// live-confirmed 2026-07-12). Entering the panel can also CHANGE the ROW
// byte (observed 1 -> 4), and leaving restores the remembered grid column.
// We only ever announce the cell/button the cursor actually landed on, so
// all of these engine quirks are self-correcting.
//
// SIDE PANEL (resolved 2026-07-12): NAME_ENTRY_PANE_FLAG (0x921ED4) is 1
// while the cursor is on the Space/Delete/Select/Default panel, and
// NAME_ENTRY_PANEL_INDEX (0xDD4574) says which button (0-3, wraps).
// Grid-letter announcements are gated on pane_flag == 0 — without that
// gate, the ROW change at panel entry would speak a phantom letter.
// Indices 0/1 (Space/Delete) proven by their effect on the name buffer;
// 2/3 (Select/Default) from on-screen order, player ear-confirmed. If
// final testing shows 2/3 swapped, fix kPanelNames below.
//
// MULTI-SCREEN HANDOFF: FF7 can chain naming screens back-to-back (Cloud →
// Barret at game start) without NAME_ENTRY_ACTIVE dropping 0 long enough to
// guarantee our 100ms poll sees it. NAME_ENTRY_CHAR_INDEX changing is the
// reliable handoff signal (0→1 captured live at the exact frame the Barret
// screen replaced Cloud's) — we re-announce the screen when it changes.
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
// letters get a "capital" prefix so A/a are distinguishable by ear — Tolk
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
    // char-index flips — two separate game writes we sample 100ms apart)
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

        // Read the live state — TWICE, requiring both samples identical.
        // The game writes these values on its own thread; a poll can land
        // mid-update (e.g. between the new char byte and the moved 0xFF
        // terminator of an append, or between the COL and ROW writes of a
        // wrap). A torn snapshot decodes to a name/cell that never existed
        // on screen, so on any mismatch we skip this poll and pick up the
        // settled state 100ms later — imperceptible, and self-correcting.
        //
        // ROW/COL are read as u8: the confirming scans only ever observed the
        // LOW byte of each DWORD slot changing, and the three high bytes are
        // unverified — if they held nonzero data, a u32 read would fail the
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
                continue;   // torn read — retry next poll
            }
            row = row1; col = col1; pane = pan1; panel = pix1;
            char_index = idx1;
        }

        // Screen (re)open: first gated poll, or the game chained straight to
        // the next character's screen (char_index change, e.g. Cloud→Barret).
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

        // Cursor movement — pane-aware. Grid letters are announced ONLY
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
                // Back on the grid — the game restores the remembered grid
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
            last_row   = row;    // keep grid state in sync silently — the
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
        // terminator (indices beyond the visible name — unverified BSS up to
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
                // cols 8-9) without needing a sighted tester — TODO.txt's
                // "fix when observed" plan depends on this record existing.
                // Only meaningful for GRID confirms: the panel's Space button
                // also appends a character while row/col still point at a
                // grid cell, which would log a false mismatch.
                if (pane == 0 && row < 7 && col < 10 &&
                    now_name.back() != kNameGrid[row][col]) {
                    char dbg[112];
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                        "[FF7Access] NAME-ENTRY GRID MISMATCH row=%u col=%u "
                        "guessed=0x%04X game-wrote=0x%04X — fix kNameGrid",
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
                // Wholesale rewrite — either the Default button restoring the
                // original name, or the first half of a chained-screen
                // handoff whose char-index flip we haven't sampled yet.
                // Defer ONE poll: if the char index changes by next poll, the
                // screen-open announce covers it; if not, it was a genuine
                // in-screen rewrite and we announce it 100ms late.
                if (!rewrite_pending) {
                    rewrite_pending = true;
                    // Deliberately do NOT update last_buf — next poll must
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
    // calling LoadLibrary (TTS::Init → Tolk.dll). The 200ms is purely for
    // loader-lock safety — it does NOT guarantee FFNx has finished initializing.
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
        // from navigation changes; 0x00DC10F0 was the sole candidate in row range 0–9.
        // Verified by ff7_config_menu_verify.py: clean 0–9 sequential tracking.
        g_config_thread = CreateThread(nullptr, 0, ConfigMenuThread, nullptr, 0, nullptr);
        if (g_config_thread) {
            Log::Write("[FF7Access] Config menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start config menu thread.");
        }

        // Save/Load menu TTS (v2.29). Cursor/phase addresses from the
        // guided scan ff7_save_menu_scan.py (2026-07-17, grid cursor
        // live-verified in-session); slot previews parsed from the save
        // files on disk (research doc §5 layout table).
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
        // cursor widgets, catalog, and price table — provenance in
        // ff7_addresses.h's SHOP block. Debug logging on state changes is
        // the live-confirm channel.
        g_shopmenu_thread = CreateThread(nullptr, 0, ShopMenuThread, nullptr, 0, nullptr);
        if (g_shopmenu_thread) {
            Log::Write("[FF7Access] Shop menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start shop menu thread.");
        }

        // G key: announce current gil (v2.30.28, FF4-scheme parity).
        g_gilkey_thread = CreateThread(nullptr, 0, GilKeyThread, nullptr, 0, nullptr);
        if (g_gilkey_thread) {
            Log::Write("[FF7Access] Gil key thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start gil key thread.");
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
        // target index 0xDC3C94 — all live-confirmed by
        // ff7_battle_menu_cursor_live_verify.py before implementation.
        g_battlemenu_thread = CreateThread(nullptr, 0, BattleMenuThread, nullptr, 0, nullptr);
        if (g_battlemenu_thread) {
            Log::Write("[FF7Access] Battle menu polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start battle menu thread.");
        }

        // Wall-bump navigation tone. Addresses resolved statically via FFNx's
        // discovery chains (ff7_wall_nav_static.py) and the detection signal
        // verified live (ff7_wall_nav_verify.py), both 2026-07-09 — see the
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
        // (ff7_field_triggers_static.py, 2026-07-13) — see the FieldNavThread
        // header comment and ff7_addresses.h SECTION 1e.
        g_fieldnav_thread = CreateThread(nullptr, 0, FieldNavThread, nullptr, 0, nullptr);
        if (g_fieldnav_thread) {
            Log::Write("[FF7Access] Field navigation (exit scan) thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start field navigation thread.");
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
            !g_statusmenu_thread && !g_shopmenu_thread && !g_gilkey_thread &&
            !g_timer_thread && !g_victory_thread &&
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
    // The 50ms poll interval is imperceptible — FF7 takes seconds to reach
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
        // Log::Init has not been called yet here either — still direct.
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
    if (g_gilkey_thread) {
        WaitForSingleObject(g_gilkey_thread, 500);
        CloseHandle(g_gilkey_thread);
        g_gilkey_thread = nullptr;
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
