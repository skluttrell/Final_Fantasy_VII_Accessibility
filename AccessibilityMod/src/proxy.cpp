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
#include <string>
#include <cstring>   // memchr/memcmp/memcpy in the kernel2 section scanner

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
static HANDLE g_battle_thread     = nullptr;
static HANDLE g_battlemenu_thread = nullptr;
static HANDLE g_wallbump_thread   = nullptr;
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
// CURSOR INDEX → OPTION NAME:
//   0=Item  1=Magic  2=Equip  3=Status  4=Order  5=Limit
//   6=???   (unlockable, identity TBD — skipped until confirmed)
//   7=Config
//   8=???   (unlockable, identity TBD — skipped until confirmed)
//   9=Save  10=Quit
// Confirmed via ff7_menu_cursor_poll.py (2026-07-01): static BSS address in
// the 0xCC region, verified clean cursor tracking with correct index range.
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
        L"Item",    // 0
        L"Magic",   // 1
        L"Equip",   // 2
        L"Status",  // 3
        L"Order",   // 4
        L"Limit",   // 5
        nullptr,    // 6 — unlockable; identity TBD, update when seen in game
        L"Config",  // 7
        nullptr,    // 8 — unlockable; identity TBD, update when seen in game
        L"Save",    // 9
        L"Quit",    // 10
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

        char dbg[80];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] MENU cursor=%u (%ls)", curr, label);
        Log::Write(dbg);
        TTS::Speak(label, /*interrupt=*/true);
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
};
static Kernel2Sections g_k2 = { nullptr, nullptr, nullptr, nullptr };

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
    const size_t len_magic  = EncodeSignature("Cure|Cure2|",        sig_magic,  sizeof(sig_magic));
    const size_t len_item   = EncodeSignature("Potion|Hi-Potion|",  sig_item,   sizeof(sig_item));
    const size_t len_weapon = EncodeSignature("Buster Sword|",      sig_weapon, sizeof(sig_weapon));
    // Command-name section head: entries 0,1,... are "Attack","Magic",...
    // stored back-to-back like every other kernel2 text section.
    const size_t len_command = EncodeSignature("Attack|Magic|",     sig_command, sizeof(sig_command));

    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t addr = 0x00400000;
    while (addr < 0x7FFF0000 &&
           (!g_k2.magic || !g_k2.item || !g_k2.weapon || !g_k2.command)) {
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
        }
        addr = base + mbi.RegionSize;
    }

    char dbg[192];
    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
        "[FF7Access] kernel2 section scan: magic=%p item=%p weapon=%p command=%p",
        g_k2.magic, g_k2.item, g_k2.weapon, g_k2.command);
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
    const uint8_t branch = *reinterpret_cast<const uint8_t*>(
        FF7Addr::BATTLE_DISPATCH_BYTE_TABLE + cmd);
    switch (branch) {
    case 0:   // section 0 (unused cmd 0x00)
    case 1:   // cmd 0x02 Magic: spell names are magic entries 0-55
        return SectionEntryText(g_k2.magic, idx, out);
    case 2:   // cmd 0x03 Summon.  The game uses the separate summon-attack-
              // name file for idx<16, but its heap copy has no locatable
              // signature; magic entries 56-71 hold the identical summon
              // names ('Choco/Mog'…'Knights of Round', verified live), so
              // use those.  idx>=16 falls through to the magic file as the
              // game itself does.
        if (idx < 16)
            return SectionEntryText(g_k2.magic, idx + 56, out);
        return SectionEntryText(g_k2.magic, idx, out);
    case 3:   // cmd 0x04 Item
    case 5:   // cmd 0x08 (item variant)
        if (idx < 128)
            return SectionEntryText(g_k2.item, idx, out);
        if (idx < 256)   // thrown weapons share the item id space at 128+
            return SectionEntryText(g_k2.weapon, idx - 128, out);
        return false;    // armor/accessory ids never flash in battle
    case 4: { // cmd 0x07: the game composes this name into a fixed buffer
        const char* buf = reinterpret_cast<const char*>(0x00DC3640);
        if (static_cast<uint8_t>(buf[0]) == 0xFF || buf[0] == 0)
            return false;
        out = FF7Text::Decode(buf);
        return !out.empty();
    }
    case 6:   // cmd 0x0D Enemy Skill: magic entries 72-95 ('Frog Song'…)
        return SectionEntryText(g_k2.magic, idx + 72, out);
    case 7:   // cmd 0x14 Limit Break: magic entries 128+ ('Braver'…)
        if (idx == 0x7F)   // the game's '????' sentinel for unnamed limits
            return false;
        return SectionEntryText(g_k2.magic, idx + 128, out);
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

static DWORD WINAPI BattleActionThread(LPVOID /*unused*/)
{
    // Default English party names indexed by character ID (0=Cloud … 8=Cid).
    // Used to name party slot 0 (the current leader) in TTS output.
    static const wchar_t* const kCharNames[] = {
        L"Cloud", L"Barret", L"Tifa", L"Aerith", L"Red XIII",
        L"Yuffie", L"Cait Sith", L"Vincent", L"Cid"
    };
    static const uint32_t kCharNameCount =
        static_cast<uint32_t>(sizeof(kCharNames) / sizeof(kCharNames[0]));

    uint8_t last_actor_id = 0xFF;   // 0xFF = sentinel; announce on next valid actor change

    // Rate limiter for kernel2 section re-scans while sections are missing.
    ULONGLONG next_scan_tick = 0;

    // Pending flash-message wait state (see ANNOUNCE TIMING above).
    bool      pending           = false;
    uint8_t   pending_cmd       = 0;      // model-state commandID of the pending turn
    uint32_t  pending_s0_cmd    = 0;      // struct snapshot at turn start
    uint32_t  pending_s0_idx    = 0;
    ULONGLONG pending_deadline  = 0;
    wchar_t   pending_actor[32] = {};

    // Announce helper: "[actor], [name-or-generic]".  Written as a lambda so
    // both the immediate path and the deferred flash path share it.
    const auto announce = [](const wchar_t* actor_label, uint8_t command_id,
                             const std::wstring* exact_name) {
        wchar_t generic_buf[32];
        const wchar_t* action = exact_name ? exact_name->c_str()
            : GenericActionLabel(command_id, generic_buf, _countof(generic_buf));
        wchar_t msg[128] = {};
        _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"%ls, %ls", actor_label, action);
        char dbg[160];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] BATTLE cmd=0x%02X %ls => %ls",
            static_cast<unsigned>(command_id),
            exact_name ? L"named" : L"generic", msg);
        Log::Write(dbg);
        TTS::Speak(msg, /*interrupt=*/true);
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

        // Build the actor label.  Slot 0 = party leader (name from savemap);
        // slots 1–2 = "ally N"; slots 4–9 = "enemy".
        wchar_t actor_label[32] = {};
        if (is_party) {
            if (actor_id == 0) {
                const uint8_t leader_id =
                    *reinterpret_cast<const volatile uint8_t*>(FF7Addr::PARTY_LEADER);
                const wchar_t* cname =
                    (leader_id < kCharNameCount) ? kCharNames[leader_id] : L"ally";
                _snwprintf_s(actor_label, _countof(actor_label), _TRUNCATE, L"%ls", cname);
            } else {
                _snwprintf_s(actor_label, _countof(actor_label), _TRUNCATE,
                             L"ally %u", static_cast<unsigned>(actor_id + 1u));
            }
        } else {
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
// BattleActionThread uses). Slot 0 = the party leader's real name from
// the savemap; other slots get positional labels ("ally 2", "enemy 1").
// Naming every actor (party member 2/3 names, real enemy names from
// scene.bin) is a known follow-up, not v2.9.
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
    if (id != 0 && SectionEntryText(g_k2.command, static_cast<uint32_t>(id) - 1, out))
        return;
    wchar_t generic_buf[32];
    out = GenericActionLabel(id, generic_buf, _countof(generic_buf));
}

static DWORD WINAPI BattleMenuThread(LPVOID /*unused*/)
{
    // Same default English names as BattleActionThread (slot 0 = leader).
    static const wchar_t* const kCharNames[] = {
        L"Cloud", L"Barret", L"Tifa", L"Aerith", L"Red XIII",
        L"Yuffie", L"Cait Sith", L"Vincent", L"Cid"
    };
    static const uint32_t kCharNameCount =
        static_cast<uint32_t>(sizeof(kCharNames) / sizeof(kCharNames[0]));

    uint16_t  last_state    = FF7Addr::BMENU_STATE_CLOSED;
    uint32_t  last_cmd_key  = 0xFFFFFFFF;  // slot<<16 | col<<8 | row
    uint32_t  last_list_key = 0xFFFFFFFF;  // state<<16 | index
    bool      targeting     = false;
    uint8_t   last_target   = 0xFF;
    ULONGLONG next_scan_tick = 0;

    const auto reset_all = [&]() {
        last_state    = FF7Addr::BMENU_STATE_CLOSED;
        last_cmd_key  = 0xFFFFFFFF;
        last_list_key = 0xFFFFFFFF;
        targeting     = false;
        last_target   = 0xFF;
    };

    // Label an actor slot for target announcements (see header comment).
    const auto target_label = [&](uint8_t slot, wchar_t* buf, size_t buf_count) {
        if (slot == 0) {
            const uint8_t leader_id =
                *reinterpret_cast<const volatile uint8_t*>(FF7Addr::PARTY_LEADER);
            const wchar_t* cname =
                (leader_id < kCharNameCount) ? kCharNames[leader_id] : L"ally 1";
            _snwprintf_s(buf, buf_count, _TRUNCATE, L"%ls", cname);
        } else if (slot <= 2) {
            _snwprintf_s(buf, buf_count, _TRUNCATE, L"ally %u",
                         static_cast<unsigned>(slot + 1u));
        } else if (slot >= 4 && slot <= 9) {
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
                CommandMenuName(cmd_id, name);
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
            uint32_t woff, table;
            if (state == FF7Addr::BMENU_STATE_MAGIC_LIST) {
                woff  = FF7Addr::BWIDGET_MAGIC_LIST;
                table = FF7Addr::BATTLE_CHAR_BLOCK
                      + slot * FF7Addr::BATTLE_CHAR_SLOT_STRIDE
                      + FF7Addr::BCHAR_OFF_MAGIC_LIST;
            } else if (state == FF7Addr::BMENU_STATE_SUMMON_LIST) {
                woff  = FF7Addr::BWIDGET_SUMMON_LIST;
                table = FF7Addr::BATTLE_CHAR_BLOCK
                      + slot * FF7Addr::BATTLE_CHAR_SLOT_STRIDE
                      + FF7Addr::BCHAR_OFF_SUMMON_LIST;
            } else {
                woff  = FF7Addr::BWIDGET_ITEM_LIST;
                table = FF7Addr::BATTLE_ITEM_LIST_TABLE;
            }
            const uint32_t widget = FF7Addr::BATTLE_WIDGET_BASE
                + slot * FF7Addr::BATTLE_WIDGET_SLOT_STRIDE + woff;
            const uint32_t w0 =
                *reinterpret_cast<const volatile uint32_t*>(widget + FF7Addr::BWIDGET_OFF_HORIZ);
            const uint32_t w4 =
                *reinterpret_cast<const volatile uint32_t*>(widget + FF7Addr::BWIDGET_OFF_VERT);
            const uint32_t scroll =
                *reinterpret_cast<const volatile uint32_t*>(widget + FF7Addr::BWIDGET_OFF_SCROLL);
            const uint32_t index = w0 + w4 + scroll;
            // Battle lists are small (magic <= 96 entries, inventory shows
            // <= 320); a huge sum means the widget is mid-initialization.
            if (index > 0x200)
                continue;

            const uint32_t key = (static_cast<uint32_t>(state) << 16) | index;
            if (key == last_list_key)
                goto targeting_check;
            last_list_key = key;

            {
                const uint16_t id16 = *reinterpret_cast<const volatile uint16_t*>(
                    table + index * 6);
                if (id16 == 0xFFFF || id16 == 0)
                    continue;   // empty/padding row — silent (see cmd 0xFF note)

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
                    (branch == 3 || branch == 5) ? id16 : (id16 & 0xFFu);

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
                char dbg[144];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] BMENU list state=%u idx=%u id=0x%04X cmd=0x%02X => %ls",
                    static_cast<unsigned>(state), index,
                    static_cast<unsigned>(id16),
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
                wchar_t label[32];
                target_label(target, label, _countof(label));
                char dbg[96];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "[FF7Access] BMENU target=%u => %ls",
                    static_cast<unsigned>(target), label);
                Log::Write(dbg);
                TTS::Speak(label, /*interrupt=*/true);
            }
        }
    }

    return 0;
}

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
            continue;
        }

        // Gate 6: no dialog/choice window active within the last 250ms.
        // Unsigned subtraction handles GetTickCount()'s 49.7-day wrap.
        const DWORD now = GetTickCount();
        if (now - Hooks::LastDialogActivityTick() < kDialogQuietMs) {
            have_last = false;
            blocked_streak = 0;
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
            continue;
        }

        // model_pos: 3 consecutive int32 (x, y, z) at +0x0C.
        const int32_t* pos = reinterpret_cast<const int32_t*>(
            elem + FF7Addr::FIELD_EVENT_MODEL_POS);
        const int32_t x = pos[0], y = pos[1], z = pos[2];

        // "Moved" on the very first valid sample: with no previous position
        // to compare, assume motion so the streak stays at zero rather than
        // beeping off one stale coordinate.
        const bool moved = !have_last || x != last_x || y != last_y || z != last_z;
        last_x = x; last_y = y; last_z = z;
        have_last = true;

        if (dir_held && !moved) {
            blocked_streak++;
        } else {
            blocked_streak = 0;
        }

        if (blocked_streak >= kConsecBlocked &&
            now - last_beep_tick >= kBeepPeriodMs) {
            last_beep_tick = now;
            // One-time log per contact episode would require more state; log
            // nothing here — at 3+ beeps/second even debug logging would spam.
            Beep(kBeepFreqHz, kBeepDurMs);
        }
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
            !g_battle_thread && !g_battlemenu_thread &&
            !g_wallbump_thread && !g_nameentry_thread) {
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
    if (g_battle_thread) {
        WaitForSingleObject(g_battle_thread, 500);
        CloseHandle(g_battle_thread);
        g_battle_thread = nullptr;
    }
    if (g_battlemenu_thread) {
        WaitForSingleObject(g_battlemenu_thread, 500);
        CloseHandle(g_battlemenu_thread);
        g_battlemenu_thread = nullptr;
    }
    if (g_wallbump_thread) {
        WaitForSingleObject(g_wallbump_thread, 500);
        CloseHandle(g_wallbump_thread);
        g_wallbump_thread = nullptr;
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
