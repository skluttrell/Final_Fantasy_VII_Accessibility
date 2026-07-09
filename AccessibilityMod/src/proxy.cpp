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
 *   TitleCursorThread and MenuCursorThread both run until Proxy::Shutdown()
 *   signals g_cursor_stop_event (a shared manual-reset event). Each thread
 *   uses WaitForSingleObject(g_cursor_stop_event, 150) as its sleep; one
 *   SetEvent() wakes both within 150ms on clean unload.
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

// Shared manual-reset stop event for TitleCursorThread and MenuCursorThread.
// Both threads block on WaitForSingleObject(g_cursor_stop_event, 150).
// One SetEvent() in Proxy::Shutdown() wakes both simultaneously.
// Written in InitThread before either CreateThread call; read in Shutdown().
// No lock needed: Shutdown() runs after InitThread exits (happens-before on
// the global state the game loop observes when both threads are live).
static HANDLE g_cursor_stop_event = nullptr;
static HANDLE g_title_thread      = nullptr;
static HANDLE g_menu_thread       = nullptr;
static HANDLE g_config_thread     = nullptr;
static HANDLE g_battle_thread     = nullptr;
static HANDLE g_wallbump_thread   = nullptr;

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
// Battle action polling thread.
//
// Polls g_active_actor_id and the battle model state arrays to detect and
// announce battle actions via TTS.
//
// WHY POLLING (not a function hook):
//   FFNx trampolines both display_battle_action_text_42782A (0x42782A) and
//   its inner wrapper sub_6D71FA (0x6D71FA) by overwriting their first 5
//   bytes with a relative JMP to FFNx's own handlers.  Hooking at those
//   entry points would intercept FFNx, not the original game, and would
//   require trampoline setup to preserve FFNx's behaviour.  Polling the
//   model state arrays is simpler and equally reliable: it reads the same
//   data the hook would read, with no patching required.
//
// ACTOR VALIDITY:
//   Party slots 0–2; enemy slots 4–9.  Slot 3 never appears.
//   g_active_actor_id initialises to 0 (Cloud's party slot) at process start
//   and is never reset between battles.  The commandID==0 check is the only
//   reliable "not in battle" signal: the large model state array is zero-
//   initialised at startup and retains the last commandID after a battle ends,
//   so commandID==0 only fires (a) at process start and (b) when the model
//   state is genuinely idle.
//
//   From empirical testing across 5 battles: commandID stays non-zero after
//   a battle ends (the model structs are not cleared between battles).
//   Between-battle silence relies on actor_id not changing — it stays at the
//   last-acting slot until the next battle's first action updates it.  This
//   means the first action of a new battle (which changes actor_id) is always
//   announced.  The edge case where a new battle's first actor matches the
//   previous battle's last actor is accepted; it will miss that one action.
//
// ACTION NAME LOOKUP:
//   get_kernel_text(8, actionIdx, 8) returns a pointer to an FF7-encoded
//   string from kernel2 section 8 (action/ability names).  Kernel2 is loaded
//   at game start and never modified, so calling this from a background thread
//   is safe — it is effectively a read-only table lookup.
//
// CALLING CONVENTION:
//   Declared __cdecl: sub_6D71FA (which calls get_kernel_text) ends with a
//   plain RET (not RETN n), meaning it is __cdecl and does not clean the
//   stack itself.  get_kernel_text is therefore also __cdecl.
//
// Gated by Config::Get().speak_battle.
// ---------------------------------------------------------------------------

static DWORD WINAPI BattleActionThread(LPVOID /*unused*/)
{
    // get_kernel_text is at FF7Addr::GET_KERNEL_TEXT (0x016E4E3C) per the
    // in-memory scan of sub_6D71FA, but that address is NOT a valid callable
    // target: it is FFNx's trampoline heap, which crashes when called from a
    // foreign thread (exception 0xC0000005 at that address, confirmed in testing).
    // FFNx patches more than 5 bytes at sub_6D71FA, so the CALL we saw at
    // offset +5 belongs to FFNx's code, not original FF7 code.
    // TODO: find the real get_kernel_text via ff7_data.h's chain:
    //   get_kernel_text = get_relative_call(draw_status_limit_level_stats, 0x10C)
    // Until then, commandID-based labels are used as the action description.

    // Default English party names indexed by character ID (0=Cloud … 8=Cid).
    // Used to name party slot 0 (the current leader) in TTS output.
    static const wchar_t* const kCharNames[] = {
        L"Cloud", L"Barret", L"Tifa", L"Aerith", L"Red XIII",
        L"Yuffie", L"Cait Sith", L"Vincent", L"Cid"
    };
    static const uint32_t kCharNameCount =
        static_cast<uint32_t>(sizeof(kCharNames) / sizeof(kCharNames[0]));

    uint8_t  last_actor_id = 0xFF;  // 0xFF = sentinel; announce on next valid actor change

    for (;;) {
        // Sleep 50ms, or wake immediately if Proxy::Shutdown() signals the event.
        if (WaitForSingleObject(g_cursor_stop_event, 50) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_battle) {
            last_actor_id = 0xFF;
            continue;
        }

        const uint8_t actor_id =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::G_ACTIVE_ACTOR_ID);

        // Classify the actor.  Slots 0–2 = party, 4–9 = enemy.  Slot 3 is
        // unused; any value outside 0–9 indicates the battle module is not
        // active (values come from BSS zero-init or unrelated writes).
        const bool is_party = (actor_id <= 2);
        const bool is_enemy = (actor_id >= 4 && actor_id <= 9);
        if (!is_party && !is_enemy) {
            last_actor_id = 0xFF;
            continue;
        }

        // Read commandID from the large battle model state array.
        // commandID == 0 means the slot is idle (not performing an action).
        // This fires at process start (BSS = 0) and whenever the battle module
        // clears the struct.  It is the primary gate against announcing during
        // field gameplay and at game startup.
        const uint8_t command_id = *reinterpret_cast<const volatile uint8_t*>(
            FF7Addr::G_BATTLE_MODEL_STATE
            + static_cast<uint32_t>(actor_id) * FF7Addr::BATTLE_MODEL_STATE_STRIDE
            + FF7Addr::BATTLE_COMMAND_ID_OFFSET);

        if (command_id == 0) {
            last_actor_id = 0xFF;
            continue;
        }

        // A real battle action is in flight.  Announce only when the active actor
        // slot changes — each new actor change signals a new turn beginning.
        // Between battles, actor_id stays constant (never reset), so the
        // triple stays the same and no announce fires until the next battle
        // changes which slot is acting.
        if (actor_id == last_actor_id) continue;
        last_actor_id = actor_id;

        // Map commandID to a human-readable action label.
        // These are the command menu IDs observed in battle testing (2026-07-05):
        //   0x01 = Attack (party standard attack)
        //   0x14 = Limit Break (party limit break)
        //   0x20 = enemy AI attack (all enemy actions use this opcode)
        // Other values (Magic=0x02, Item=0x04, Steal=0x06, etc.) are named
        // generically until confirmed.  A kernel2 lookup via get_kernel_text
        // would give exact ability names, but that requires finding the real
        // get_kernel_text address first (see TODO above).
        const wchar_t* action_label;
        switch (command_id) {
        case 0x01: action_label = L"Attack";     break;
        case 0x02: action_label = L"Magic";      break;
        case 0x04: action_label = L"Item";       break;
        case 0x06: action_label = L"Steal";      break;
        case 0x14: action_label = L"Limit Break"; break;
        case 0x20: action_label = L"attacks";    break;
        default: {
            // Unknown command: report the numeric value so nothing is silenced.
            static wchar_t unknown_buf[32];
            _snwprintf_s(unknown_buf, _countof(unknown_buf), _TRUNCATE,
                         L"command %u", static_cast<unsigned>(command_id));
            action_label = unknown_buf;
            break;
        }
        }
        const std::wstring action_name = action_label;

        // Build the actor label.
        // Slot 0 = party leader: read PARTY_LEADER for the character ID → name.
        // Slots 1–2 = "ally 2" / "ally 3".
        // Slots 4–9 = "enemy".
        wchar_t actor_label[32] = {};
        if (is_party) {
            if (actor_id == 0) {
                const uint8_t leader_id =
                    *reinterpret_cast<const volatile uint8_t*>(FF7Addr::PARTY_LEADER);
                const wchar_t* cname =
                    (leader_id < kCharNameCount) ? kCharNames[leader_id] : L"ally";
                _snwprintf_s(actor_label, _countof(actor_label), _TRUNCATE,
                             L"%ls", cname);
            } else {
                _snwprintf_s(actor_label, _countof(actor_label), _TRUNCATE,
                             L"ally %u", static_cast<unsigned>(actor_id + 1u));
            }
        } else {
            wcscpy_s(actor_label, L"enemy");
        }

        // Compose: "[actor label], [action name]"
        wchar_t announce[128] = {};
        _snwprintf_s(announce, _countof(announce), _TRUNCATE,
                     L"%ls, %ls", actor_label, action_name.c_str());

        char dbg[128];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "[FF7Access] BATTLE actor=%u cmd=0x%02X => %ls",
            static_cast<unsigned>(actor_id),
            static_cast<unsigned>(command_id),
            announce);
        Log::Write(dbg);
        TTS::Speak(announce, /*interrupt=*/true);
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

        // Battle action TTS. Polls g_active_actor_id + commandID + actionIdx;
        // calls get_kernel_text(8, actionIdx, 8) in-process to name the action.
        // Confirmed addresses: G_ACTIVE_ACTOR_ID=0xBE1170, G_BATTLE_MODEL_STATE=0xBE1178,
        // G_SMALL_BATTLE_MODEL_STATE=0xBF23B8, GET_KERNEL_TEXT=0x016E4E3C
        // (ff7_battle_action_scan.py, 2026-07-05).
        g_battle_thread = CreateThread(nullptr, 0, BattleActionThread, nullptr, 0, nullptr);
        if (g_battle_thread) {
            Log::Write("[FF7Access] Battle action polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start battle action thread.");
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

        if (!g_title_thread && !g_menu_thread && !g_config_thread &&
            !g_battle_thread && !g_wallbump_thread) {
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
    if (g_wallbump_thread) {
        WaitForSingleObject(g_wallbump_thread, 500);
        CloseHandle(g_wallbump_thread);
        g_wallbump_thread = nullptr;
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
