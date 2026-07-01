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
#include "tts.h"
#include "config.h"
#include "log.h"

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
//   0=Item  1=Magic  2=Equip  3=Status  4=Order  5=Limit  6=Config
//   7=???   8=???   (unlockable, identity TBD — skipped until confirmed)
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
        L"Config",  // 6
        nullptr,    // 7 — unlockable; identity TBD, update when seen in game
        nullptr,    // 8 — unlockable; identity TBD, update when seen in game
        L"Save",    // 9
        L"Quit",    // 10
    };
    static const uint8_t kMenuMax = 10;  // highest valid main-menu index

    uint8_t last_cursor = 0xFF;  // 0xFF = no valid cursor seen yet

    for (;;) {
        if (WaitForSingleObject(g_cursor_stop_event, 150) == WAIT_OBJECT_0)
            break;

        if (!Config::Get().speak_menus) {
            last_cursor = 0xFF;
            continue;
        }

        // Only the field-map game state can show the main menu.
        const int16_t field_id =
            *reinterpret_cast<const volatile int16_t*>(FF7Addr::FIELD_ID);
        if (field_id == 0) {
            last_cursor = 0xFF;
            continue;
        }

        const uint8_t curr =
            *reinterpret_cast<const volatile uint8_t*>(FF7Addr::MENU_CURSOR);

        if (curr == last_cursor) continue;

        // Values outside 0–kMenuMax mean the byte is being used for
        // something else (sub-menu state, battle, etc.). Reset sentinel so
        // we re-announce if we return to a valid main-menu position.
        if (curr > kMenuMax) {
            last_cursor = 0xFF;
            continue;
        }

        last_cursor = curr;

        const wchar_t* label = kMenuLabels[curr];
        if (!label) {
            // Cursor landed on an unlockable slot not yet identified.
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

        g_menu_thread = CreateThread(nullptr, 0, MenuCursorThread, nullptr, 0, nullptr);
        if (g_menu_thread) {
            Log::Write("[FF7Access] Menu cursor polling thread started.");
        } else {
            Log::Write("[FF7Access] Warning: could not start menu cursor thread.");
        }

        // If both threads failed to start, release the event now since
        // Shutdown() will find no threads to join and would still try to
        // close it. Leave it open if at least one thread is running.
        if (!g_title_thread && !g_menu_thread) {
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
