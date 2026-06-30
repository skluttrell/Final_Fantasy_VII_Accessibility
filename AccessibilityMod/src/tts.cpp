/*
 * tts.cpp -- Runtime loading of Tolk and screen reader output implementation.
 *
 * Why runtime loading instead of linking against Tolk.lib:
 *   - The mod must not prevent FF7 from starting if Tolk.dll is absent.
 *     Static linking would cause an import-table load failure at process start.
 *   - LoadLibrary from a known path (the FF7 folder) is safer than relying on
 *     the system search path, which varies per user.
 *   - It mirrors how our winmm proxy loads the real winmm.dll — a consistent pattern.
 */

#include "tts.h"
#include "config.h"
#include "log.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

namespace TTS {

namespace {

    // Function pointer types matching the Tolk C API signatures.
    // These match the declarations in deps/tolk/Tolk.h.
    //
    // WHY NO WINAPI (__stdcall):
    //   The dkager Tolk C API is compiled with no explicit calling convention,
    //   which defaults to __cdecl in MSVC. __cdecl means the CALLER cleans the
    //   stack after the call (compiler emits "add esp, N" after the call site).
    //   __stdcall (WINAPI) means the CALLEE cleans (emits "ret N"). Declaring
    //   a __cdecl function as __stdcall causes the compiler to omit the "add
    //   esp, N" cleanup, leaving arguments on the stack. For any function that
    //   takes parameters (Tolk_TrySAPI, Tolk_Speak), this silently corrupts ESP
    //   and the next function return jumps to garbage, producing an access
    //   violation at an unmapped address (0x5997AC69 in our crash log).
    using Fn_Tolk_Load            = void    (*)();
    using Fn_Tolk_IsLoaded        = bool    (*)();
    using Fn_Tolk_Unload          = void    (*)();
    using Fn_Tolk_TrySAPI         = void    (*)(bool);
    using Fn_Tolk_Output          = bool    (*)(const wchar_t*, bool);
    using Fn_Tolk_Speak           = bool    (*)(const wchar_t*, bool);
    using Fn_Tolk_Silence         = bool    (*)();
    using Fn_Tolk_DetectScreenReader = const wchar_t* (*)();

    // Runtime-loaded Tolk function pointers. All start as nullptr.
    // Any function that remains nullptr is treated as unavailable.
    HMODULE            g_tolk_dll        = nullptr;
    Fn_Tolk_Load             g_Tolk_Load             = nullptr;
    Fn_Tolk_Unload           g_Tolk_Unload           = nullptr;
    Fn_Tolk_TrySAPI          g_Tolk_TrySAPI          = nullptr;
    Fn_Tolk_Speak            g_Tolk_Speak            = nullptr;
    Fn_Tolk_Silence          g_Tolk_Silence          = nullptr;
    Fn_Tolk_DetectScreenReader g_Tolk_DetectScreenReader = nullptr;

    bool             g_initialized = false;
    CRITICAL_SECTION g_speak_cs;   // serializes Speak/Silence; initialized in Init()

    // Helper: resolve a named export from Tolk.dll.
    // Returns nullptr (silently) if the export is absent — allowing forward
    // compatibility with older Tolk versions that may lack newer exports.
    template<typename T>
    T resolve(const char* name) {
        return reinterpret_cast<T>(GetProcAddress(g_tolk_dll, name));
    }

// ---------------------------------------------------------------------------
// SEH-isolated Tolk call helper.
//
// MSVC C2712: __try cannot appear in a function that has C++ objects with
// destructors (including std::string). TTS::Init() uses std::string, so the
// actual SEH block lives here where no unwinding objects are in scope.
// Returns true if both calls succeeded, false if either threw an exception.
// ---------------------------------------------------------------------------
static bool tolk_init_with_seh(Fn_Tolk_TrySAPI trySAPI, Fn_Tolk_Load load)
{
    __try {
        if (trySAPI) trySAPI(true);
        load();
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // anonymous namespace

void Init()
{
    // Determine the directory containing this DLL (the FF7 install folder).
    // Tolk.dll must be in the same directory.
    HMODULE hSelf = nullptr;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(&Init),
        &hSelf
    );

    char self_path[MAX_PATH] = {};
    GetModuleFileNameA(hSelf, self_path, MAX_PATH);

    // Replace the filename portion with "Tolk.dll".
    std::string tolk_path(self_path);
    const size_t sep = tolk_path.find_last_of("\\/");
    if (sep != std::string::npos) tolk_path = tolk_path.substr(0, sep + 1);
    tolk_path += "Tolk.dll";

    g_tolk_dll = LoadLibraryA(tolk_path.c_str());
    if (!g_tolk_dll) {
        // Tolk.dll not found — TTS is unavailable but the game runs normally.
        Log::Write("[FF7Access] Tolk.dll not found — TTS disabled.");
        return;
    }

    // Resolve all Tolk exports we need.
    g_Tolk_Load             = resolve<Fn_Tolk_Load>            ("Tolk_Load");
    g_Tolk_Unload           = resolve<Fn_Tolk_Unload>          ("Tolk_Unload");
    g_Tolk_TrySAPI          = resolve<Fn_Tolk_TrySAPI>         ("Tolk_TrySAPI");
    g_Tolk_Speak            = resolve<Fn_Tolk_Speak>           ("Tolk_Speak");
    g_Tolk_Silence          = resolve<Fn_Tolk_Silence>         ("Tolk_Silence");
    g_Tolk_DetectScreenReader = resolve<Fn_Tolk_DetectScreenReader>("Tolk_DetectScreenReader");

    if (!g_Tolk_Load || !g_Tolk_Speak) {
        // Tolk.dll present but doesn't export the functions we need.
        // Possibly wrong Tolk version.
        Log::Write("[FF7Access] Tolk.dll found but missing required exports.");
        FreeLibrary(g_tolk_dll);
        g_tolk_dll = nullptr;
        return;
    }

    // Enable SAPI fallback and initialize Tolk (screen reader detection).
    // SEH lives in tolk_init_with_seh() — see comment on that function.
    // If Tolk.dll is the .NET ndarilek fork rather than the native C++ dkager
    // build, its exports are CLR managed stubs that crash when called from a
    // native thread. We catch that here so a bad Tolk.dll cannot crash the game.
    if (!tolk_init_with_seh(g_Tolk_TrySAPI, g_Tolk_Load)) {
        Log::Write("[FF7Access] Tolk call threw an exception. "
                   "Use the native C++ Tolk from dkager/tolk, "
                   "not the .NET ndarilek fork. TTS disabled.");
        FreeLibrary(g_tolk_dll);
        g_tolk_dll                = nullptr;
        g_Tolk_Load               = nullptr;
        g_Tolk_Unload             = nullptr;
        g_Tolk_TrySAPI            = nullptr;
        g_Tolk_Speak              = nullptr;
        g_Tolk_Silence            = nullptr;
        g_Tolk_DetectScreenReader = nullptr;
        return;
    }

    InitializeCriticalSection(&g_speak_cs);
    g_initialized = true;

    // Log which screen reader Tolk selected so we can confirm NVDA vs SAPI.
    if (g_Tolk_DetectScreenReader) {
        const wchar_t* reader = g_Tolk_DetectScreenReader();
        if (reader && reader[0] != L'\0') {
            // Convert the wide name to narrow ASCII for the log (screen reader
            // names are always ASCII in practice: "NVDA", "JAWS", etc.).
            char buf[128] = "[FF7Access] Screen reader detected: ";
            int off = (int)strlen(buf);
            for (int i = 0; reader[i] && off < 120; ++i)
                buf[off++] = (char)reader[i];
            buf[off] = '\0';
            Log::Write(buf);
        } else {
            Log::Write("[FF7Access] No screen reader detected — SAPI only.");
        }
    }
    Log::Write("[FF7Access] Tolk initialized successfully.");
}

void Speak(const wchar_t* text, bool interrupt)
{
    // Fast pre-check outside the lock; the real guard is repeated inside.
    if (!g_initialized || !g_Tolk_Speak) return;
    if (!text || text[0] == L'\0') return;

    const bool do_interrupt = interrupt && Config::Get().interrupt;

    // Serialize concurrent callers (game main thread via hook functions,
    // TitleCursorThread via polling). g_initialized is re-checked under the
    // lock so that a concurrent Shutdown() cannot cause a call into Tolk
    // after FreeLibrary — any caller blocked here sees g_initialized=false
    // when it acquires the lock and returns without touching g_Tolk_Speak.
    EnterCriticalSection(&g_speak_cs);
    if (g_initialized && g_Tolk_Speak)
        g_Tolk_Speak(text, do_interrupt);
    LeaveCriticalSection(&g_speak_cs);
}

void Silence()
{
    if (!g_initialized || !g_Tolk_Silence) return;

    EnterCriticalSection(&g_speak_cs);
    if (g_initialized && g_Tolk_Silence)
        g_Tolk_Silence();
    LeaveCriticalSection(&g_speak_cs);
}

void Shutdown()
{
    if (!g_initialized) return;

    // Acquire the speak lock and clear g_initialized while holding it.
    // Any Speak/Silence call that is blocked on EnterCriticalSection will see
    // g_initialized=false when it acquires the lock and return without calling
    // into Tolk. Any call already inside Tolk_Speak finishes before we proceed.
    // By the time this runs, Proxy::Shutdown() has already joined
    // TitleCursorThread, so no background thread is calling Speak() anymore.
    EnterCriticalSection(&g_speak_cs);
    g_initialized = false;
    LeaveCriticalSection(&g_speak_cs);

    if (g_Tolk_Unload) g_Tolk_Unload();
    if (g_tolk_dll)    FreeLibrary(g_tolk_dll);
    g_tolk_dll = nullptr;

    DeleteCriticalSection(&g_speak_cs);
}

} // namespace TTS
