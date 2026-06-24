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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

namespace TTS {

namespace {

    // Function pointer types matching the Tolk C API signatures.
    // These match the declarations in deps/tolk/Tolk.h.
    using Fn_Tolk_Load            = void    (WINAPI*)();
    using Fn_Tolk_IsLoaded        = bool    (WINAPI*)();
    using Fn_Tolk_Unload          = void    (WINAPI*)();
    using Fn_Tolk_TrySAPI         = void    (WINAPI*)(bool);
    using Fn_Tolk_Output          = bool    (WINAPI*)(const wchar_t*, bool);
    using Fn_Tolk_Speak           = bool    (WINAPI*)(const wchar_t*, bool);
    using Fn_Tolk_Silence         = bool    (WINAPI*)();
    using Fn_Tolk_DetectScreenReader = const wchar_t* (WINAPI*)();

    // Runtime-loaded Tolk function pointers. All start as nullptr.
    // Any function that remains nullptr is treated as unavailable.
    HMODULE            g_tolk_dll        = nullptr;
    Fn_Tolk_Load       g_Tolk_Load       = nullptr;
    Fn_Tolk_Unload     g_Tolk_Unload     = nullptr;
    Fn_Tolk_TrySAPI    g_Tolk_TrySAPI    = nullptr;
    Fn_Tolk_Speak      g_Tolk_Speak      = nullptr;
    Fn_Tolk_Silence    g_Tolk_Silence    = nullptr;

    bool g_initialized = false;

    // Helper: resolve a named export from Tolk.dll.
    // Returns nullptr (silently) if the export is absent — allowing forward
    // compatibility with older Tolk versions that may lack newer exports.
    template<typename T>
    T resolve(const char* name) {
        return reinterpret_cast<T>(GetProcAddress(g_tolk_dll, name));
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
        // OutputDebugString can be seen in a debugger if needed.
        OutputDebugStringA("[FF7Access] Tolk.dll not found — TTS disabled.\n");
        return;
    }

    // Resolve all Tolk exports we need.
    g_Tolk_Load    = resolve<Fn_Tolk_Load>   ("Tolk_Load");
    g_Tolk_Unload  = resolve<Fn_Tolk_Unload> ("Tolk_Unload");
    g_Tolk_TrySAPI = resolve<Fn_Tolk_TrySAPI>("Tolk_TrySAPI");
    g_Tolk_Speak   = resolve<Fn_Tolk_Speak>  ("Tolk_Speak");
    g_Tolk_Silence = resolve<Fn_Tolk_Silence>("Tolk_Silence");

    if (!g_Tolk_Load || !g_Tolk_Speak) {
        // Tolk.dll present but doesn't export the functions we need.
        // Possibly wrong Tolk version.
        OutputDebugStringA("[FF7Access] Tolk.dll found but missing required exports.\n");
        FreeLibrary(g_tolk_dll);
        g_tolk_dll = nullptr;
        return;
    }

    // Enable SAPI as a fallback so TTS works even without NVDA or JAWS running.
    // This ensures accessibility for users who only use Windows' built-in narrator.
    if (g_Tolk_TrySAPI) g_Tolk_TrySAPI(true);

    // Initialize Tolk — this triggers screen reader detection.
    g_Tolk_Load();
    g_initialized = true;

    OutputDebugStringA("[FF7Access] Tolk initialized successfully.\n");
}

void Speak(const wchar_t* text, bool interrupt)
{
    // No-op guard: if Tolk failed to load, return immediately rather than crashing.
    if (!g_initialized || !g_Tolk_Speak) return;
    if (!text || text[0] == L'\0') return;

    // Honor the global interrupt override from the config file.
    // If the user set interrupt=false, never interrupt ongoing speech.
    const bool do_interrupt = interrupt && Config::Get().interrupt;

    g_Tolk_Speak(text, do_interrupt);
}

void Silence()
{
    if (!g_initialized || !g_Tolk_Silence) return;
    g_Tolk_Silence();
}

void Shutdown()
{
    if (!g_initialized) return;

    if (g_Tolk_Unload) g_Tolk_Unload();
    if (g_tolk_dll)    FreeLibrary(g_tolk_dll);

    g_tolk_dll    = nullptr;
    g_initialized = false;
}

} // namespace TTS
