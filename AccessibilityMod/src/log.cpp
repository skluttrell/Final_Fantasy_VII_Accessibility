/*
 * log.cpp -- Debug log implementation: timestamped file output + OutputDebugStringA.
 *
 * WHY ALWAYS CALL OutputDebugStringA:
 *   Developers use DebugView to watch real-time output. File logging is for
 *   end-user bug reports (where DebugView is not an option). Both paths should
 *   work simultaneously so a developer can use either channel without reconfiguring.
 *
 * WHY OVERWRITE (NOT APPEND) THE LOG FILE:
 *   Each game session produces a fresh log. Appending would accumulate entries
 *   across many sessions, making the file large and hard for a user to send.
 *   The most recent run is always what matters for a bug report, so truncating
 *   at startup is the right default.
 *
 * WHY CRITICAL_SECTION:
 *   During the hook installation phase, the background thread (proxy.cpp) and the
 *   game's main thread could theoretically both reach Log::Write() simultaneously:
 *   the background thread writes init messages, and if hooks installed faster than
 *   expected the game thread might call hook_message before the background thread
 *   exits. A CRITICAL_SECTION serializes those accesses safely without the overhead
 *   of a kernel mutex (it spins briefly before blocking, ideal for low-contention).
 */

#include "log.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#include <cstring>

namespace Log {

namespace {

    // Log file handle and synchronization.
    static FILE*            g_file = nullptr;
    static CRITICAL_SECTION g_cs;
    static bool             g_cs_init = false;

    // ---------------------------------------------------------------------------
    // get_log_path: Determine the full path for ffvii_accessibility.log.
    //
    // Uses the same pattern as Config::Load() and TTS::Init(): find our own
    // DLL path by passing the address of a function inside this DLL to
    // GetModuleHandleExA. This is the portable way for a DLL to find itself —
    // GetModuleFileNameA(NULL) would give the EXE path, not ours.
    // ---------------------------------------------------------------------------
    static bool get_log_path(char* out, DWORD size)
    {
        HMODULE hSelf = nullptr;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&get_log_path),
            &hSelf
        );
        if (!hSelf) return false;

        char dll_path[MAX_PATH] = {};
        if (!GetModuleFileNameA(hSelf, dll_path, MAX_PATH)) return false;

        // Strip the DLL filename to get just the directory.
        // e.g. "C:\Games\FF7\version.dll" → "C:\Games\FF7\"
        const char* last_sep = nullptr;
        for (const char* p = dll_path; *p; ++p) {
            if (*p == '\\' || *p == '/') last_sep = p;
        }
        if (!last_sep) return false;

        // Copy directory + log filename into out.
        const DWORD dir_len = static_cast<DWORD>(last_sep - dll_path + 1);
        const char* log_name = "ffvii_accessibility.log";
        const DWORD name_len = static_cast<DWORD>(strlen(log_name));
        if (dir_len + name_len + 1 > size) return false;

        memcpy(out, dll_path, dir_len);
        memcpy(out + dir_len, log_name, name_len + 1); // +1 for null terminator
        return true;
    }

} // anonymous namespace

void Init(bool enabled)
{
    // Initialize the CRITICAL_SECTION first so Write() is always safe.
    if (!g_cs_init) {
        InitializeCriticalSection(&g_cs);
        g_cs_init = true;
    }

    if (!enabled) return; // DebugView output still works via Write().

    char log_path[MAX_PATH] = {};
    if (!get_log_path(log_path, MAX_PATH)) {
        OutputDebugStringA("[FF7Access] Log::Init: could not determine log path.\n");
        return;
    }

    // fopen_s with "w" creates or truncates — each run starts with a clean log.
    errno_t err = fopen_s(&g_file, log_path, "w");
    if (err != 0 || !g_file) {
        OutputDebugStringA("[FF7Access] Log::Init: could not open log file for writing.\n");
        g_file = nullptr;
        return;
    }

    // Write a header so the log file has clear session boundaries.
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_file,
        "# FF7 Accessibility Mod — debug log\n"
        "# Session started: %04u-%02u-%02u %02u:%02u:%02u\n"
        "# To disable this log, set debug_log = false in ffvii_accessibility.cfg\n"
        "#\n",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    fflush(g_file);
}

void Write(const char* msg)
{
    if (!msg) return;

    // --- OutputDebugStringA path (always runs) ---
    //
    // We need to append \n to the message. OutputDebugStringA does not add one,
    // and DebugView expects one to terminate each line.
    // Build "[FF7Access] msg\n" if msg doesn't already have [FF7Access], or just
    // "msg\n" if it does. Since all callers already include [FF7Access], just append.
    {
        // Use a small stack buffer for the common case; fall back to a heap alloc
        // only for pathologically long messages (shouldn't occur in practice).
        const size_t len = strlen(msg);
        if (len < 1020) {
            char buf[1024];
            memcpy(buf, msg, len);
            buf[len]     = '\n';
            buf[len + 1] = '\0';
            OutputDebugStringA(buf);
        } else {
            OutputDebugStringA(msg);
            OutputDebugStringA("\n");
        }
    }

    // --- File path (only when debug_log = true and file opened successfully) ---
    if (!g_file) return;

    // Format a timestamp: [HH:MM:SS.mmm]
    SYSTEMTIME st;
    GetLocalTime(&st);

    // Acquire the lock before touching the file.
    if (g_cs_init) EnterCriticalSection(&g_cs);

    if (g_file) { // Re-check under the lock (Shutdown may have closed it).
        fprintf(g_file, "[%02u:%02u:%02u.%03u] %s\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            msg);
        // Flush after every line so a crash doesn't lose the last messages —
        // exactly the case where the log is most useful.
        fflush(g_file);
    }

    if (g_cs_init) LeaveCriticalSection(&g_cs);
}

void Shutdown()
{
    if (g_cs_init) EnterCriticalSection(&g_cs);

    if (g_file) {
        fputs("# Session ended.\n", g_file);
        fclose(g_file);
        g_file = nullptr;
    }

    if (g_cs_init) {
        LeaveCriticalSection(&g_cs);
        DeleteCriticalSection(&g_cs);
        g_cs_init = false;
    }
}

} // namespace Log
