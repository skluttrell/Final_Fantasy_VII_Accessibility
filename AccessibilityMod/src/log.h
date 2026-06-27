/*
 * log.h -- Debug logging for the FF7 Accessibility Mod.
 *
 * All [FF7Access] diagnostic messages route through Log::Write(). When the
 * user sets "debug_log = true" in ffvii_accessibility.cfg, messages are also
 * written to ffvii_accessibility.log in the FF7 install folder.
 *
 * File logging is OFF by default so normal users see no overhead. When a user
 * reports a bug, they enable debug_log, reproduce the issue, and send the log.
 *
 * USAGE:
 *   Log::Write("[FF7Access] Something happened.");  // no trailing newline
 *
 * OutputDebugStringA is ALWAYS called so DebugView still works for developers
 * regardless of whether file logging is enabled.
 *
 * THREAD SAFETY: Log::Write is safe to call from any thread after Init()
 * returns. It is also safe to call before Init() — messages route to
 * OutputDebugStringA only.
 */

#pragma once

namespace Log {

/*
 * Init: Open (or create/truncate) ffvii_accessibility.log in the same
 * directory as this DLL. Must be called after Config::Load() — that is where
 * the enabled flag comes from. Safe to call from a background thread.
 *
 * If enabled is false, Init still succeeds (no file is opened) and Write()
 * routes messages only to OutputDebugStringA.
 */
void Init(bool enabled);

/*
 * Write: Emit a single log message.
 *
 * Always calls OutputDebugStringA("[FF7Access] ... \n") so messages are
 * visible in DebugView regardless of debug_log setting.
 *
 * If Init(true) was called, also writes a timestamped line to the log file:
 *     [HH:MM:SS.mmm] msg
 *
 * msg must NOT include a trailing newline — Write() appends one.
 * Thread-safe.
 */
void Write(const char* msg);

/*
 * Shutdown: Flush and close the log file.
 * Called from DllMain on DLL_PROCESS_DETACH. Safe to call even if Init()
 * was never called or file logging was disabled.
 */
void Shutdown();

} // namespace Log
