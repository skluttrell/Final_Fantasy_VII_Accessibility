/*
 * config.cpp -- Implementation of config file parsing.
 *
 * Config file location: same directory as winmm.dll (the FF7 install folder).
 * File name: ffvii_accessibility.cfg
 * Format: one key=value pair per line, # comments, blank lines ignored.
 * Keys are case-insensitive. Boolean values: "true"/"1" = true, anything else = false.
 */

#include "config.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <fstream>
#include <string>
#include <algorithm>
#include <cctype>

namespace Config {

namespace {
    // The one global settings instance. Populated by Load(), read by Get().
    Settings g_settings;

    // Strips leading and trailing whitespace from a string in-place.
    void trim(std::string& s) {
        const auto not_space = [](unsigned char c) { return !std::isspace(c); };
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
        s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    }

    // Returns true if the value string represents a truthy config value.
    // Truthy: "true" (case-insensitive), "1", "yes".
    bool parse_bool(const std::string& value) {
        std::string v = value;
        std::transform(v.begin(), v.end(), v.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return (v == "true" || v == "1" || v == "yes");
    }
} // anonymous namespace

void Load()
{
    // Find the directory containing this DLL so we can locate the config file
    // next to it. GetModuleFileNameA with a NULL HMODULE would give the EXE path.
    // We need to pass our own HMODULE. We obtain it via a dummy call to
    // GetModuleHandleExA using the address of this function as an anchor —
    // this is the standard portable pattern for a DLL to find its own path.
    HMODULE hSelf = NULL;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(&Load),
        &hSelf
    );

    char dll_path[MAX_PATH] = {};
    GetModuleFileNameA(hSelf, dll_path, MAX_PATH);

    // Strip the DLL filename to get just the directory.
    // e.g. "C:\Games\FF7\winmm.dll" → "C:\Games\FF7\"
    std::string config_path(dll_path);
    const size_t last_sep = config_path.find_last_of("\\/");
    if (last_sep != std::string::npos) {
        config_path = config_path.substr(0, last_sep + 1);
    }
    config_path += "ffvii_accessibility.cfg";

    // If the config file doesn't exist, silently keep the defaults.
    std::ifstream file(config_path);
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        // Strip comments (everything from # onward).
        const size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        trim(line);
        if (line.empty()) continue;

        // Split on the first '=' to get key and value.
        const size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string key   = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);
        trim(key);
        trim(value);
        if (key.empty()) continue;

        // Lowercase the key for case-insensitive matching.
        std::transform(key.begin(), key.end(), key.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if      (key == "speak_dialog")  g_settings.speak_dialog  = parse_bool(value);
        else if (key == "speak_choices") g_settings.speak_choices = parse_bool(value);
        else if (key == "speak_battle")  g_settings.speak_battle  = parse_bool(value);
        else if (key == "speak_battle_menu") g_settings.speak_battle_menu = parse_bool(value);
        else if (key == "speak_menus")   g_settings.speak_menus   = parse_bool(value);
        else if (key == "wall_bump_tone") g_settings.wall_bump_tone = parse_bool(value);
        else if (key == "interrupt")     g_settings.interrupt      = parse_bool(value);
        else if (key == "debug_log")     g_settings.debug_log      = parse_bool(value);
        // Unknown keys are silently ignored for forward compatibility.
    }
}

const Settings& Get()
{
    return g_settings;
}

} // namespace Config
