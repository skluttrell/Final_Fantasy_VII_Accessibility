// ff7_curated_line_names.h -- hand-curated spoken names for LINE
// triggers whose dev entity names carry no meaning (v2.30.97).
//
// WHY THIS TABLE EXISTS: some puzzle screens name every trigger
// literally "lineNN", so the dev-word translation can only produce
// "line" and the browser speaks an undifferentiated "line 1".."line 11".
// The defining case (play log.10, 2026-08-09): the Train Graveyard north
// screen, where the player must walk onto two specific lines to hop
// through boardable trains and rearrange the wrecks before the Sector 7
// exit path exists at all. A sighted player sees a brown train with lit
// windows among grey wrecks; the mod spoke eleven identical "line"s and
// the player circled the field for ten minutes and quit. This table is
// that glance: it substitutes a human-written name for the translated
// dev label wherever a line's spoken identity is built.
//
// SCOPE RULES (read before adding entries):
//   - Keyed by (maplist field id, owning entity id) -- the SAME identity
//     ff7_line_trigger_catalog.h uses, available at runtime from the
//     engine's line array. It inherits the same accepted staleness
//     tradeoff: during a field transition a stale array entry may pair
//     with the new field id for one keypress and simply miss (or hit a
//     same-field row).
//   - Entries are added from DECODED SCRIPT EVIDENCE only (an offline
//     dump of the field's entity scripts proving what each line does),
//     never from guesses -- the same never-guess rule as the story
//     hotspot list (v2.30.46). Cite the dump log in the entry comment.
//   - Names must fit the browser's 23-character wchar_t[24] storage
//     WITH room for a duplicate ordinal (" 2") when entries share a
//     name; keep them short and start with the OBJECT, not the action,
//     so J/L cycling groups kin by first word.
//   - Direction words ("up"/"down"/"left") are FORBIDDEN inside names:
//     journey speech composes "take <name>, down 3 seconds" and a
//     direction inside the name reads as two conflicting instructions
//     (the v2.30.67 ladder lesson).
//   - full_phrase=true suppresses the browser's behavior-catalog suffix
//     (", climb"/", scene"/", press OK") because the name already
//     states the action ("brown train, hop in"). full_phrase=false
//     keeps the suffix: "south wreck" + ", climb" composes exactly like
//     the ladder convention.
//
// CONSUMED BY LineSpokenBaseName() in proxy.cpp -- the single wrapper
// both name producers (Triggers-category build pass and
// TriggerLineSpokenName) call, so browser, walk-into announce, journey
// legs and homing all speak the same words (the one-vocabulary rule,
// v2.30.62/.96).
#pragma once
#include <cstdint>

namespace FF7CuratedLines {

struct CuratedLine {
    uint16_t field_id;
    uint8_t  entity_id;
    bool     full_phrase;   // true = name states the action; browser must
                            // not append its line-kind suffix
    const wchar_t* name;    // spoken base name (<= 23 chars incl. ordinal)
};

// Sorted by (field_id, entity_id) for binary search.
//
// -- Train Graveyard (fields 144 'mds7st1' south, 145 'mds7st2' north) --
// Script evidence: investigate/ff7_graveyard_train_dump.py, log
// graveyard_train_dump_20260809_130649.log (full disassembly of both
// fields; summary in research doc section 8, v2.30.97 entry).
//   Field 144 is a chain of climb-over-wreck LINE pairs (ground side /
//   roof side, each reqew's a cloud LADER script) plus one roof-gap jump
//   pair; entity 2 sits INSIDE the first train's interior (z=-134, where
//   the sewer drops you) and entity 3 is its outside twin.
//   Field 145 is the train-hopping puzzle. State byte V[1][164]: bit0 =
//   brown train's side (its two lines LINON-swap each hop, so exactly
//   one of entity 7/8 is enabled at a time -- ordinals never fire on
//   them), bit1 = middle passenger car (kyak01) rolled away (set by the
//   first brown-train hop), bit2 = upper train (kisya01) rolled away
//   (only fully rolls once bit1 is set; entity 9/10 likewise swap).
//   Walking onto a hop line plays the jump-in animation, teleports the
//   player through, and IDLCK batches re-lock/unlock the walkmesh -- the
//   Sector 7 exit route only exists after both trains have moved.
inline constexpr CuratedLine kCurated[] = {
    // field 144 (mds7st1): entity 2 = interior climb-out (walk-on),
    // entity 3 = outside climb-in ([OK]); pairs 4/5, 6/7, 8/9 = the
    // three climb-over wrecks along the east route, ground/roof sides
    // in south-to-north order; 10/11 = the roof-gap jump pair.
    {144,  2, false, L"first train"},
    {144,  3, false, L"first train"},
    {144,  4, false, L"south wreck"},
    {144,  5, false, L"south wreck"},
    {144,  6, false, L"middle wreck"},
    {144,  7, false, L"middle wreck"},
    {144,  8, false, L"north wreck"},
    {144,  9, false, L"north wreck"},
    {144, 10, true,  L"roof gap jump"},
    {144, 11, true,  L"roof gap jump"},
    // field 145 (mds7st2): 3/4 = climb pair over the center wreck,
    // 5/6 = climb pair over the far-left wreck (nearest the exit),
    // 7/8 = the brown boardable train (right side, the puzzle opener),
    // 9/10 = the upper boardable train, 11-14 = roof-gap jumps between
    // wreck tops (Ether barrel / Hi-Potion route).
    {145,  3, false, L"center wreck"},
    {145,  4, false, L"center wreck"},
    {145,  5, false, L"left wreck"},
    {145,  6, false, L"left wreck"},
    {145,  7, true,  L"brown train, hop in"},
    {145,  8, true,  L"brown train, hop in"},
    {145,  9, true,  L"upper train, hop in"},
    {145, 10, true,  L"upper train, hop in"},
    {145, 11, true,  L"roof gap jump"},
    {145, 12, true,  L"roof gap jump"},
    {145, 13, true,  L"roof gap jump"},
    {145, 14, true,  L"roof gap jump"},
};

inline const CuratedLine* Find(uint16_t field_id, uint8_t entity_id)
{
    size_t lo = 0, hi = sizeof(kCurated) / sizeof(kCurated[0]);
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2;
        const CuratedLine& e = kCurated[mid];
        if (e.field_id < field_id ||
            (e.field_id == field_id && e.entity_id < entity_id))
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < sizeof(kCurated) / sizeof(kCurated[0]) &&
        kCurated[lo].field_id == field_id &&
        kCurated[lo].entity_id == entity_id)
        return &kCurated[lo];
    return nullptr;
}

} // namespace FF7CuratedLines
