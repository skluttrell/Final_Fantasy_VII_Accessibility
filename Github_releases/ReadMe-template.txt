FINAL FANTASY VII Accessibility Mod
v.[version number]

Purpose:

Adds screen reader output, pathfinding, sound queues and other accessibility aides to FINAL FANTASY VII.

Known Issues:

* Not all dialog boxes chime when they require the user to press a button to continue.
*Long character dialog is broken into blocks by the game and spread over 2 or more confirmation events. Sometimes this dialog is spoken in its entirety in one go by the screen reader leaving silent confirmation events to be confirmed through.
* Pathfinding doesn't always give the user a clear path to the target, notably in cramped areas like the 7th Heaven hideout.
* Battle announcements are sometimes slow. This is because an artificial delay is introduced to limit speech clutter or events talking over one another. This may need further refinement.
* the P.H.S. menu is not hooked in due to not being available in the story progression at the time of this release.
* The controls submenu in the config menu is not hooked in and may change the control scheme if accessed.
* Journeys cannot see story locks. A route may point at a door the story has not opened yet; when that happens the mod says "the next exit is not available here yet" and the journey continues once the door works.
* Journeys do not cross the world map yet.

New in this version:

* This is a TEST BUILD: diagnostic logging is on by default. The mod writes ffvii_accessibility.log in your FF7 folder each session. If anything goes wrong, please attach that file to your bug report. To turn logging off, press F8 in game and change the Debug log setting.
* Fixed: the Magic, Materia, Equip and Limit menus went silent for the rest of the session after your first battle. All menus now announce correctly after battles, and opening the menu quickly after a battle no longer skips its announcements.
* Journeys to a save point now guide you all the way to the save point itself. Arriving in the save room gives directions to the pad, including any ladders between levels, and "Journey complete" is only spoken when you actually reach the save point.
* Every automatic journey announcement now speaks the real walking route, like "up 4 seconds, then left 2 seconds", with no extra key press needed. The straight line hint is only used when a route cannot be computed.
* When you are very close to a destination, directions now tell you which way to face, like "very close to the up and left".

Install:

* Purchase and install FINAL FANTASY VII from Steam
https://store.steampowered.com/app/3837340/FINAL_FANTASY_VII/
If you have the 2013 version already, that one works with this mod along with the 2026 edition.
Note: this mod does not cover the Remakes or any other edition other than the original.
* Download and install either FFNX or the 7th Heaven mod manager.
* Copy and paste the Tolk.dll, nvdaControllerClient32.dll, version.dll, and ffvii_accessibility.cfg into the following folder.
** 2013: "C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\"
*** Note: any purchase of the game made after the 2026 version's release is the 2026 version despite Steam's page saying it's release was in 2013.
** 2026: "C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\"
* Run the game using ff7_en.exe

Keys

Announcements:

G: Announce current Gil
M: Announce current map.
H: In battle, announce character hp, mp, status effects.
T: Announce active timers.
Shift+T: Toggle timer freeze.
I: In shop, magic, materia, and equip menus, read the description of the highlighted item or spell.

Battle:

With the cursor on Attack, press Right for Defend or Left for Change. These two commands are not shown as menu rows in the original game.

Pathfinding:

J and L or [ and ]: cycle destinations in pathfinder
Shift+J and L or - and =: change destination categories
K: Announce name of currently selected destination.
Shift+K: Reset destination category to All. Also ends an active journey.
\ or p: get directions to selected destination. On a place in the Places category, this starts a journey to it. While a journey is active, this key always speaks the current leg of the journey.

The Places category lists only places you have already visited, so it grows as you explore.

Settings menu:

F8: Open or close the spoken accessibility settings menu. It works everywhere except the name entry screen.
While the menu is open:
J and L or [ and ]: move between settings
Shift+J and L or - and =: change the selected setting. Tone volume moves in steps of 10 and plays a sample tone at the new loudness.
K: repeat the current setting and its value.
I: describe what the current setting does.
Changes apply immediately and are saved to your config file for you. The pathfinder keys pause while the menu is open and come back when it closes.
