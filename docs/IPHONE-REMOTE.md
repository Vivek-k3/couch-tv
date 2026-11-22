# The iPhone's own remote (Control Center)

On an Android TV or Google TV with the on-TV app (option C), the TV shows up in the iPhone's built-in
**Control Center ▸ Remote** (Apple TV Remote), next to any Apple TVs. No app on the iPhone, no computer.

It is in this fork only (`appleremote/`), and has been tried on one TV so far: a Changhong AI PONT
(Android TV 11, 32-bit ARM) with an iPhone on iOS 27.

## How it works

`appleremote/` is a small Go program (about 10 MB on disk, about 5 to 10 MB of memory) that the
on-TV app carries as `lib/<abi>/libtvbridge.so`. It:

- appears to iOS as an Apple TV (the Companion protocol: `_companion-link._tcp`, PIN pairing, encrypted
  session), so the Control Center remote lists the TV and sends it swipes, taps and buttons;
- also appears as a HomeKit Television (optional: add it in the Home app for Siri, power and inputs);
- turns what the iPhone sends into key presses through a virtual remote (`/dev/uinput`).

Only the shell user may open `/dev/uinput`, so the app starts the program over the ADB connection it
already holds (Couch TV, **Connect ADB**): it copies it to `/data/local/tmp/tvbridge` and runs it with
`setsid`. Nothing new is asked for. Its state (paired iPhones, the HomeKit code) is in
`/data/local/tmp/tvb`, and its control API listens on `127.0.0.1:8899`, on the TV only.

## Use it

1. Couch TV must have its ADB connection (on-tv/README.md, "The one setup step"). The remote starts
   by itself whenever that connects, after every restart too.
2. On the iPhone: Control Center ▸ Remote ▸ pick the TV. The TV shows a code; type it on the iPhone (once per iPhone).
3. Optional: Home app ▸ + ▸ Add Accessory ▸ More options, and the setup code the remote's screen shows
   (`adb shell am start -n dev.couchtv.ontv/.AppleRemoteActivity`).

| iPhone remote | TV |
|---|---|
| Swipes on the touch area | Arrow keys |
| Tap | OK |
| Back, TV/Home, Play/Pause | Back, Home, Play/Pause |
| Volume buttons, mute | Volume up/down, mute |

## Switch it off

`POST /api/settings {"apple_remote": false}` (with a paired phone's token) stops it and keeps it off;
`true` starts it again. `GET /api/settings` reports `apple_remote: {enabled, available, running}`.

## Build

`scripts/build-apk.sh` builds it into the on-TV APKs when Go 1.24 or newer is installed; without Go the
app is built without it. Tests: `cd appleremote && go test ./...`.

## Limits

- The TV must be on: when it sleeps, the program sleeps with it, so the remote cannot turn it on.
- Long presses and the Siri button are not passed on.
- It needs ADB, so it does not run on current Fire OS (which blocks an app from the TV's own ADB).
