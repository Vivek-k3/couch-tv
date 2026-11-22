package dev.couchtv.ontv

import android.content.Context
import android.provider.Settings
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * The iPhone's own Control Center remote (Apple TV Remote) for this TV.
 *
 * appleremote/ (Go) is built into this APK as lib/<abi>/libtvbridge.so. It makes the TV appear to
 * iOS as an Apple TV (the Companion protocol) and as a HomeKit Television, and turns the iPhone's
 * swipes and buttons into key presses through a virtual remote (/dev/uinput). Only the shell user
 * may open /dev/uinput, so the binary is started over the ADB connection this app already holds:
 * copied to /data/local/tmp and run with setsid, so it outlives the shell. Nothing new is asked for.
 *
 * Its state (iPhone pairings, the HomeKit setup code) lives in /data/local/tmp/tvb, so a TV that
 * ran the separate "TV Bridge" app keeps its pairings. It listens for its control API on
 * 127.0.0.1:8899 (local only) and shows the iPhone's PIN through AppleRemoteActivity.
 *
 * Off with Store "apple_remote" = false (POST /api/settings {"apple_remote": false}), which also stops it.
 */
object AppleRemote {
    private const val TAG = "couchtv"
    private const val BIN = "/data/local/tmp/tvbridge"
    private const val DIR = "/data/local/tmp/tvb"
    const val STATUS_URL = "http://127.0.0.1:8899/status"

    fun enabled() = Store.bool("apple_remote", true)

    private fun lib(c: Context) = File(c.applicationInfo.nativeLibraryDir, "libtvbridge.so")

    /** True when this build carries the bridge (it is left out when Go was not there at build time). */
    fun available(c: Context) = lib(c).isFile

    private fun q(s: String) = "'" + s.replace("'", "'\\''") + "'"

    /**
     * Starts the bridge as the shell user if it is not running, and replaces it when this APK carries
     * a different binary. Needs ADB. Safe to call often: it does nothing when the right one is up.
     */
    @Synchronized fun start(c: Context): String {
        if (!enabled()) return "off"
        if (!available(c)) return "not in this build"
        if (!Adb.connected) return "needs ADB"
        val name = Settings.Global.getString(c.contentResolver, "device_name")?.takeIf { it.isNotBlank() } ?: "Google TV"
        val script = """
            mkdir -p $DIR
            if ! cmp -s ${q(lib(c).path)} $BIN; then kill $(pidof tvbridge) 2>/dev/null; sleep 1; cp ${q(lib(c).path)} $BIN && chmod 755 $BIN; fi
            if pidof tvbridge >/dev/null; then echo running; else
            cd $DIR && (setsid nohup $BIN -data $DIR -name ${q(name)} -http 127.0.0.1:8899 -pin-activity ${BuildConfig.APPLICATION_ID}/.AppleRemoteActivity > $DIR/log.txt 2>&1 < /dev/null &) ; sleep 1; pidof tvbridge >/dev/null && echo started || echo failed; fi
        """.trimIndent()
        val out = runCatching { Adb.shell(script, 30_000).trim() }.getOrElse { "error: ${it.message}" }
        Log.i(TAG, "apple remote: $out")
        return out
    }

    @Synchronized fun stop(): String {
        if (!Adb.connected) return "needs ADB"
        return runCatching { Adb.shell("kill \$(pidof tvbridge) 2>/dev/null; echo stopped", 10_000).trim() }.getOrElse { "error: ${it.message}" }
    }

    /** The bridge's own /status (HomeKit code and pairing, paired iPhones, a PIN while one pairs), or null when it is not up. */
    fun status(): org.json.JSONObject? = runCatching {
        val conn = URL(STATUS_URL).openConnection() as HttpURLConnection
        conn.connectTimeout = 1500; conn.readTimeout = 1500
        try { org.json.JSONObject(conn.inputStream.bufferedReader().readText()) } finally { conn.disconnect() }
    }.getOrNull()

    fun startAsync(c: Context) { Thread { start(c.applicationContext) }.start() }
}
