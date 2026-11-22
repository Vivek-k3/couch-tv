package dev.couchtv.ontv

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * A Google Photos shared album as the home's slideshow.
 *
 * Google's Photos Library API no longer lets an app read albums it did not make (March 2025), so this
 * reads the album's public share page instead, the way photo frames do: the link from Share ▸ Create
 * link (photos.app.goo.gl/... or photos.google.com/share/...). Anyone with that link can see the album.
 * The page lists each photo's lh3.googleusercontent.com/pw/ address with its size; those addresses
 * load without signing in. This is not an official API, so Google can change the page and break it:
 * the last good list is kept and shown until a refresh works again.
 *
 * Stored in Store (gphotos_album, gphotos.json). The home gets {url, photos, fetched, error} from
 * GET /api/settings as "album", and shows only the album while it has photos.
 */
object GooglePhotos {
    private const val TAG = "couchtv"
    private const val MAX = 300
    private const val EVERY_MS = 6 * 60 * 60 * 1000L
    private val PHOTO = Regex("""\["(https://lh3\.googleusercontent\.com/pw/[A-Za-z0-9_\-]+)",(\d+),(\d+)""")
    @Volatile private var lastError: String? = null
    @Volatile private var busy = false

    fun albumUrl(): String? = Store.str("gphotos_album")?.takeIf { it.isNotBlank() }

    /** True for a Google Photos share link. */
    fun looksRight(u: String) = Regex("""^https://(photos\.app\.goo\.gl/[A-Za-z0-9]+|photos\.google\.com/share/[A-Za-z0-9_\-]+(\?key=[A-Za-z0-9_\-]+)?)/?$""").matches(u.trim())

    private fun cached(): JSONObject? = Store.readJson("gphotos.json") as? JSONObject

    /** What the home and the setup page see. */
    fun status(): JSONObject {
        val url = albumUrl() ?: return JSONObject().put("url", JSONObject.NULL).put("photos", JSONArray())
        val c = cached()?.takeIf { it.optString("url") == url }
        val oldFormat = c?.optJSONArray("photos")?.opt(0) is String   // before sizes were kept
        if (c == null || oldFormat || System.currentTimeMillis() - c.optLong("fetched") > EVERY_MS) refreshAsync()
        return JSONObject().put("url", url)
            .put("photos", c?.optJSONArray("photos") ?: JSONArray())
            .put("fetched", c?.optLong("fetched") ?: 0)
            .put("error", lastError ?: JSONObject.NULL)
    }

    /** Sets (or with "" clears) the album and reads it straight away. Throws ApiError-style messages. */
    fun set(u: String): String? {
        val url = u.trim()
        if (url.isEmpty()) {
            Store.putStr("gphotos_album", ""); Store.writeJson("gphotos.json", JSONObject()); lastError = null
            return null
        }
        if (!looksRight(url)) return "That is not a Google Photos share link (photos.app.goo.gl/... or photos.google.com/share/...)."
        Store.putStr("gphotos_album", url)
        refresh()
        return lastError
    }

    fun refreshAsync() {
        if (busy) return
        Thread { refresh() }.start()
    }

    @Synchronized fun refresh() {
        val url = albumUrl() ?: return
        busy = true
        // A short link once read is remembered as the photos.google.com/share address it led to, so later
        // refreshes skip photos.app.goo.gl: a Jio router's DNS answered that one name with an address that
        // never connected, while photos.google.com and lh3.googleusercontent.com worked (Changhong TV, India).
        val resolved = cached()?.takeIf { it.optString("url") == url }?.optString("resolved")?.takeIf { it.startsWith("https://photos.google.com/share/") }
        try {
            var final = resolved ?: url
            val photos = parse(fetch(final) { final = it })
            if (photos.length() == 0) {
                lastError = "No photos found at that link. Check it is a shared album link and that link sharing is on."
                return
            }
            Store.writeJson("gphotos.json", JSONObject().put("url", url).put("resolved", final).put("photos", photos).put("fetched", System.currentTimeMillis()))
            lastError = null
            Log.i(TAG, "google photos: ${photos.length()} photos")
            Now.push()   // the home picks the new list up on its next refresh
        } catch (e: Exception) {
            lastError = "Could not read the album: ${e.message}" +
                if (url.contains("photos.app.goo.gl")) ". This TV may not reach the short link: open it in a browser and paste the photos.google.com/share/... address it opens instead." else ""
            Log.w(TAG, "google photos: ${e.message}")
        } finally { busy = false }
    }

    private fun fetch(start: String, landed: (String) -> Unit = {}): String {
        var u = start
        repeat(6) {
            val c = URL(u).openConnection() as HttpURLConnection
            c.instanceFollowRedirects = false
            c.connectTimeout = 10_000; c.readTimeout = 20_000
            c.setRequestProperty("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
            c.setRequestProperty("Accept-Language", "en")
            try {
                val code = c.responseCode
                if (code in 300..399) {
                    u = URL(URL(u), c.getHeaderField("Location") ?: throw IllegalStateException("redirect without an address")).toString()
                    if (!u.startsWith("https://")) throw IllegalStateException("unexpected redirect")
                    return@repeat
                }
                if (code != 200) throw IllegalStateException("Google answered $code")
                landed(u)
                return c.inputStream.bufferedReader().use { r -> r.readText().take(8_000_000) }
            } finally { c.disconnect() }
        }
        throw IllegalStateException("too many redirects")
    }

    /**
     * Photos from a share page, in album order: {u: address sized for a TV, w, h: the photo's own size}.
     * The size lets the home put two tall photos side by side. Public for the unit test.
     */
    fun parse(html: String): JSONArray {
        val seen = LinkedHashMap<String, Pair<Int, Int>>()
        for (m in PHOTO.findAll(html)) {
            val w = m.groupValues[2].toInt(); val h = m.groupValues[3].toInt()
            if (w < 200 || h < 200) continue      // icons and avatars, not photos
            if (m.groupValues[1] !in seen) seen[m.groupValues[1]] = w to h
            if (seen.size >= MAX) break
        }
        return JSONArray(seen.map { (u, wh) -> JSONObject().put("u", "$u=w1920-h1080").put("w", wh.first).put("h", wh.second) })
    }
}
