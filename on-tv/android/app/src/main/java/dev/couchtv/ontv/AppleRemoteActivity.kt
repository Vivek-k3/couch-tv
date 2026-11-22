package dev.couchtv.ontv

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.widget.TextView

/**
 * The iPhone remote's screen. The bridge (AppleRemote) opens it with an extra "pin" while an iPhone
 * pairs, and it closes itself once the pairing is done. Opened without a PIN it starts the bridge if
 * needed and shows its state, with the HomeKit setup code until Apple Home is paired.
 */
class AppleRemoteActivity : Activity() {
    private lateinit var text: TextView
    private val ui = Handler(Looper.getMainLooper())
    @Volatile private var visible = false
    @Volatile private var pin: String? = null

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        text = TextView(this).apply {
            textSize = 28f
            setTextColor(Color.WHITE)
            setBackgroundColor(Color.rgb(16, 18, 24))
            gravity = Gravity.CENTER
            setPadding(64, 64, 64, 64)
        }
        setContentView(text)
        pin = intent.getStringExtra("pin")
        if (pin != null) showPin() else {
            show(if (AppleRemote.available(this)) "Starting the iPhone remote…" else "This build of Couch TV has no iPhone remote.")
            AppleRemote.startAsync(this)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.getStringExtra("pin")?.let { pin = it; showPin() }
    }

    private fun showPin() {
        text.textSize = 40f
        show("Enter this code on your iPhone\n\n" + pin.orEmpty().toCharArray().joinToString(" "))
    }

    override fun onResume() { super.onResume(); visible = true; poll() }
    override fun onPause() { super.onPause(); visible = false }

    private fun poll() {
        if (!visible) return
        Thread {
            val s = AppleRemote.status()
            if (s != null && pin != null) {
                if (s.optString("companionPin", "").isEmpty()) { ui.post { finish() }; return@Thread } // pairing done or cancelled
                ui.postDelayed({ poll() }, 1000); return@Thread
            }
            if (s != null) {
                val code = s.optString("homekitCode", "")
                val shown = if (code.length == 8) "${code.substring(0, 3)}-${code.substring(3, 5)}-${code.substring(5)}" else code
                val remotes = s.optInt("companionPaired", 0)
                show("iPhone remote is on\n\n" +
                    (if (remotes > 0) "iPhone paired ✓ ($remotes)\n\n" else "On your iPhone: Control Center ▸ Remote ▸ pick this TV\n\n") +
                    (if (s.optBoolean("homekitPaired")) "Paired with Apple Home ✓"
                     else "Optional, for Siri and the Home app:\nHome app ▸ + ▸ Add Accessory ▸ More options…\n\nSetup code  $shown"))
            } else if (pin == null && !Adb.connected) {
                show("The iPhone remote needs Couch TV's ADB connection.\n\nOpen Couch TV and press Connect ADB.")
            }
            ui.postDelayed({ poll() }, 3000)
        }.start()
    }

    private fun show(s: String) = ui.post { text.text = s }
}
