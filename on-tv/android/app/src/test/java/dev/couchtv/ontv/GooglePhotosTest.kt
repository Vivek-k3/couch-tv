package dev.couchtv.ontv

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GooglePhotosTest {
    @Test fun shareLinks() {
        assertTrue(GooglePhotos.looksRight("https://photos.app.goo.gl/AbC123xyz"))
        assertTrue(GooglePhotos.looksRight("https://photos.google.com/share/AF1Qip_abc-1?key=Zx_9-k"))
        assertFalse(GooglePhotos.looksRight("https://photos.google.com/album/AF1Qip"))    // a private album address
        assertFalse(GooglePhotos.looksRight("http://photos.app.goo.gl/AbC123"))
        assertFalse(GooglePhotos.looksRight("https://example.com/photos.app.goo.gl/x"))
    }

    @Test fun parsesPhotosInOrderSkippingIconsAndRepeats() {
        val html = """
            AF_initDataCallback({data:[["https://lh3.googleusercontent.com/a/ACg8ocAvatar",96,96],
            [null,["https://lh3.googleusercontent.com/pw/AP1GczFirst_1",4032,3024,null]],
            [null,["https://lh3.googleusercontent.com/pw/AP1GczSecond-2",3024,4032,null]],
            [null,["https://lh3.googleusercontent.com/pw/AP1GczIcon",64,64,null]],
            [null,["https://lh3.googleusercontent.com/pw/AP1GczFirst_1",4032,3024,null]]]});
        """
        val got = GooglePhotos.parse(html)
        assertEquals(2, got.length())
        assertEquals("https://lh3.googleusercontent.com/pw/AP1GczFirst_1=w1920-h1080", got.getString(0))
        assertEquals("https://lh3.googleusercontent.com/pw/AP1GczSecond-2=w1920-h1080", got.getString(1))
    }

    @Test fun nothingOnAnUnrelatedPage() {
        assertEquals(0, GooglePhotos.parse("<html><body>Sign in</body></html>").length())
    }
}
