import com.fatoora.*
import java.io.File

fun main(args: Array<String>) {
    SignedInvoice.fromXml(File("signed.xml").readText()).use { invoice ->
        val payload = invoice.qrCode()
        File("qr.txt").writeText(payload)
        println(payload)
    }
}
