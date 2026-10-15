import com.fatoora.*
import java.io.File

fun main(args: Array<String>) {
    Signer.fromPem(File("certificate.pem").readText(), File("private-key.pem").readText()).use { signer ->
        FinalizedInvoice.fromXml(File("invoice.xml").readText()).use { invoice ->
            signer.sign(invoice).use { signed -> File("signed.xml").writeText(signed.intoXml()) }
        }
    }
    println("Saved signed.xml")
}
