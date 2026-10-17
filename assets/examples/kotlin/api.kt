import com.fatoora.*
import java.io.File

fun main(args: Array<String>) {
    val environment = 0 // Non-production; credentials must match.
    val token = requireNotNull(System.getenv("ZATCA_TOKEN")) { "Set ZATCA_TOKEN first" }
    val secret = requireNotNull(System.getenv("ZATCA_SECRET")) { "Set ZATCA_SECRET first" }
    Config.create(environment).use { config ->
        ZatcaClient.create(config).use { client ->
            CsidProduction.create(environment, null, token, secret).use { credentials ->
                SignedInvoice.fromXml(File("signed.xml").readText()).use { invoice ->
                    client.reportSimplifiedInvoice(invoice, credentials, false, "en").use { response ->
                        response.ensureAccepted()
                        println("Invoice reporting accepted")
                    }
                }
            }
        }
    }
}
