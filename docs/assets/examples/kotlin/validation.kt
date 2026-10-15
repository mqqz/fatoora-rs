import com.fatoora.*
import java.io.File
import kotlinx.serialization.json.*

fun main(args: Array<String>) {
    Config.create(0).use { config ->
        val xml = File("invoice.xml").readText()
        if (args.contains("--zatca")) {
            val hash = File("previous-hash.txt").readText().trim()
            val options = kotlinx.serialization.json.buildJsonObject {
                put("previous_invoice_hash", kotlinx.serialization.json.JsonPrimitive(hash))
            }.toString()
            val json = Xml.validateZatca(config, xml, options)
            println(json)
            val report = kotlinx.serialization.json.Json.parseToJsonElement(json).jsonObject
            if (!report.getValue("is_valid").jsonPrimitive.boolean) kotlin.system.exitProcess(1)
        } else {
            Xml.validate(config, xml)
            println("XSD valid")
        }
    }
}
