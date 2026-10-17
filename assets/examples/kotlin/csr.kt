import com.fatoora.*
import java.io.File

fun main(args: Array<String>) {
    CsrProperties.fromPropertiesStr(File("csr.properties").readText()).use { properties ->
        SigningKey.generate().use { key ->
            properties.build(key, 0).use { csr ->
                File("csr.pem").writeText(csr.toPem())
                File("key.pem").writeText(key.toPem())
            }
        }
    }
    println("Saved csr.pem and key.pem")
}
