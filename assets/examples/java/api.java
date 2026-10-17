import com.fatoora.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class Guide {
    static String read(String path) throws java.io.IOException {
        return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
    }
    static void write(String path, String text) throws java.io.IOException {
        Files.write(Paths.get(path), text.getBytes(StandardCharsets.UTF_8));
    }
    public static void main(String[] args) throws Exception {
        int environment = 0; // Non-production; credentials must match.
        String token = java.util.Objects.requireNonNull(System.getenv("ZATCA_TOKEN"), "Set ZATCA_TOKEN first");
        String secret = java.util.Objects.requireNonNull(System.getenv("ZATCA_SECRET"), "Set ZATCA_SECRET first");
        try (Config config = Config.create(environment);
             ZatcaClient client = ZatcaClient.create(config);
             CsidProduction credentials = CsidProduction.create(environment, null, token, secret);
             SignedInvoice invoice = SignedInvoice.fromXml(read("signed.xml"));
             ValidationResponse response = client.reportSimplifiedInvoice(invoice, credentials, false, "en")) {
            response.ensureAccepted();
            System.out.println("Invoice reporting accepted");
        }
    }
}
