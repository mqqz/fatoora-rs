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
        try (Signer signer = Signer.fromPem(read("certificate.pem"), read("private-key.pem"));
             FinalizedInvoice invoice = FinalizedInvoice.fromXml(read("invoice.xml"));
             SignedInvoice signed = signer.sign(invoice)) {
            write("signed.xml", signed.intoXml());
        }
        System.out.println("Saved signed.xml");
    }
}
