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
        try (CsrProperties properties = CsrProperties.fromPropertiesStr(read("csr.properties"));
             SigningKey key = SigningKey.generate();
             Csr csr = properties.build(key, 0)) {
            write("csr.pem", csr.toPem());
            write("key.pem", key.toPem());
        }
        System.out.println("Saved csr.pem and key.pem");
    }
}
