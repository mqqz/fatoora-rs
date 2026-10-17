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
        try (Config config = Config.create(0)) {
            String xml = read("invoice.xml");
            if (java.util.Arrays.asList(args).contains("--zatca")) {
                com.google.gson.JsonObject options = new com.google.gson.JsonObject();
                options.addProperty("previous_invoice_hash", read("previous-hash.txt").trim());
                String json = Xml.validateZatca(config, xml, options.toString());
                System.out.println(json);
                boolean valid = com.google.gson.JsonParser.parseString(json).getAsJsonObject()
                    .get("is_valid").getAsBoolean();
                if (!valid) System.exit(1);
            } else {
                Xml.validate(config, xml);
                System.out.println("XSD valid");
            }
        }
    }
}
