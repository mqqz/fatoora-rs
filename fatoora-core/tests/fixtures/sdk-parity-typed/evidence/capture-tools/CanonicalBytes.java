// Test-only adapter for the checksum-pinned 238-R3.4.8 SDK. No copied SDK code.
// Captures the SDK's own transform and canonicalization results. The caller
// must also compare SHA-256 of these bytes with the public CLI hash result.
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.xml.transform.Transformer;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

public class CanonicalBytes {
    public static void main(String[] args) throws Exception {
        Class<?> type = Class.forName("com.gazt.einvoicing.hashing.generation.service.impl.HashingGenerationServiceImpl");
        Object service = type.getConstructor().newInstance();
        Method transform = type.getDeclaredMethod("getTransformer");
        Method canonicalize = type.getDeclaredMethod("canonicalizeXml", byte[].class);
        transform.setAccessible(true);
        canonicalize.setAccessible(true);
        ByteArrayOutputStream intermediate = new ByteArrayOutputStream();
        ((Transformer) transform.invoke(service)).transform(
            new StreamSource(new StringReader(Files.readString(Path.of(args[0]), StandardCharsets.UTF_8))),
            new StreamResult(intermediate));
        String result = (String) canonicalize.invoke(service, (Object) intermediate.toByteArray());
        Files.writeString(Path.of(args[1]), result, StandardCharsets.UTF_8);
    }
}
