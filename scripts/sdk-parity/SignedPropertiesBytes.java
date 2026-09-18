// Test-only adapter to the checksum-pinned SDK. Captures the exact digest preimage
// from the SDK's own population/serialization methods, with observed signing time.
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.XPath;

public class SignedPropertiesBytes {
    private static Method method(Class<?> type, String name, Class<?>... args) throws Exception {
        Method m = type.getDeclaredMethod(name, args); m.setAccessible(true); return m;
    }
    public static void main(String[] args) throws Exception {
        Class<?> type = Class.forName("com.gazt.einvoicing.signing.service.impl.SigningServiceImpl");
        Object service = type.getConstructor().newInstance();
        Map namespaces = (Map) method(type, "getNameSpacesMap").invoke(service);
        Method parse = method(type, "getXmlDocument", String.class);
        Document signed = (Document) parse.invoke(service, Files.readString(Path.of(args[1])));
        if (args.length == 4 && args[3].equals("actual")) {
            String value = (String) method(type, "getNodeXmlValue", Document.class, Map.class, String.class)
                .invoke(service, signed, namespaces, "//xades:SignedProperties");
            Files.writeString(Path.of(args[2]), value);
            return;
        }
        String[] paths = {"//xades:CertDigest/ds:DigestValue", "//xades:SigningTime", "//ds:X509IssuerName", "//ds:X509SerialNumber"};
        String[] values = new String[4];
        for (int i=0; i<4; i++) {
            XPath xpath = DocumentHelper.createXPath(paths[i]); xpath.setNamespaceURIs(namespaces);
            values[i] = xpath.selectSingleNode(signed).getText();
        }
        String transformed = (String) method(type, "transformXML", String.class).invoke(service, Files.readString(Path.of(args[0])));
        Document doc = (Document) parse.invoke(service, transformed);
        String hash = (String) method(type, "populateSignedSignatureProperties", Document.class, Map.class,
            String.class, String.class, String.class, String.class).invoke(service, doc, namespaces, values[0], values[1], values[2], values[3]);
        String bytes = (String) method(type, "getNodeXmlValue", Document.class, Map.class, String.class)
            .invoke(service, doc, namespaces, "//xades:SignedProperties");
        XPath digest = DocumentHelper.createXPath("//ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue");
        digest.setNamespaceURIs(namespaces);
        if (!hash.equals(digest.selectSingleNode(signed).getText())) throw new Exception("SDK SignedProperties preimage differs from CLI digest");
        Files.writeString(Path.of(args[2]), bytes);
    }
}
