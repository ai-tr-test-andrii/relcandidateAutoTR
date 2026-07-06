import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

public class InfrastructureVulns {

    // Allowlist of permitted schemes and hosts for outbound requests.
    // Extend this list to include additional trusted external domains as needed.
    private static final List<String> ALLOWED_SCHEMES = Arrays.asList("http", "https");
    private static final List<String> ALLOWED_HOSTS   = Arrays.asList(
            "api.example.com",
            "cdn.example.com"
    );

    // 1. SSRF (High) — fixed: validate scheme and host against explicit allowlists
    //    using java.net.URI (stdlib parser) before opening the connection.
    public String fetchUrl(HttpServletRequest request) throws Exception {

        String target = request.getParameter("url");

        // Parse with URI so scheme and host are extracted by the stdlib,
        // not by a regex or substring search that can be bypassed.
        URI uri;
        try {
            uri = new URI(target).normalize();
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid URL supplied.");
        }

        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "";
        String host   = uri.getHost()   != null ? uri.getHost().toLowerCase()   : "";

        // Enforce scheme allowlist — blocks file://, ftp://, gopher://, etc.
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            throw new IllegalArgumentException(
                    "URL scheme not permitted: " + scheme);
        }

        // Enforce host allowlist — blocks requests to internal/cloud-metadata addresses.
        if (!ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException(
                    "URL host not permitted: " + host);
        }

        URL url = uri.toURL();

        return new String(
                url.openStream().readAllBytes());
    }

    // 2. XXE (High)
    public Document parseXml(InputStream xml)
            throws Exception {

        DocumentBuilderFactory factory =
                DocumentBuilderFactory.newInstance();

        DocumentBuilder builder =
                factory.newDocumentBuilder();

        return builder.parse(xml);
    }

    // 3. Weak Hash (Medium)
    public byte[] md5(String input)
            throws Exception {

        return MessageDigest
                .getInstance("MD5")
                .digest(input.getBytes());
    }

    // 4. Information Exposure (Medium)
    public void log(Exception e) {
        e.printStackTrace();
    }

    // 5. Open Redirect (Medium/High)
    public String redirect(
            HttpServletRequest request) {

        return request.getParameter(
                "redirectUrl");
    }
}