import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * Tests that verify the SSRF remediation in {@link InfrastructureVulns#fetchUrl}.
 *
 * The fix uses {@code java.net.URI} to parse the caller-supplied URL and then
 * validates both the scheme and host against explicit allowlists before any
 * network connection is opened.  These tests confirm that disallowed schemes
 * and hosts are rejected with {@link IllegalArgumentException} and that the
 * method accepts well-formed allowlisted URLs.
 */
public class InfrastructureVulnsTest {

    private InfrastructureVulns sut;
    private HttpServletRequest  mockRequest;

    @BeforeEach
    void setUp() {
        sut         = new InfrastructureVulns();
        mockRequest = Mockito.mock(HttpServletRequest.class);
    }

    // -----------------------------------------------------------------------
    // Scheme allowlist enforcement
    // -----------------------------------------------------------------------

    /**
     * A {@code file://} URL must be rejected — it would let an attacker read
     * local files on the server (e.g. /etc/passwd).
     */
    @Test
    void fetchUrl_fileScheme_throwsIllegalArgument() {
        when(mockRequest.getParameter("url")).thenReturn("file:///etc/passwd");

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));

        assertTrue(ex.getMessage().toLowerCase().contains("scheme") ||
                   ex.getMessage().toLowerCase().contains("permitted"),
                "Exception message should mention the disallowed scheme");
    }

    /**
     * A {@code ftp://} URL must be rejected — not in the allowed-scheme list.
     */
    @Test
    void fetchUrl_ftpScheme_throwsIllegalArgument() {
        when(mockRequest.getParameter("url")).thenReturn("ftp://api.example.com/file");

        assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));
    }

    /**
     * A {@code gopher://} URL must be rejected — classic SSRF pivot protocol.
     */
    @Test
    void fetchUrl_gopherScheme_throwsIllegalArgument() {
        when(mockRequest.getParameter("url")).thenReturn("gopher://internal-host/path");

        assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));
    }

    // -----------------------------------------------------------------------
    // Host allowlist enforcement
    // -----------------------------------------------------------------------

    /**
     * Requests to 127.0.0.1 (loopback) must be blocked to prevent access to
     * services listening only on localhost.
     */
    @Test
    void fetchUrl_localhostIp_throwsIllegalArgument() {
        when(mockRequest.getParameter("url")).thenReturn("http://127.0.0.1/admin");

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));

        assertTrue(ex.getMessage().toLowerCase().contains("host") ||
                   ex.getMessage().toLowerCase().contains("permitted"),
                "Exception message should mention the disallowed host");
    }

    /**
     * Requests to the literal string "localhost" must be blocked.
     */
    @Test
    void fetchUrl_localhostName_throwsIllegalArgument() {
        when(mockRequest.getParameter("url")).thenReturn("http://localhost/secret");

        assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));
    }

    /**
     * Requests to private RFC-1918 addresses must be blocked.
     */
    @Test
    void fetchUrl_privateNetworkAddress_throwsIllegalArgument() {
        when(mockRequest.getParameter("url")).thenReturn("http://192.168.1.1/router");

        assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));
    }

    /**
     * AWS instance metadata endpoint (169.254.169.254) must be blocked — a
     * classic SSRF target for credential theft in cloud environments.
     */
    @Test
    void fetchUrl_awsMetadataEndpoint_throwsIllegalArgument() {
        when(mockRequest.getParameter("url"))
                .thenReturn("http://169.254.169.254/latest/meta-data/");

        assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));
    }

    /**
     * An arbitrary external host that is not on the allowlist must be blocked.
     */
    @Test
    void fetchUrl_arbitraryExternalHost_throwsIllegalArgument() {
        when(mockRequest.getParameter("url")).thenReturn("https://attacker.example.org/evil");

        assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));
    }

    /**
     * A subdomain of an allowed host must NOT be permitted — the check must be
     * an exact match, not a suffix/contains check that can be bypassed with
     * e.g. "evil.api.example.com".
     */
    @Test
    void fetchUrl_subdomainOfAllowedHost_throwsIllegalArgument() {
        when(mockRequest.getParameter("url"))
                .thenReturn("https://evil.api.example.com/path");

        assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));
    }

    /**
     * A URL crafted to fool a contains/suffix check by appending the allowed
     * host as a path component must be blocked
     * (e.g. "https://evil.com/api.example.com").
     */
    @Test
    void fetchUrl_allowedHostInPath_throwsIllegalArgument() {
        when(mockRequest.getParameter("url"))
                .thenReturn("https://evil.com/api.example.com");

        assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));
    }

    /**
     * A URL with an embedded username that includes an allowed hostname
     * (e.g. "https://api.example.com@evil.com/") must be blocked — the real
     * host is "evil.com", not "api.example.com".
     */
    @Test
    void fetchUrl_allowedHostInUserinfo_throwsIllegalArgument() {
        when(mockRequest.getParameter("url"))
                .thenReturn("https://api.example.com@evil.com/");

        assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));
    }

    // -----------------------------------------------------------------------
    // Input validation — malformed URLs
    // -----------------------------------------------------------------------

    /**
     * A completely malformed URL must be rejected with an
     * {@link IllegalArgumentException}, not cause an unhandled exception.
     */
    @Test
    void fetchUrl_malformedUrl_throwsIllegalArgument() {
        when(mockRequest.getParameter("url")).thenReturn("not a url at all %%");

        assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));
    }

    /**
     * An empty string parameter must be rejected.
     */
    @Test
    void fetchUrl_emptyUrl_throwsIllegalArgument() {
        when(mockRequest.getParameter("url")).thenReturn("");

        assertThrows(
                IllegalArgumentException.class,
                () -> sut.fetchUrl(mockRequest));
    }

    // -----------------------------------------------------------------------
    // Happy-path: allowlisted host — validates structure, not live network
    // -----------------------------------------------------------------------

    /**
     * A URL whose scheme is {@code https} and whose host is exactly
     * {@code api.example.com} must pass the validation checks and reach the
     * actual network call.  Since no live server is available in unit tests,
     * we assert that the rejection path is NOT taken (i.e. no
     * {@link IllegalArgumentException} is thrown for scheme/host reasons).
     *
     * <p>Note: the test catches any {@link java.io.IOException} that may arise
     * from the actual network call in a test environment — that is expected
     * and does not indicate a security problem.
     */
    @Test
    void fetchUrl_allowedHttpsHost_passesValidation() {
        when(mockRequest.getParameter("url"))
                .thenReturn("https://api.example.com/data");

        try {
            sut.fetchUrl(mockRequest);
            // If the call succeeds (unlikely in unit test), that is fine.
        } catch (IllegalArgumentException e) {
            // An IllegalArgumentException here means the URL was incorrectly
            // rejected by the allowlist — fail the test.
            fail("Allowlisted URL was incorrectly rejected: " + e.getMessage());
        } catch (Exception e) {
            // Any other exception (IOException, etc.) is a network-level error,
            // not a security rejection — the validation passed correctly.
        }
    }

    /**
     * A URL whose scheme is {@code http} and whose host is exactly
     * {@code cdn.example.com} must also pass validation.
     */
    @Test
    void fetchUrl_allowedHttpHost_passesValidation() {
        when(mockRequest.getParameter("url"))
                .thenReturn("http://cdn.example.com/asset.png");

        try {
            sut.fetchUrl(mockRequest);
        } catch (IllegalArgumentException e) {
            fail("Allowlisted URL was incorrectly rejected: " + e.getMessage());
        } catch (Exception e) {
            // Network error expected in test environment — validation passed.
        }
    }
}
