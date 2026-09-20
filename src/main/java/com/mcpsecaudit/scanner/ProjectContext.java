package com.mcpsecaudit.scanner;

/**
 * What the scanned project reveals about how its MCP server is exposed.
 * Source files alone cannot answer this - the answer lives in build files
 * and Spring configuration - but it decides whether a missing authorization
 * annotation is a real risk or noise on a local stdio server.
 *
 * <p>Exposure and authentication are separate questions. A server can be reachable over
 * HTTP and still demand a token on every request, in which case a tool without
 * {@code @PreAuthorize} is reachable by any authenticated client rather than by anyone.
 *
 * @param httpExposureDetected   whether something can reach the server over HTTP
 * @param evidence               what made that call
 * @param endpointAuthenticated  whether reaching the MCP endpoint requires authenticating
 * @param authenticationEvidence what made that call, or null when it was not made
 */
public record ProjectContext(boolean httpExposureDetected, String evidence,
                             boolean endpointAuthenticated, String authenticationEvidence) {

    public static ProjectContext noHttpExposure() {
        return new ProjectContext(false, "no HTTP exposure detected", false, null);
    }

    public static ProjectContext httpExposure(String evidence) {
        return new ProjectContext(true, evidence, false, null);
    }

    /** The same context, with the endpoint known to reject unauthenticated callers. */
    public ProjectContext authenticatedBy(String authenticationEvidence) {
        return new ProjectContext(httpExposureDetected, evidence, true, authenticationEvidence);
    }
}
