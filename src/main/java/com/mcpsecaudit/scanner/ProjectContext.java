package com.mcpsecaudit.scanner;

/**
 * What the scanned project reveals about how its MCP server is exposed.
 * Source files alone cannot answer this - the answer lives in build files
 * and Spring configuration - but it decides whether a missing authorization
 * annotation is a real risk or noise on a local stdio server.
 */
public record ProjectContext(boolean httpExposureDetected, String evidence) {

    public static ProjectContext noHttpExposure() {
        return new ProjectContext(false, "no HTTP exposure detected");
    }

    public static ProjectContext httpExposure(String evidence) {
        return new ProjectContext(true, evidence);
    }
}
