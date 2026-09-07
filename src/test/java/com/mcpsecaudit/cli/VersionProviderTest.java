package com.mcpsecaudit.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class VersionProviderTest {

    @Test
    void reportsTheVersionFilteredInFromTheBuild() throws Exception {
        String version = new VersionProvider().getVersion()[0];

        assertTrue(version.startsWith("mcp-sec-audit "), version);
        assertTrue(version.matches(".*\\d+\\.\\d+\\.\\d+.*"), version);
    }
}
