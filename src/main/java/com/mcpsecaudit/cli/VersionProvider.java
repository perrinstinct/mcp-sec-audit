package com.mcpsecaudit.cli;

import com.mcpsecaudit.McpSecAudit;
import picocli.CommandLine;

import java.io.InputStream;
import java.util.Properties;

/** Reads the version Maven filtered into version.properties, so it never drifts from the pom. */
public class VersionProvider implements CommandLine.IVersionProvider {

    @Override
    public String[] getVersion() throws Exception {
        try (InputStream stream = VersionProvider.class.getResourceAsStream("/version.properties")) {
            if (stream == null) {
                return new String[]{McpSecAudit.NAME + " (unknown version)"};
            }
            Properties properties = new Properties();
            properties.load(stream);
            return new String[]{McpSecAudit.NAME + " " + properties.getProperty("version", "unknown")};
        }
    }
}
