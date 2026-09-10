package com.mcpsecaudit.cli;

import com.mcpsecaudit.McpSecAudit;
import picocli.CommandLine;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/** Reads the version Maven filtered into version.properties, so it never drifts from the pom. */
public class VersionProvider implements CommandLine.IVersionProvider {

    @Override
    public String[] getVersion() {
        return new String[]{McpSecAudit.NAME + " " + version()};
    }

    /** The version Maven filtered in, or "unknown" if the resource is missing. */
    public static String version() {
        try (InputStream stream = VersionProvider.class.getResourceAsStream("/version.properties")) {
            if (stream == null) {
                return "unknown";
            }
            Properties properties = new Properties();
            properties.load(stream);
            return properties.getProperty("version", "unknown");
        } catch (IOException e) {
            return "unknown";
        }
    }
}
