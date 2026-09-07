package com.mcpsecaudit.scanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Looks for evidence that the scanned project exposes its MCP server over HTTP,
 * by reading build files and Spring configuration rather than Java sources.
 */
public class ProjectContextDetector {

    private static final Set<String> INSPECTED_FILE_NAMES =
            Set.of("pom.xml", "build.gradle", "build.gradle.kts");

    private static final Set<String> INSPECTED_DIRECTORIES = Set.of("target", "build", "out", ".git");

    /** Substring markers that each imply the application can serve HTTP traffic. */
    private static final Map<String, String> HTTP_MARKERS = Map.of(
            "spring-ai-starter-mcp-server-webmvc", "spring-ai-starter-mcp-server-webmvc dependency",
            "spring-ai-starter-mcp-server-webflux", "spring-ai-starter-mcp-server-webflux dependency",
            "spring-boot-starter-web", "spring-boot-starter-web dependency",
            "spring.ai.mcp.server.stdio=false", "spring.ai.mcp.server.stdio=false",
            "stdio: false", "spring.ai.mcp.server.stdio: false"
    );

    public ProjectContext detect(Path rootDirectory) throws IOException {
        try (Stream<Path> paths = Files.walk(rootDirectory)) {
            List<Path> candidates = paths
                    .filter(Files::isRegularFile)
                    .filter(this::isInspectable)
                    .toList();

            for (Path candidate : candidates) {
                String content = readOrEmpty(candidate);
                for (Map.Entry<String, String> marker : HTTP_MARKERS.entrySet()) {
                    if (content.contains(marker.getKey())) {
                        return ProjectContext.httpExposure(
                                marker.getValue() + " in " + rootDirectory.relativize(candidate));
                    }
                }
            }
        }
        return ProjectContext.noHttpExposure();
    }

    private boolean isInspectable(Path path) {
        for (Path segment : path) {
            if (INSPECTED_DIRECTORIES.contains(segment.toString())) {
                return false;
            }
        }
        String fileName = path.getFileName().toString();
        return INSPECTED_FILE_NAMES.contains(fileName)
                || (fileName.startsWith("application") && isSpringConfigExtension(fileName));
    }

    private boolean isSpringConfigExtension(String fileName) {
        return fileName.endsWith(".properties") || fileName.endsWith(".yml") || fileName.endsWith(".yaml");
    }

    private String readOrEmpty(Path file) {
        try {
            return Files.readString(file);
        } catch (IOException e) {
            return "";
        }
    }
}
