package com.mcpsecaudit.scanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Decides whether the module owning a source file can serve HTTP traffic, by reading its
 * build file and Spring configuration rather than Java sources.
 *
 * <p>The unit is the module, not the repository. In a monorepo each module is its own
 * application: a web starter in {@code misc/some-demo} says nothing about a stdio server
 * three directories away. Ancestors still count, because a real parent pom can pass
 * dependencies down, and missing that would quietly downgrade a genuine finding — but
 * siblings never do.
 */
public class ProjectContextDetector {

    private static final Set<String> BUILD_FILE_NAMES =
            Set.of("pom.xml", "build.gradle", "build.gradle.kts");

    /** Substring markers that each imply the application can serve HTTP traffic. */
    private static final Map<String, String> HTTP_MARKERS = Map.of(
            "spring-ai-starter-mcp-server-webmvc", "spring-ai-starter-mcp-server-webmvc dependency",
            "spring-ai-starter-mcp-server-webflux", "spring-ai-starter-mcp-server-webflux dependency",
            "spring-boot-starter-web", "spring-boot-starter-web dependency",
            "spring.ai.mcp.server.stdio=false", "spring.ai.mcp.server.stdio=false",
            "stdio: false", "spring.ai.mcp.server.stdio: false"
    );

    private final Map<Path, ProjectContext> byModule = new HashMap<>();

    public ProjectContext detect(Path target) {
        Path module = owningModule(target);

        ProjectContext own = contextOf(module);
        if (own.httpExposureDetected()) {
            return own;
        }

        for (Path ancestor = module.getParent(); ancestor != null; ancestor = ancestor.getParent()) {
            if (!containsBuildFile(ancestor)) {
                continue;
            }
            ProjectContext inherited = contextOf(ancestor);
            if (inherited.httpExposureDetected()) {
                return inherited;
            }
        }
        return ProjectContext.noHttpExposure();
    }

    /** The nearest directory at or above the target that owns a build file. */
    private Path owningModule(Path target) {
        Path directory = Files.isDirectory(target)
                ? target.toAbsolutePath()
                : target.toAbsolutePath().getParent();

        for (Path candidate = directory; candidate != null; candidate = candidate.getParent()) {
            if (containsBuildFile(candidate)) {
                return candidate;
            }
        }
        return directory;
    }

    private ProjectContext contextOf(Path moduleDirectory) {
        return byModule.computeIfAbsent(moduleDirectory, this::inspect);
    }

    private ProjectContext inspect(Path moduleDirectory) {
        for (Path file : filesOwnedBy(moduleDirectory)) {
            String content = readOrEmpty(file);
            for (Map.Entry<String, String> marker : HTTP_MARKERS.entrySet()) {
                if (content.contains(marker.getKey())) {
                    return ProjectContext.httpExposure("%s in %s/%s".formatted(
                            marker.getValue(),
                            moduleDirectory.getFileName(),
                            moduleDirectory.relativize(file)));
                }
            }
        }
        return ProjectContext.noHttpExposure();
    }

    /**
     * The module's own build files plus its Spring configuration. Never looks sideways
     * into other modules, which is what made a sibling's dependency contaminate the
     * whole repository.
     */
    private List<Path> filesOwnedBy(Path moduleDirectory) {
        List<Path> files = new ArrayList<>();
        for (String buildFileName : BUILD_FILE_NAMES) {
            Path buildFile = moduleDirectory.resolve(buildFileName);
            if (Files.isRegularFile(buildFile)) {
                files.add(buildFile);
            }
        }

        Path sources = moduleDirectory.resolve("src");
        if (Files.isDirectory(sources)) {
            try (Stream<Path> paths = Files.walk(sources)) {
                paths.filter(Files::isRegularFile).filter(this::isSpringConfig).forEach(files::add);
            } catch (IOException e) {
                // an unreadable module simply yields no evidence
            }
        }
        return files;
    }

    private boolean containsBuildFile(Path directory) {
        return BUILD_FILE_NAMES.stream().anyMatch(name -> Files.isRegularFile(directory.resolve(name)));
    }

    private boolean isSpringConfig(Path file) {
        String fileName = file.getFileName().toString();
        return fileName.startsWith("application")
                && (fileName.endsWith(".properties") || fileName.endsWith(".yml") || fileName.endsWith(".yaml"));
    }

    private String readOrEmpty(Path file) {
        try {
            return Files.readString(file);
        } catch (IOException e) {
            return "";
        }
    }
}
