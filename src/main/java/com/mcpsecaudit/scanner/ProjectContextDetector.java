package com.mcpsecaudit.scanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Decides whether the module owning a source file can serve HTTP traffic, and whether
 * reaching its MCP endpoint requires authenticating, by reading its build file, its Spring
 * configuration and its security configuration.
 *
 * <p>The unit is the module, not the repository. In a monorepo each module is its own
 * application: a web starter in {@code misc/some-demo} says nothing about a stdio server
 * three directories away. Ancestors still count for dependencies, because a real parent pom
 * can pass them down, and missing that would quietly downgrade a genuine finding - but
 * siblings never do, and Java sources are read in the owning module only, since code is not
 * inherited the way a dependency is.
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

    /**
     * Spring AI's MCP security starter builds a chain that authenticates every request, but
     * only once an issuer URI is configured, and only until the application declares a chain
     * of its own.
     */
    private static final String AUTO_CONFIGURATION_DEPENDENCY = "mcp-server-security-spring-boot";

    private static final String ISSUER_URI_MARKER = "issuer-uri";

    private static final Set<String> SECURITY_CHAIN_MARKERS =
            Set.of("SecurityFilterChain", "SecurityWebFilterChain");

    /** Endpoint properties, matched in both {@code .properties} and YAML. */
    private static final Pattern ENDPOINT_PROPERTY = Pattern.compile(
            "(mcp-endpoint|sse-endpoint|sse-message-endpoint)\\s*[:=]\\s*([^\\s#]+)");

    private final SecurityChainAnalyzer chainAnalyzer = new SecurityChainAnalyzer();

    private final Map<Path, ProjectContext> exposureByModule = new HashMap<>();
    private final Map<Path, Optional<String>> authenticationByModule = new HashMap<>();

    public ProjectContext detect(Path target) {
        Path module = owningModule(target);

        ProjectContext exposure = exposureOf(module);
        if (!exposure.httpExposureDetected()) {
            return exposure;
        }
        return authenticationOf(module).map(exposure::authenticatedBy).orElse(exposure);
    }

    private ProjectContext exposureOf(Path module) {
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
        return exposureByModule.computeIfAbsent(moduleDirectory, this::inspect);
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

    private Optional<String> authenticationOf(Path moduleDirectory) {
        return authenticationByModule.computeIfAbsent(moduleDirectory, this::inspectSecurity);
    }

    /**
     * The module's own chains decide; only a module that declares none falls back to the
     * starter's auto-configuration, exactly as Spring Boot does.
     */
    private Optional<String> inspectSecurity(Path moduleDirectory) {
        SecurityChainAnalyzer.Verdict verdict = chainAnalyzer.inspect(
                securityConfigurationOf(moduleDirectory), mcpEndpointsOf(moduleDirectory));

        if (verdict.chainsDeclared()) {
            return Optional.ofNullable(verdict.authenticationEvidence());
        }
        return autoConfiguredAuthentication(moduleDirectory);
    }

    private Optional<String> autoConfiguredAuthentication(Path moduleDirectory) {
        if (!dependencyDeclared(moduleDirectory, AUTO_CONFIGURATION_DEPENDENCY)) {
            return Optional.empty();
        }
        boolean issuerConfigured = configurationFilesOf(moduleDirectory).stream()
                .anyMatch(file -> readOrEmpty(file).contains(ISSUER_URI_MARKER));
        if (!issuerConfigured) {
            return Optional.empty();
        }
        return Optional.of("%s auto-configuration with an %s in %s".formatted(
                AUTO_CONFIGURATION_DEPENDENCY, ISSUER_URI_MARKER, moduleDirectory.getFileName()));
    }

    /** Dependencies can come from the module itself or from a real parent above it. */
    private boolean dependencyDeclared(Path moduleDirectory, String artifactId) {
        for (Path directory = moduleDirectory; directory != null; directory = directory.getParent()) {
            for (Path buildFile : buildFilesOf(directory)) {
                if (readOrEmpty(buildFile).contains(artifactId)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** The module's own Java sources that mention a security chain, so the rest is never parsed. */
    private List<Path> securityConfigurationOf(Path moduleDirectory) {
        Path sources = moduleDirectory.resolve("src/main/java");
        if (!Files.isDirectory(sources)) {
            return List.of();
        }
        try (Stream<Path> paths = Files.walk(sources)) {
            return paths
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".java"))
                    .filter(path -> {
                        String content = readOrEmpty(path);
                        return SECURITY_CHAIN_MARKERS.stream().anyMatch(content::contains);
                    })
                    .toList();
        } catch (IOException e) {
            return List.of();
        }
    }

    /** The defaults, plus any endpoint the module moved in its Spring configuration. */
    private Set<String> mcpEndpointsOf(Path moduleDirectory) {
        Set<String> endpoints = new HashSet<>(SecurityChainAnalyzer.DEFAULT_MCP_ENDPOINTS);
        for (Path file : configurationFilesOf(moduleDirectory)) {
            Matcher matcher = ENDPOINT_PROPERTY.matcher(readOrEmpty(file));
            while (matcher.find()) {
                String endpoint = matcher.group(2);
                if (endpoint.startsWith("/")) {
                    endpoints.add(endpoint);
                }
            }
        }
        return endpoints;
    }

    /**
     * The module's own build files plus its Spring configuration. Never looks sideways
     * into other modules, which is what made a sibling's dependency contaminate the
     * whole repository.
     */
    private List<Path> filesOwnedBy(Path moduleDirectory) {
        List<Path> files = new ArrayList<>(buildFilesOf(moduleDirectory));
        files.addAll(configurationFilesOf(moduleDirectory));
        return files;
    }

    private List<Path> buildFilesOf(Path directory) {
        List<Path> files = new ArrayList<>();
        for (String buildFileName : BUILD_FILE_NAMES) {
            Path buildFile = directory.resolve(buildFileName);
            if (Files.isRegularFile(buildFile)) {
                files.add(buildFile);
            }
        }
        return files;
    }

    private List<Path> configurationFilesOf(Path moduleDirectory) {
        Path sources = moduleDirectory.resolve("src");
        if (!Files.isDirectory(sources)) {
            return List.of();
        }
        try (Stream<Path> paths = Files.walk(sources)) {
            return paths.filter(Files::isRegularFile).filter(this::isSpringConfig).toList();
        } catch (IOException e) {
            return List.of();  // an unreadable module simply yields no evidence
        }
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
