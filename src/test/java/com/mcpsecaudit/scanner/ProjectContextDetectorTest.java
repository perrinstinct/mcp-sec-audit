package com.mcpsecaudit.scanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProjectContextDetectorTest {

    @Test
    void detectsHttpExposureFromAWebStarterDependency(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.ai</groupId>
                            <artifactId>spring-ai-starter-mcp-server-webmvc</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """);

        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertTrue(context.httpExposureDetected());
        assertTrue(context.evidence().contains("webmvc"));
    }

    @Test
    void detectsHttpExposureFromStdioDisabledInProperties(@TempDir Path tempDir) throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(tempDir.resolve("src/main/resources/application-http.properties"),
                "spring.ai.mcp.server.stdio=false\n");

        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertTrue(context.httpExposureDetected());
    }

    @Test
    void reportsNoHttpExposureForAStdioOnlyProject(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.ai</groupId>
                            <artifactId>spring-ai-starter-mcp-server</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """);
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(tempDir.resolve("src/main/resources/application.properties"),
                "spring.ai.mcp.server.stdio=true\n");

        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertFalse(context.httpExposureDetected());
    }

    @Test
    void reportsNoHttpExposureWhenThereIsNothingToReadAtAll(@TempDir Path tempDir) throws IOException {
        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertFalse(context.httpExposureDetected());
    }

    @Test
    void findsTheBuildFileAboveTheScannedSubdirectory(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project><dependencies><dependency>
                    <artifactId>spring-ai-starter-mcp-server-webmvc</artifactId>
                </dependency></dependencies></project>
                """);
        Path sources = tempDir.resolve("src/main/java/com/example");
        Files.createDirectories(sources);
        Files.writeString(sources.resolve("Tool.java"), "public class Tool {}");

        ProjectContext context = new ProjectContextDetector().detect(sources);

        assertTrue(context.httpExposureDetected(),
                "scanning a subdirectory must still see the project's own build file");
    }

    @Test
    void findsTheBuildFileWhenGivenASingleFile(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project><dependencies><dependency>
                    <artifactId>spring-boot-starter-web</artifactId>
                </dependency></dependencies></project>
                """);
        Path file = tempDir.resolve("src/main/java/Tool.java");
        Files.createDirectories(file.getParent());
        Files.writeString(file, "public class Tool {}");

        ProjectContext context = new ProjectContextDetector().detect(file);

        assertTrue(context.httpExposureDetected());
    }
}
