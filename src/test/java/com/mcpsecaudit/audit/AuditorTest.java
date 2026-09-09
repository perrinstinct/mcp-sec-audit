package com.mcpsecaudit.audit;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.ScanReport;
import com.mcpsecaudit.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditorTest {

    @Test
    void combinesFindingsFromAllRulesAcrossToolMethods(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("RiskyTool.java"), """
                package com.example;

                public class RiskyTool {

                    @Tool
                    public void runCommand(String command) throws Exception {
                        Runtime.getRuntime().exec(command);
                    }
                }
                """);

        ScanReport report = new Auditor().audit(tempDir);

        assertEquals(tempDir.toString(), report.scannedPath());
        assertNotNull(report.scannedAt());
        assertTrue(report.findings().stream().anyMatch(f -> f.ruleId().equals("PROC_EXEC")));
        assertTrue(report.findings().stream().anyMatch(f -> f.ruleId().equals("MISSING_AUTH")));
    }

    @Test
    void returnsNoFindingsForCleanCode(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("CleanTool.java"), """
                package com.example;

                public class CleanTool {

                    @PreAuthorize("hasRole('ADMIN')")
                    @Tool
                    public String safeEcho(String message) {
                        return message;
                    }
                }
                """);

        ScanReport report = new Auditor().audit(tempDir);

        assertTrue(report.findings().isEmpty());
    }

    @Test
    void ignoresEveryRuleOnAMethodMarkedWithABareIgnoreComment(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("RiskyTool.java"), """
                package com.example;

                public class RiskyTool {

                    // mcp-sec-audit:ignore
                    @Tool
                    public void suppressed(String command) throws Exception {
                        Runtime.getRuntime().exec(command);
                    }

                    @Tool
                    public void notSuppressed(String command) throws Exception {
                        Runtime.getRuntime().exec(command);
                    }
                }
                """);

        ScanReport report = new Auditor().audit(tempDir);

        assertTrue(report.findings().stream().noneMatch(f -> f.methodName().equals("suppressed")));
        assertTrue(report.findings().stream().anyMatch(f -> f.methodName().equals("notSuppressed")));
    }

    @Test
    void ignoresOnlyTheNamedRulesWhenTheCommentListsThem(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("RiskyTool.java"), """
                package com.example;

                public class RiskyTool {

                    // mcp-sec-audit:ignore PROC_EXEC
                    @Tool
                    public void partlySuppressed(String command) throws Exception {
                        Runtime.getRuntime().exec(command);
                    }
                }
                """);

        ScanReport report = new Auditor().audit(tempDir);

        assertTrue(report.findings().stream().noneMatch(f -> f.ruleId().equals("PROC_EXEC")));
        assertTrue(report.findings().stream().anyMatch(f -> f.ruleId().equals("MISSING_AUTH")));
    }

    @Test
    void acceptsAnIgnoreCommentInsideTheMethodBody(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("RiskyTool.java"), """
                package com.example;

                public class RiskyTool {

                    @Tool
                    public void suppressedInline(String command) throws Exception {
                        // mcp-sec-audit:ignore PROC_EXEC - command is a fixed allowlisted binary
                        Runtime.getRuntime().exec(command);
                    }
                }
                """);

        ScanReport report = new Auditor().audit(tempDir);

        assertTrue(report.findings().stream().noneMatch(f -> f.ruleId().equals("PROC_EXEC")));
    }

    @Test
    void gradesToolsByTheirOwnModuleNotTheWholeRepo(@TempDir Path tempDir) throws IOException {
        String tool = """
                package com.example;

                public class WeatherService {

                    @Tool
                    public String forecast(String city) {
                        return city;
                    }
                }
                """;

        Path webModule = tempDir.resolve("web-server");
        Files.createDirectories(webModule.resolve("src/main/java"));
        Files.writeString(webModule.resolve("pom.xml"), """
                <project><dependencies><dependency>
                    <artifactId>spring-ai-starter-mcp-server-webmvc</artifactId>
                </dependency></dependencies></project>
                """);
        Files.writeString(webModule.resolve("src/main/java/WeatherService.java"), tool);

        Path stdioModule = tempDir.resolve("stdio-server");
        Files.createDirectories(stdioModule.resolve("src/main/java"));
        Files.writeString(stdioModule.resolve("pom.xml"),
                "<project><artifactId>stdio-server</artifactId></project>");
        Files.writeString(stdioModule.resolve("src/main/java/WeatherService.java"), tool);

        ScanReport report = new Auditor().audit(tempDir);

        List<Finding> auth = report.findings().stream()
                .filter(f -> f.ruleId().equals("MISSING_AUTH"))
                .toList();

        assertEquals(2, auth.size(), auth.toString());
        assertTrue(auth.stream().anyMatch(
                f -> f.filePath().contains("web-server") && f.severity() == Severity.HIGH), auth.toString());
        assertTrue(auth.stream().anyMatch(
                f -> f.filePath().contains("stdio-server") && f.severity() == Severity.LOW), auth.toString());
    }
}
