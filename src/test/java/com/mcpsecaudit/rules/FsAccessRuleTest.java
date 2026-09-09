package com.mcpsecaudit.rules;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.Severity;
import com.mcpsecaudit.scanner.McpToolScanner;
import com.mcpsecaudit.scanner.ProjectContext;
import com.mcpsecaudit.scanner.ToolMethod;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FsAccessRuleTest {

    @Test
    void flagsFileInstantiationAndFilesUtilityCalls(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("FsTool.java"), """
                package com.example;

                public class FsTool {

                    @Tool
                    public void readViaFile(String path) throws Exception {
                        File file = new File(path);
                    }

                    @Tool
                    public void readViaFilesUtility(String path) throws Exception {
                        Files.readAllBytes(Paths.get(path));
                    }

                    @Tool
                    public String safeEcho(String message) {
                        return message;
                    }
                }
                """);

        List<ToolMethod> toolMethods = new McpToolScanner().scan(tempDir);
        SecurityRule rule = new FsAccessRule();

        List<Finding> findings = toolMethods.stream()
                .flatMap(toolMethod -> rule.evaluate(toolMethod, ProjectContext.noHttpExposure()).stream())
                .toList();

        assertEquals(3, findings.size());
        assertTrue(findings.stream().allMatch(f -> f.ruleId().equals("FS_ACCESS")));
        // every sink here is fed by a tool parameter, so all of them are tainted
        assertTrue(findings.stream().allMatch(f -> f.severity() == Severity.HIGH));
        assertEquals(1, findings.stream().filter(f -> f.methodName().equals("readViaFile")).count());
        assertEquals(2, findings.stream().filter(f -> f.methodName().equals("readViaFilesUtility")).count());
        assertTrue(findings.stream().noneMatch(f -> f.methodName().equals("safeEcho")));
    }

    @Test
    void ruleIdIsFsAccess() {
        assertEquals("FS_ACCESS", new FsAccessRule().ruleId());
    }

    @Test
    void separatesModelControlledPathsFromHardcodedOnes(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("Compare.java"), """
                package com.example;

                public class Compare {

                    @Tool
                    public String readAnything(String path) throws Exception {
                        return Files.readString(Paths.get(path));
                    }

                    @Tool
                    public String readChangelog() throws Exception {
                        return Files.readString(Paths.get("/opt/app/CHANGELOG.md"));
                    }

                    @Tool
                    public String readVia(String name) throws Exception {
                        String trimmed = name.trim();
                        Path target = Paths.get("/opt", trimmed);
                        return Files.readString(target);
                    }
                }
                """);

        List<ToolMethod> toolMethods = new McpToolScanner().scan(tempDir);
        SecurityRule rule = new FsAccessRule();
        List<Finding> findings = toolMethods.stream()
                .flatMap(toolMethod -> rule.evaluate(toolMethod, ProjectContext.noHttpExposure()).stream())
                .toList();

        assertTrue(findings.stream()
                        .filter(f -> f.methodName().equals("readAnything"))
                        .allMatch(f -> f.severity() == Severity.HIGH),
                "a parameter reaching the sink is exploitable");
        assertTrue(findings.stream()
                        .filter(f -> f.methodName().equals("readChangelog"))
                        .allMatch(f -> f.severity() == Severity.MEDIUM),
                "a hardcoded path is not model-controlled");
        // taint must survive being passed through local variables
        assertTrue(findings.stream()
                        .filter(f -> f.methodName().equals("readVia"))
                        .anyMatch(f -> f.severity() == Severity.HIGH && f.message().contains("name")),
                "taint must propagate through local assignments: " + findings);
    }
}
