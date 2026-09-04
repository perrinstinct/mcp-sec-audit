package com.mcpsecaudit.rules;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.Severity;
import com.mcpsecaudit.scanner.McpToolScanner;
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
                .flatMap(toolMethod -> rule.evaluate(toolMethod).stream())
                .toList();

        assertEquals(3, findings.size());
        assertTrue(findings.stream().allMatch(f -> f.ruleId().equals("FS_ACCESS")));
        assertTrue(findings.stream().allMatch(f -> f.severity() == Severity.MEDIUM));
        assertEquals(1, findings.stream().filter(f -> f.methodName().equals("readViaFile")).count());
        assertEquals(2, findings.stream().filter(f -> f.methodName().equals("readViaFilesUtility")).count());
        assertTrue(findings.stream().noneMatch(f -> f.methodName().equals("safeEcho")));
    }

    @Test
    void ruleIdIsFsAccess() {
        assertEquals("FS_ACCESS", new FsAccessRule().ruleId());
    }
}
