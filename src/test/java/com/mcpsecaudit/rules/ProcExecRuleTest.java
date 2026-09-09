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

class ProcExecRuleTest {

    @Test
    void flagsRuntimeExecAndProcessBuilder(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("VulnerableTool.java"), """
                package com.example;

                public class VulnerableTool {

                    @Tool
                    public void runCommand(String command) throws Exception {
                        Runtime.getRuntime().exec(command);
                    }

                    @Tool
                    public void spawnProcess(String command) throws Exception {
                        new ProcessBuilder(command).start();
                    }

                    @Tool
                    public String safeEcho(String message) {
                        return message;
                    }
                }
                """);

        List<ToolMethod> toolMethods = new McpToolScanner().scan(tempDir);
        SecurityRule rule = new ProcExecRule();

        List<Finding> findings = toolMethods.stream()
                .flatMap(toolMethod -> rule.evaluate(toolMethod, ProjectContext.noHttpExposure()).stream())
                .toList();

        assertEquals(2, findings.size());
        assertTrue(findings.stream().allMatch(f -> f.ruleId().equals("PROC_EXEC")));
        assertTrue(findings.stream().allMatch(f -> f.severity() == Severity.CRITICAL));
        assertTrue(findings.stream().anyMatch(f -> f.methodName().equals("runCommand")));
        assertTrue(findings.stream().anyMatch(f -> f.methodName().equals("spawnProcess")));
        assertTrue(findings.stream().noneMatch(f -> f.methodName().equals("safeEcho")));
    }

    @Test
    void ruleIdIsProcExec() {
        assertEquals("PROC_EXEC", new ProcExecRule().ruleId());
    }

    @Test
    void onlyRatesExecCriticalWhenTheModelControlsTheCommand(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("Exec.java"), """
                package com.example;

                public class Exec {

                    @Tool
                    public void runWhatever(String cmd) throws Exception {
                        Runtime.getRuntime().exec(cmd);
                    }

                    @Tool
                    public void runBackup() throws Exception {
                        Runtime.getRuntime().exec("/usr/local/bin/backup");
                    }
                }
                """);

        List<ToolMethod> toolMethods = new McpToolScanner().scan(tempDir);
        SecurityRule rule = new ProcExecRule();
        List<Finding> findings = toolMethods.stream()
                .flatMap(toolMethod -> rule.evaluate(toolMethod, ProjectContext.noHttpExposure()).stream())
                .toList();

        assertTrue(findings.stream().anyMatch(
                f -> f.methodName().equals("runWhatever") && f.severity() == Severity.CRITICAL));
        assertTrue(findings.stream().anyMatch(
                f -> f.methodName().equals("runBackup") && f.severity() == Severity.HIGH));
    }
}
