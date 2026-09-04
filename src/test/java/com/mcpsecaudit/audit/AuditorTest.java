package com.mcpsecaudit.audit;

import com.mcpsecaudit.model.ScanReport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

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
}
