package com.mcpsecaudit.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanCommandTest {

    @Test
    void exitsZeroByDefaultEvenWithCriticalFindings(@TempDir Path tempDir) throws IOException {
        writeVulnerableTool(tempDir);

        int exitCode = new CommandLine(new ScanCommand()).execute(tempDir.toString());

        assertEquals(0, exitCode);
    }

    @Test
    void exitsOneWithFailOnCriticalWhenCriticalFindingsExist(@TempDir Path tempDir) throws IOException {
        writeVulnerableTool(tempDir);

        int exitCode = new CommandLine(new ScanCommand())
                .execute(tempDir.toString(), "--fail-on-critical");

        assertEquals(1, exitCode);
    }

    @Test
    void exitsZeroWithFailOnCriticalWhenNoCriticalFindingExists(@TempDir Path tempDir) throws IOException {
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

        int exitCode = new CommandLine(new ScanCommand())
                .execute(tempDir.toString(), "--fail-on-critical");

        assertEquals(0, exitCode);
    }

    @Test
    void writesJsonReportWhenJsonOptionGiven(@TempDir Path tempDir) throws IOException {
        writeVulnerableTool(tempDir);
        Path jsonFile = tempDir.resolve("report.json");

        int exitCode = new CommandLine(new ScanCommand())
                .execute(tempDir.toString(), "--json", jsonFile.toString());

        assertEquals(0, exitCode);
        assertTrue(Files.exists(jsonFile));
        assertTrue(Files.readString(jsonFile).contains("PROC_EXEC"));
    }

    private void writeVulnerableTool(Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("VulnerableTool.java"), """
                package com.example;

                public class VulnerableTool {

                    @Tool
                    public void runCommand(String command) throws Exception {
                        Runtime.getRuntime().exec(command);
                    }
                }
                """);
    }
}
