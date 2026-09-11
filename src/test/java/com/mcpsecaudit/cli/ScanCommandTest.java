package com.mcpsecaudit.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    @Test
    void scansASingleJavaFileGivenDirectly(@TempDir Path tempDir) throws IOException {
        writeVulnerableTool(tempDir);
        Path jsonFile = tempDir.resolve("report.json");

        int exitCode = new CommandLine(new ScanCommand())
                .execute(tempDir.resolve("VulnerableTool.java").toString(), "--json", jsonFile.toString());

        assertEquals(0, exitCode);
        assertTrue(Files.readString(jsonFile).contains("PROC_EXEC"),
                "scanning a single file must not silently report nothing");
    }

    @Test
    void refusesAPathThatDoesNotExistWithoutADump(@TempDir Path tempDir) {
        StringWriter err = new StringWriter();

        int exitCode = new CommandLine(new ScanCommand())
                .setErr(new PrintWriter(err))
                .execute(tempDir.resolve("nope").toString());

        assertEquals(CommandLine.ExitCode.USAGE, exitCode);
        assertTrue(err.toString().contains("no such file or directory"), err.toString());
        assertFalse(err.toString().contains("\tat "), "must not print a stack trace: " + err);
    }

    @Test
    void refusesAFileThatIsNotJavaSource(@TempDir Path tempDir) throws IOException {
        Path notJava = tempDir.resolve("pom.xml");
        Files.writeString(notJava, "<project/>");
        StringWriter err = new StringWriter();

        int exitCode = new CommandLine(new ScanCommand())
                .setErr(new PrintWriter(err))
                .execute(notJava.toString());

        assertEquals(CommandLine.ExitCode.USAGE, exitCode);
        assertTrue(err.toString().contains("not a Java source file"), err.toString());
    }

    @Test
    void writesASarifReportWhenAskedTo(@TempDir Path tempDir) throws IOException {
        writeVulnerableTool(tempDir);
        Path sarifFile = tempDir.resolve("report.sarif");

        int exitCode = new CommandLine(new ScanCommand())
                .execute(tempDir.toString(), "--sarif", sarifFile.toString());

        assertEquals(0, exitCode);
        String sarif = Files.readString(sarifFile);
        assertTrue(sarif.contains("\"version\" : \"2.1.0\""), sarif);
        assertTrue(sarif.contains("PROC_EXEC"), sarif);
        assertTrue(sarif.contains("\"level\" : \"error\""), sarif);
    }

    @Test
    void recordsKnownFindingsAndStopsGatingOnThem(@TempDir Path tempDir) throws IOException {
        writeVulnerableTool(tempDir);
        Path baseline = tempDir.resolve("baseline.txt");

        int recording = new CommandLine(new ScanCommand())
                .execute(tempDir.toString(), "--write-baseline", baseline.toString());

        assertEquals(0, recording);
        assertTrue(Files.readString(baseline).contains("PROC_EXEC"), Files.readString(baseline));

        // the same code, now known: the gate must no longer trip
        int gated = new CommandLine(new ScanCommand())
                .execute(tempDir.toString(), "--baseline", baseline.toString(), "--fail-on-critical");

        assertEquals(0, gated, "a baselined finding must not fail the build");
    }

    @Test
    void stillGatesOnFindingsTheBaselineDoesNotKnow(@TempDir Path tempDir) throws IOException {
        writeVulnerableTool(tempDir);
        Path baseline = tempDir.resolve("baseline.txt");
        new CommandLine(new ScanCommand())
                .execute(tempDir.toString(), "--write-baseline", baseline.toString());

        // somebody adds a second tool that shells out
        Files.writeString(tempDir.resolve("OtherTool.java"), """
                package com.example;

                public class OtherTool {

                    @Tool
                    public void alsoRuns(String command) throws Exception {
                        Runtime.getRuntime().exec(command);
                    }
                }
                """);

        int gated = new CommandLine(new ScanCommand())
                .execute(tempDir.toString(), "--baseline", baseline.toString(), "--fail-on-critical");

        assertEquals(1, gated, "a finding absent from the baseline must still fail the build");
    }
}
