package com.mcpsecaudit.cli;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.ScanReport;
import com.mcpsecaudit.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BaselineTest {

    @Test
    void suppressesOnlyTheFindingsItRecorded(@TempDir Path tempDir) throws IOException {
        ScanReport recorded = report(
                finding("FS_ACCESS", Severity.HIGH, "Doc.java", 51, "Doc", "read"));
        Path file = tempDir.resolve("baseline.txt");
        Baseline.of(recorded).writeTo(file);

        Baseline baseline = Baseline.readFrom(file);

        assertTrue(baseline.covers(finding("FS_ACCESS", Severity.HIGH, "Doc.java", 51, "Doc", "read")));
        assertFalse(baseline.covers(finding("PROC_EXEC", Severity.HIGH, "Doc.java", 51, "Doc", "read")),
                "a different rule in the same method is a new problem");
        assertFalse(baseline.covers(finding("FS_ACCESS", Severity.HIGH, "Doc.java", 51, "Doc", "write")),
                "a different method is a new problem");
    }

    @Test
    void survivesLineNumbersMovingAround(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("baseline.txt");
        Baseline.of(report(finding("FS_ACCESS", Severity.HIGH, "Doc.java", 51, "Doc", "read"))).writeTo(file);

        // somebody added an import at the top of the file
        assertTrue(Baseline.readFrom(file)
                        .covers(finding("FS_ACCESS", Severity.HIGH, "Doc.java", 57, "Doc", "read")),
                "an edit above the finding must not invalidate the baseline");
    }

    @Test
    void letsASeverityEscalationThrough(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("baseline.txt");
        Baseline.of(report(finding("FS_ACCESS", Severity.MEDIUM, "Doc.java", 51, "Doc", "read"))).writeTo(file);

        // a tool parameter now reaches the sink: the risk really did change
        assertFalse(Baseline.readFrom(file)
                        .covers(finding("FS_ACCESS", Severity.HIGH, "Doc.java", 51, "Doc", "read")),
                "escalating severity must resurface the finding");
    }

    @Test
    void keepsCoveringAFindingWhoseSeverityDropped(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("baseline.txt");
        Baseline.of(report(finding("MISSING_AUTH", Severity.HIGH, "Tool.java", 12, "Tool", "run"))).writeTo(file);

        // the endpoint turned out to authenticate: same problem, less risk than recorded
        assertTrue(Baseline.readFrom(file)
                        .covers(finding("MISSING_AUTH", Severity.LOW, "Tool.java", 12, "Tool", "run")),
                "only a rise in risk is new; a drop must stay quiet");
    }

    @Test
    void survivesAHandEditedEntry(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("baseline.txt");
        Files.writeString(file, """
                this line is not an entry
                FS_ACCESS|NOT_A_SEVERITY|Doc.java|Doc#read
                FS_ACCESS|HIGH|Doc.java|Doc#write
                """);

        Baseline baseline = Baseline.readFrom(file);

        assertTrue(baseline.covers(finding("FS_ACCESS", Severity.HIGH, "Doc.java", 4, "Doc", "write")));
        assertFalse(baseline.covers(finding("FS_ACCESS", Severity.HIGH, "Doc.java", 4, "Doc", "read")),
                "an entry nobody can read cannot silence a finding");
    }

    @Test
    void writesADiffFriendlyFile(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("baseline.txt");
        Baseline.of(report(
                finding("PROC_EXEC", Severity.CRITICAL, "Z.java", 9, "Z", "run"),
                finding("FS_ACCESS", Severity.HIGH, "A.java", 51, "A", "read"),
                finding("FS_ACCESS", Severity.HIGH, "A.java", 57, "A", "read"))).writeTo(file);

        List<String> entries = Files.readAllLines(file).stream()
                .filter(line -> !line.startsWith("#") && !line.isBlank())
                .toList();

        assertEquals(2, entries.size(), "two findings in one method are one entry: " + entries);
        assertEquals(entries.stream().sorted().toList(), entries, "entries must be sorted");
        assertTrue(Files.readString(file).startsWith("#"), "the file explains itself");
    }

    @Test
    void ignoresCommentsAndBlankLines(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("baseline.txt");
        Files.writeString(file, """
                # hand-written comment

                FS_ACCESS|HIGH|Doc.java|Doc#read
                """);

        assertTrue(Baseline.readFrom(file)
                .covers(finding("FS_ACCESS", Severity.HIGH, "Doc.java", 4, "Doc", "read")));
    }

    private ScanReport report(Finding... findings) {
        return new ScanReport("/repo", Instant.parse("2026-01-01T00:00:00Z"), List.of(findings));
    }

    private Finding finding(String ruleId, Severity severity, String file, int line,
                            String className, String methodName) {
        return new Finding(ruleId, severity, "message", file, line, className, methodName);
    }
}
