package com.mcpsecaudit.cli;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.ScanReport;
import com.mcpsecaudit.model.Severity;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConsoleReporterTest {

    @Test
    void formatsFindingsSortedBySeverityWithSummary() {
        ScanReport report = new ScanReport("/repo", Instant.parse("2026-01-01T00:00:00Z"), List.of(
                new Finding("MISSING_AUTH", Severity.HIGH, "no auth", "Tool.java", 10, "Tool", "run"),
                new Finding("PROC_EXEC", Severity.CRITICAL, "danger", "Tool.java", 12, "Tool", "run")
        ));

        String output = new ConsoleReporter().format(report);

        assertTrue(output.contains("/repo"));
        assertTrue(output.contains("2 finding(s)"));
        assertTrue(output.contains("[CRITICAL] PROC_EXEC"));
        assertTrue(output.contains("[HIGH] MISSING_AUTH"));
        assertTrue(output.contains("Tool.java:12"));
        assertTrue(output.contains("Summary: 1 CRITICAL, 1 HIGH"));
        assertTrue(output.indexOf("CRITICAL") < output.indexOf("HIGH"));
    }

    @Test
    void formatsEmptyReport() {
        ScanReport report = new ScanReport("/repo", Instant.now(), List.of());

        String output = new ConsoleReporter().format(report);

        assertTrue(output.contains("No findings."));
    }

    @Test
    void groupsRepeatedFindingsOfOneRuleWithinOneToolMethod() {
        ScanReport report = new ScanReport("/repo", Instant.parse("2026-01-01T00:00:00Z"), List.of(
                new Finding("FS_ACCESS", Severity.HIGH, "Paths.get() ...", "Doc.java", 51, "Doc", "read"),
                new Finding("FS_ACCESS", Severity.HIGH, "Files.exists() ...", "Doc.java", 52, "Doc", "read"),
                new Finding("FS_ACCESS", Severity.HIGH, "Files.readString() ...", "Doc.java", 57, "Doc", "read"),
                new Finding("FS_ACCESS", Severity.HIGH, "Files.writeString() ...", "Doc.java", 77, "Doc", "edit")
        ));

        String output = new ConsoleReporter().format(report);

        // one entry per (rule, severity, tool method) - three occurrences are one fix
        assertEquals(1, output.lines().filter(line -> line.contains("Doc#read")).count(), output);
        assertEquals(1, output.lines().filter(line -> line.contains("Doc#edit")).count(), output);
        assertTrue(output.contains("Doc.java:51"), output);
        assertTrue(output.contains("also at lines 52, 57"), output);
        // the raw count stays honest
        assertTrue(output.contains("4 finding(s)"), output);
        assertTrue(output.contains("Summary: 4 HIGH"), output);
    }

    @Test
    void keepsDifferentSeveritiesOfOneRuleApart() {
        ScanReport report = new ScanReport("/repo", Instant.parse("2026-01-01T00:00:00Z"), List.of(
                new Finding("FS_ACCESS", Severity.HIGH, "tainted", "Doc.java", 10, "Doc", "read"),
                new Finding("FS_ACCESS", Severity.MEDIUM, "hardcoded", "Doc.java", 20, "Doc", "read")
        ));

        String output = new ConsoleReporter().format(report);

        assertEquals(2, output.lines().filter(line -> line.contains("Doc#read")).count(), output);
    }
}
