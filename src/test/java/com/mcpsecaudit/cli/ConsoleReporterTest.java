package com.mcpsecaudit.cli;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.ScanReport;
import com.mcpsecaudit.model.Severity;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

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
}
