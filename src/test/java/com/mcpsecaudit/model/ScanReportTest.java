package com.mcpsecaudit.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ScanReportTest {

    private Finding sampleFinding() {
        return new Finding("PROC_EXEC", Severity.CRITICAL, "msg", "File.java", 1, "C", "m");
    }

    @Test
    void storesScannedPathAndTimestampAndFindings() {
        Instant now = Instant.now();
        ScanReport report = new ScanReport("/repo", now, List.of(sampleFinding()));

        assertEquals("/repo", report.scannedPath());
        assertEquals(now, report.scannedAt());
        assertEquals(1, report.findings().size());
    }

    @Test
    void findingsListIsImmutable() {
        ScanReport report = new ScanReport("/repo", Instant.now(), new ArrayList<>(List.of(sampleFinding())));

        assertThrows(UnsupportedOperationException.class, () -> report.findings().add(sampleFinding()));
    }

    @Test
    void rejectsNullFindings() {
        assertThrows(NullPointerException.class, () -> new ScanReport("/repo", Instant.now(), null));
    }

    @Test
    void rejectsBlankScannedPath() {
        assertThrows(IllegalArgumentException.class, () -> new ScanReport("", Instant.now(), List.of()));
    }
}
