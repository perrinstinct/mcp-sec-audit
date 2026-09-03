package com.mcpsecaudit.model;

import java.time.Instant;
import java.util.List;

public record ScanReport(
        String scannedPath,
        Instant scannedAt,
        List<Finding> findings
) {
    public ScanReport {
        if (scannedPath == null || scannedPath.isBlank()) {
            throw new IllegalArgumentException("scannedPath must not be blank");
        }
        if (scannedAt == null) {
            throw new IllegalArgumentException("scannedAt must not be null");
        }
        findings = List.copyOf(findings);
    }
}
