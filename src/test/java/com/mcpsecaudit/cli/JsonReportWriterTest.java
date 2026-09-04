package com.mcpsecaudit.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonReportWriterTest {

    @Test
    void writesAJsonFileThatRoundTripsBackToTheSameScanReport(@TempDir Path tempDir) throws IOException {
        ScanReport report = new ScanReport("/repo", Instant.parse("2026-01-01T00:00:00Z"), List.of(
                new Finding("PROC_EXEC", Severity.CRITICAL, "danger", "Tool.java", 10, "Tool", "run")
        ));
        Path jsonFile = tempDir.resolve("report.json");

        new JsonReportWriter().write(report, jsonFile);

        assertTrue(Files.exists(jsonFile));
        assertTrue(Files.readString(jsonFile).contains("PROC_EXEC"));

        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        ScanReport readBack = mapper.readValue(jsonFile.toFile(), ScanReport.class);

        assertEquals(report, readBack);
    }
}
