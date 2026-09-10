package com.mcpsecaudit.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SarifReportWriterTest {

    @Test
    void writesTheSarifSkeletonGitHubExpects(@TempDir Path tempDir) throws IOException {
        JsonNode sarif = write(tempDir, report(tempDir, finding(Severity.CRITICAL, "PROC_EXEC", 24)));

        assertEquals("2.1.0", sarif.get("version").asText());
        assertTrue(sarif.get("$schema").asText().contains("sarif"));
        assertEquals(1, sarif.get("runs").size());
        assertEquals("mcp-sec-audit", sarif.at("/runs/0/tool/driver/name").asText());
        assertTrue(sarif.at("/runs/0/tool/driver/version").asText().matches("\\d+\\.\\d+\\.\\d+.*"),
                sarif.at("/runs/0/tool/driver/version").asText());
    }

    @Test
    void declaresEachRuleOnceInTheCatalogue(@TempDir Path tempDir) throws IOException {
        JsonNode sarif = write(tempDir, report(tempDir,
                finding(Severity.CRITICAL, "PROC_EXEC", 10),
                finding(Severity.HIGH, "PROC_EXEC", 20),
                finding(Severity.MEDIUM, "FS_ACCESS", 30)));

        List<String> ruleIds = StreamSupport
                .stream(sarif.at("/runs/0/tool/driver/rules").spliterator(), false)
                .map(rule -> rule.get("id").asText())
                .toList();

        assertEquals(List.of("FS_ACCESS", "PROC_EXEC"), ruleIds.stream().sorted().toList());
        assertEquals(3, sarif.at("/runs/0/results").size());
    }

    @Test
    void mapsOurFourSeveritiesOntoSarifsThreeLevels(@TempDir Path tempDir) throws IOException {
        JsonNode sarif = write(tempDir, report(tempDir,
                finding(Severity.CRITICAL, "PROC_EXEC", 10),
                finding(Severity.HIGH, "FS_ACCESS", 20),
                finding(Severity.MEDIUM, "NET_ACCESS", 30),
                finding(Severity.LOW, "MISSING_AUTH", 40)));

        JsonNode results = sarif.at("/runs/0/results");
        assertEquals("error", results.get(0).get("level").asText());
        assertEquals("error", results.get(1).get("level").asText());
        assertEquals("warning", results.get(2).get("level").asText());
        assertEquals("note", results.get(3).get("level").asText());
    }

    @Test
    void locatesEachResultByFileAndLine(@TempDir Path tempDir) throws IOException {
        JsonNode sarif = write(tempDir, report(tempDir, finding(Severity.HIGH, "FS_ACCESS", 42)));

        JsonNode location = sarif.at("/runs/0/results/0/locations/0/physicalLocation");
        assertEquals(42, location.at("/region/startLine").asInt());
        assertTrue(location.at("/artifactLocation/uri").asText().endsWith("Tool.java"),
                location.toString());
    }

    @Test
    void makesUrisRelativeToTheGivenBaseSoGitHubCanMatchFiles(@TempDir Path tempDir) throws IOException {
        Path module = tempDir.resolve("server");
        Files.createDirectories(module);

        ScanReport report = new ScanReport(module.toString(), Instant.parse("2026-01-01T00:00:00Z"),
                List.of(new Finding("FS_ACCESS", Severity.HIGH, "msg",
                        "src/main/java/Tool.java", 7, "Tool", "read")));

        Path sarifFile = tempDir.resolve("out.sarif");
        // as if the tool ran from the repository root while scanning a module below it
        new SarifReportWriter().write(report, sarifFile, tempDir);

        JsonNode sarif = new ObjectMapper().readTree(sarifFile.toFile());
        assertEquals("server/src/main/java/Tool.java",
                sarif.at("/runs/0/results/0/locations/0/physicalLocation/artifactLocation/uri").asText());
    }

    private JsonNode write(Path tempDir, ScanReport report) throws IOException {
        Path sarifFile = tempDir.resolve("report.sarif");
        new SarifReportWriter().write(report, sarifFile, tempDir);
        return new ObjectMapper().readTree(sarifFile.toFile());
    }

    private ScanReport report(Path scannedPath, Finding... findings) {
        return new ScanReport(scannedPath.toString(), Instant.parse("2026-01-01T00:00:00Z"), List.of(findings));
    }

    private Finding finding(Severity severity, String ruleId, int line) {
        return new Finding(ruleId, severity, "something risky", "Tool.java", line, "Tool", "run");
    }
}
