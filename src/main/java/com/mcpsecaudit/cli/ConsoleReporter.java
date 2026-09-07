package com.mcpsecaudit.cli;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.ScanReport;
import com.mcpsecaudit.model.Severity;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ConsoleReporter {

    private static final List<Severity> SEVERITY_ORDER = List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW);

    public String format(ScanReport report) {
        StringBuilder output = new StringBuilder();
        output.append("Scanned: ").append(report.scannedPath()).append(System.lineSeparator());
        output.append("At: ").append(report.scannedAt()).append(System.lineSeparator());
        output.append(System.lineSeparator());

        List<Finding> findings = sortedBySeverityThenLocation(report);

        if (findings.isEmpty()) {
            output.append("No findings.").append(System.lineSeparator());
            return output.toString();
        }

        output.append(findings.size()).append(" finding(s):")
                .append(System.lineSeparator()).append(System.lineSeparator());

        for (Finding finding : findings) {
            appendFinding(output, finding);
        }

        output.append("Summary: ").append(summarize(findings)).append(System.lineSeparator());

        return output.toString();
    }

    private List<Finding> sortedBySeverityThenLocation(ScanReport report) {
        return report.findings().stream()
                .sorted(Comparator.comparingInt((Finding f) -> SEVERITY_ORDER.indexOf(f.severity()))
                        .thenComparing(Finding::filePath)
                        .thenComparingInt(Finding::line))
                .toList();
    }

    private void appendFinding(StringBuilder output, Finding finding) {
        output.append("[%s] %s  %s:%d  %s#%s".formatted(
                finding.severity(), finding.ruleId(), finding.filePath(), finding.line(),
                finding.className(), finding.methodName()
        )).append(System.lineSeparator());
        output.append("  ").append(finding.message()).append(System.lineSeparator());
        output.append(System.lineSeparator());
    }

    private String summarize(List<Finding> findings) {
        Map<Severity, Long> counts = findings.stream()
                .collect(Collectors.groupingBy(Finding::severity, Collectors.counting()));

        return SEVERITY_ORDER.stream()
                .filter(counts::containsKey)
                .map(severity -> counts.get(severity) + " " + severity)
                .collect(Collectors.joining(", "));
    }
}
