package com.mcpsecaudit.cli;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.ScanReport;
import com.mcpsecaudit.model.Severity;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ConsoleReporter {

    private static final List<Severity> SEVERITY_ORDER =
            List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW);

    /**
     * One line per thing to fix. Several findings of the same rule in the same tool method
     * are one problem - validate the parameter once and they all go - so they are shown
     * together. The JSON report keeps every location, which is what SARIF consumers and
     * PR annotations need.
     */
    private record Group(String ruleId, Severity severity, String filePath, String className, String methodName) {

        static Group of(Finding finding) {
            return new Group(finding.ruleId(), finding.severity(), finding.filePath(),
                    finding.className(), finding.methodName());
        }
    }

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

        output.append(findings.size()).append(" finding(s), grouped by tool method:")
                .append(System.lineSeparator()).append(System.lineSeparator());

        groupByToolMethod(findings).values().forEach(group -> appendGroup(output, group));

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

    private Map<Group, List<Finding>> groupByToolMethod(List<Finding> findings) {
        return findings.stream().collect(Collectors.groupingBy(
                Group::of, LinkedHashMap::new, Collectors.toList()));
    }

    private void appendGroup(StringBuilder output, List<Finding> group) {
        Finding first = group.get(0);
        output.append("[%s] %s  %s:%d  %s#%s".formatted(
                first.severity(), first.ruleId(), first.filePath(), first.line(),
                first.className(), first.methodName()
        )).append(System.lineSeparator());
        output.append("  ").append(first.message()).append(System.lineSeparator());

        if (group.size() > 1) {
            String otherLines = group.stream().skip(1)
                    .map(finding -> String.valueOf(finding.line()))
                    .collect(Collectors.joining(", "));
            output.append("  also at lines ").append(otherLines).append(System.lineSeparator());
        }
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
