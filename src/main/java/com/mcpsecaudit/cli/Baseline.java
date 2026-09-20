package com.mcpsecaudit.cli;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.ScanReport;
import com.mcpsecaudit.model.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * A snapshot of the findings a codebase already had, so adopting the tool does not mean
 * fixing everything first: recorded findings stay quiet and only new ones fail the build.
 *
 * <p>Entries deliberately exclude the line number. Keying on a line would mean that adding
 * an import at the top of a file invalidates every entry below it, which is how baselines
 * usually rot. Severity is recorded on purpose: a finding escalating from MEDIUM to HIGH -
 * a tool parameter now reaching the sink - is a real change in risk and must resurface even
 * though the rule and method are unchanged. Only a rise resurfaces, though: a finding that
 * drops to LOW is the same known problem, judged less severe than when it was recorded.
 *
 * <p>Written sorted and without a timestamp, because this file gets reviewed in pull
 * requests and a noisy diff defeats the point.
 */
public final class Baseline {

    private static final String HEADER = """
            # mcp-sec-audit baseline
            # Findings listed here are known and will not be reported.
            # Format: RULE_ID|SEVERITY|file|Class#method
            # Regenerate with: mcp-sec-audit <path> --write-baseline <this file>
            """;

    private static final String SEPARATOR = "|";

    private final Set<String> entries;

    /** Where a finding was recorded, mapped to the worst severity recorded for it. */
    private final Map<String, Severity> recorded;

    private Baseline(Set<String> entries) {
        this.entries = entries;
        this.recorded = index(entries);
    }

    private static Map<String, Severity> index(Set<String> entries) {
        Map<String, Severity> recorded = new HashMap<>();
        for (String entry : entries) {
            String[] fields = entry.split(Pattern.quote(SEPARATOR));
            if (fields.length != 4) {
                continue;  // hand-edited into something unreadable: better reported than hidden
            }
            severityNamed(fields[1]).ifPresent(severity -> recorded.merge(
                    String.join(SEPARATOR, fields[0], fields[2], fields[3]),
                    severity,
                    (recordedSeverity, other) -> recordedSeverity.compareTo(other) >= 0
                            ? recordedSeverity : other));
        }
        return recorded;
    }

    private static Optional<Severity> severityNamed(String name) {
        try {
            return Optional.of(Severity.valueOf(name));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public static Baseline of(ScanReport report) {
        Set<String> entries = new TreeSet<>();
        report.findings().forEach(finding -> entries.add(entryFor(finding)));
        return new Baseline(entries);
    }

    public static Baseline readFrom(Path file) throws IOException {
        Set<String> entries = new LinkedHashSet<>();
        for (String line : Files.readAllLines(file)) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                entries.add(trimmed);
            }
        }
        return new Baseline(entries);
    }

    public static Baseline empty() {
        return new Baseline(Set.of());
    }

    public void writeTo(Path file) throws IOException {
        Files.writeString(file, HEADER + String.join(System.lineSeparator(), entries)
                + System.lineSeparator());
    }

    public boolean covers(Finding finding) {
        Severity known = recorded.get(locationOf(finding));
        return known != null && known.compareTo(finding.severity()) >= 0;
    }

    public int size() {
        return entries.size();
    }

    /** The report without anything the baseline already knows about. */
    public ScanReport filter(ScanReport report) {
        List<Finding> remaining = report.findings().stream()
                .filter(finding -> !covers(finding))
                .toList();
        return new ScanReport(report.scannedPath(), report.scannedAt(), remaining);
    }

    private static String entryFor(Finding finding) {
        return String.join(SEPARATOR,
                finding.ruleId(),
                finding.severity().name(),
                finding.filePath(),
                finding.className() + "#" + finding.methodName());
    }

    /** The same entry without the severity: what identifies the finding across gradings. */
    private static String locationOf(Finding finding) {
        return String.join(SEPARATOR,
                finding.ruleId(),
                finding.filePath(),
                finding.className() + "#" + finding.methodName());
    }
}
