package com.mcpsecaudit.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpsecaudit.McpSecAudit;
import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.ScanReport;
import com.mcpsecaudit.model.Severity;
import com.mcpsecaudit.rules.FsAccessRule;
import com.mcpsecaudit.rules.MissingAuthRule;
import com.mcpsecaudit.rules.NetAccessRule;
import com.mcpsecaudit.rules.ProcExecRule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Writes findings as SARIF 2.1.0, the format GitHub Code Scanning ingests to raise alerts
 * in the Security tab and annotate pull request diffs inline.
 *
 * <p>SARIF only has three levels, so the four severities are projected onto them. The
 * per-result {@code level} carries the real grading; {@code security-severity} is attached
 * per result rather than per rule, because the same rule is CRITICAL or HIGH depending on
 * whether a tool parameter reaches the sink, and a rule-level number would badge every
 * hardcoded call as if it were exploitable.
 */
public class SarifReportWriter {

    private static final String SCHEMA =
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

    private static final String INFORMATION_URI = "https://github.com/perrinstinct/mcp-sec-audit";

    private record RuleDoc(String shortDescription, String fullDescription) {
    }

    private static final Map<String, RuleDoc> RULE_DOCS = Map.of(
            ProcExecRule.RULE_ID, new RuleDoc(
                    "MCP tool executes an OS command",
                    "The tool method runs a process. If a tool parameter reaches the command, the model "
                            + "decides what is executed on the host."),
            FsAccessRule.RULE_ID, new RuleDoc(
                    "MCP tool reads or writes the filesystem",
                    "The tool method touches files. If a tool parameter reaches the path, the model "
                            + "decides which file is read or written."),
            NetAccessRule.RULE_ID, new RuleDoc(
                    "MCP tool makes network calls",
                    "The tool method performs network I/O. If a tool parameter reaches the target, the "
                            + "model decides what the server connects to."),
            MissingAuthRule.RULE_ID, new RuleDoc(
                    "MCP tool has no authorization annotation",
                    "Neither the tool method nor its class carries @PreAuthorize, @Secured or "
                            + "@RolesAllowed, so any client reaching the server can invoke it.")
    );

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * @param uriBase directory the reported URIs are made relative to - the repository root,
     *                so that GitHub can match each result to a file in the checkout
     */
    public void write(ScanReport report, Path outputFile, Path uriBase) throws IOException {
        ObjectNode sarif = mapper.createObjectNode();
        sarif.put("$schema", SCHEMA);
        sarif.put("version", "2.1.0");

        ObjectNode run = sarif.putArray("runs").addObject();
        run.putObject("tool").set("driver", driver(report));
        run.set("results", results(report, uriBase));

        mapper.writerWithDefaultPrettyPrinter().writeValue(outputFile.toFile(), sarif);
    }

    private ObjectNode driver(ScanReport report) {
        ObjectNode driver = mapper.createObjectNode();
        driver.put("name", McpSecAudit.NAME);
        driver.put("version", VersionProvider.version());
        driver.put("informationUri", INFORMATION_URI);

        ArrayNode rules = driver.putArray("rules");
        for (String ruleId : distinctRuleIds(report)) {
            ObjectNode rule = rules.addObject();
            rule.put("id", ruleId);
            rule.put("name", ruleId);
            RuleDoc doc = RULE_DOCS.get(ruleId);
            if (doc != null) {
                rule.putObject("shortDescription").put("text", doc.shortDescription());
                rule.putObject("fullDescription").put("text", doc.fullDescription());
            }
        }
        return driver;
    }

    private Set<String> distinctRuleIds(ScanReport report) {
        Set<String> ruleIds = new LinkedHashSet<>();
        report.findings().forEach(finding -> ruleIds.add(finding.ruleId()));
        return ruleIds;
    }

    private ArrayNode results(ScanReport report, Path uriBase) {
        ArrayNode results = mapper.createArrayNode();
        for (Finding finding : report.findings()) {
            ObjectNode result = results.addObject();
            result.put("ruleId", finding.ruleId());
            result.put("level", levelOf(finding.severity()));
            result.putObject("message").put("text", finding.message());
            result.putObject("properties")
                    .put("security-severity", securitySeverityOf(finding.severity()))
                    .put("tool-method", finding.className() + "#" + finding.methodName());

            ObjectNode physicalLocation = result.putArray("locations").addObject()
                    .putObject("physicalLocation");
            physicalLocation.putObject("artifactLocation")
                    .put("uri", uriOf(report, finding, uriBase))
                    .put("uriBaseId", "%SRCROOT%");
            physicalLocation.putObject("region").put("startLine", finding.line());
        }
        return results;
    }

    private String levelOf(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW -> "note";
        };
    }

    private String securitySeverityOf(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "9.0";
            case HIGH -> "7.0";
            case MEDIUM -> "5.0";
            case LOW -> "3.0";
        };
    }

    /**
     * Findings carry a path relative to whatever was scanned, which GitHub cannot resolve
     * unless the scan happened to start at the repository root. Rebase onto uriBase.
     */
    private String uriOf(ScanReport report, Finding finding, Path uriBase) {
        Path scanned = Path.of(report.scannedPath()).toAbsolutePath();
        Path scanRoot = Files.isRegularFile(scanned) ? scanned.getParent() : scanned;
        Path absolute = scanRoot.resolve(finding.filePath()).normalize();

        try {
            return toUri(uriBase.toAbsolutePath().normalize().relativize(absolute));
        } catch (IllegalArgumentException outsideBase) {
            return toUri(absolute);
        }
    }

    private String toUri(Path path) {
        return path.toString().replace('\\', '/');
    }
}
