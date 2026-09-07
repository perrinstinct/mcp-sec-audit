package com.mcpsecaudit.cli;

import com.mcpsecaudit.McpSecAudit;
import com.mcpsecaudit.audit.Auditor;
import com.mcpsecaudit.model.ScanReport;
import com.mcpsecaudit.model.Severity;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(
        name = McpSecAudit.NAME,
        mixinStandardHelpOptions = true,
        version = "mcp-sec-audit 0.1.0",
        description = "Scans Spring Boot / Spring AI source code for MCP tool methods exposed without protection."
)
public class ScanCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Directory containing Java source files to scan")
    private Path path;

    @Option(names = "--json", description = "Write the JSON report to this file")
    private Path jsonOutput;

    @Option(names = "--fail-on-critical", description = "Exit with status 1 if any CRITICAL finding is found")
    private boolean failOnCritical;

    @Option(names = "--include-tests", description = "Also scan sources under src/test (skipped by default)")
    private boolean includeTests;

    @Override
    public Integer call() throws Exception {
        ScanReport report = new Auditor(includeTests).audit(path);

        System.out.println(new ConsoleReporter().format(report));

        if (jsonOutput != null) {
            new JsonReportWriter().write(report, jsonOutput);
        }

        boolean hasCritical = report.findings().stream()
                .anyMatch(finding -> finding.severity() == Severity.CRITICAL);

        return (failOnCritical && hasCritical) ? 1 : 0;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new ScanCommand()).execute(args);
        System.exit(exitCode);
    }
}
