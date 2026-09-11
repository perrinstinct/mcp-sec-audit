package com.mcpsecaudit.cli;

import com.mcpsecaudit.McpSecAudit;
import com.mcpsecaudit.audit.Auditor;
import com.mcpsecaudit.model.ScanReport;
import com.mcpsecaudit.model.Severity;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.Callable;

@Command(
        name = McpSecAudit.NAME,
        mixinStandardHelpOptions = true,
        versionProvider = VersionProvider.class,
        description = "Scans Spring Boot / Spring AI source code for MCP tool methods exposed without protection."
)
public class ScanCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Directory to scan, or a single .java file")
    private Path path;

    @Option(names = "--json", description = "Write the JSON report to this file")
    private Path jsonOutput;

    @Option(names = "--sarif",
            description = "Write a SARIF 2.1.0 report to this file, for GitHub Code Scanning")
    private Path sarifOutput;

    @Option(names = "--baseline",
            description = "Ignore findings recorded in this baseline file")
    private Path baselineFile;

    @Option(names = "--write-baseline",
            description = "Record the current findings as a baseline in this file and exit 0")
    private Path baselineToWrite;

    @Option(names = "--fail-on-critical", description = "Exit with status 1 if any CRITICAL finding is found")
    private boolean failOnCritical;

    @Option(names = "--include-tests", description = "Also scan sources under src/test (skipped by default)")
    private boolean includeTests;

    @CommandLine.Spec
    private CommandLine.Model.CommandSpec spec;

    @Override
    public Integer call() {
        Optional<String> rejection = reasonToReject(path);
        if (rejection.isPresent()) {
            spec.commandLine().getErr().println(McpSecAudit.NAME + ": " + rejection.get());
            return CommandLine.ExitCode.USAGE;
        }

        ScanReport report;
        try {
            report = new Auditor(includeTests).audit(path);
        } catch (IOException e) {
            spec.commandLine().getErr().println(
                    McpSecAudit.NAME + ": cannot read " + path + ": " + e.getMessage());
            return CommandLine.ExitCode.USAGE;
        }

        if (baselineToWrite != null) {
            try {
                Baseline.of(report).writeTo(baselineToWrite);
            } catch (IOException e) {
                spec.commandLine().getErr().println(
                        McpSecAudit.NAME + ": cannot write " + baselineToWrite + ": " + e.getMessage());
                return CommandLine.ExitCode.USAGE;
            }
            spec.commandLine().getOut().println("Recorded " + report.findings().size()
                    + " finding(s) as a baseline in " + baselineToWrite);
            return 0;
        }

        if (baselineFile != null) {
            Baseline baseline;
            try {
                baseline = Baseline.readFrom(baselineFile);
            } catch (IOException e) {
                spec.commandLine().getErr().println(
                        McpSecAudit.NAME + ": cannot read " + baselineFile + ": " + e.getMessage());
                return CommandLine.ExitCode.USAGE;
            }
            int before = report.findings().size();
            report = baseline.filter(report);
            int suppressed = before - report.findings().size();
            if (suppressed > 0) {
                spec.commandLine().getOut().println(
                        suppressed + " finding(s) suppressed by " + baselineFile);
            }
        }

        spec.commandLine().getOut().println(new ConsoleReporter().format(report));

        if (jsonOutput != null) {
            try {
                new JsonReportWriter().write(report, jsonOutput);
            } catch (IOException e) {
                spec.commandLine().getErr().println(
                        McpSecAudit.NAME + ": cannot write " + jsonOutput + ": " + e.getMessage());
                return CommandLine.ExitCode.USAGE;
            }
        }

        if (sarifOutput != null) {
            try {
                // URIs are rebased on the working directory, which in CI is the checkout root
                new SarifReportWriter().write(report, sarifOutput, Path.of("").toAbsolutePath());
            } catch (IOException e) {
                spec.commandLine().getErr().println(
                        McpSecAudit.NAME + ": cannot write " + sarifOutput + ": " + e.getMessage());
                return CommandLine.ExitCode.USAGE;
            }
        }

        boolean hasCritical = report.findings().stream()
                .anyMatch(finding -> finding.severity() == Severity.CRITICAL);

        return (failOnCritical && hasCritical) ? 1 : 0;
    }

    private Optional<String> reasonToReject(Path path) {
        if (!Files.exists(path)) {
            return Optional.of(path + ": no such file or directory");
        }
        if (Files.isRegularFile(path) && !path.getFileName().toString().endsWith(".java")) {
            return Optional.of(path + ": not a Java source file (pass a .java file or a directory)");
        }
        if (!Files.isRegularFile(path) && !Files.isDirectory(path)) {
            return Optional.of(path + ": not a regular file or directory");
        }
        if (!Files.isReadable(path)) {
            return Optional.of(path + ": permission denied");
        }
        return Optional.empty();
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new ScanCommand())
                // Users get a message, never a Java stack trace.
                .setExecutionExceptionHandler((exception, command, parseResult) -> {
                    command.getErr().println(McpSecAudit.NAME + ": " + exception);
                    return CommandLine.ExitCode.SOFTWARE;
                })
                .execute(args);
        System.exit(exitCode);
    }
}
