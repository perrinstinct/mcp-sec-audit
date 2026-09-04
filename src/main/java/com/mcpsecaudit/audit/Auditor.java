package com.mcpsecaudit.audit;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.ScanReport;
import com.mcpsecaudit.rules.FsAccessRule;
import com.mcpsecaudit.rules.MissingAuthRule;
import com.mcpsecaudit.rules.NetAccessRule;
import com.mcpsecaudit.rules.ProcExecRule;
import com.mcpsecaudit.rules.SecurityRule;
import com.mcpsecaudit.scanner.McpToolScanner;
import com.mcpsecaudit.scanner.ToolMethod;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

public class Auditor {

    private final McpToolScanner scanner;
    private final List<SecurityRule> rules;

    public Auditor() {
        this(new McpToolScanner(), List.of(
                new ProcExecRule(), new FsAccessRule(), new NetAccessRule(), new MissingAuthRule()
        ));
    }

    public Auditor(McpToolScanner scanner, List<SecurityRule> rules) {
        this.scanner = scanner;
        this.rules = List.copyOf(rules);
    }

    public ScanReport audit(Path rootDirectory) throws IOException {
        List<ToolMethod> toolMethods = scanner.scan(rootDirectory);

        List<Finding> findings = toolMethods.stream()
                .flatMap(toolMethod -> rules.stream().flatMap(rule -> rule.evaluate(toolMethod).stream()))
                .toList();

        return new ScanReport(rootDirectory.toString(), Instant.now(), findings);
    }
}
