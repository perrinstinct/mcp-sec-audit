package com.mcpsecaudit.rules;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.Severity;
import com.mcpsecaudit.scanner.McpToolScanner;
import com.mcpsecaudit.scanner.ToolMethod;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MissingAuthRuleTest {

    @Test
    void flagsMethodsWithoutAuthAnnotationAtMethodOrClassLevel(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("UnprotectedTool.java"), """
                package com.example;

                public class UnprotectedTool {

                    @Tool
                    public void unprotectedMethod() {
                    }

                    @PreAuthorize("hasRole('ADMIN')")
                    @Tool
                    public void methodLevelProtected() {
                    }
                }
                """);

        Files.writeString(tempDir.resolve("ClassProtectedTool.java"), """
                package com.example;

                @Secured("ROLE_ADMIN")
                public class ClassProtectedTool {

                    @Tool
                    public void classLevelProtected() {
                    }
                }
                """);

        List<ToolMethod> toolMethods = new McpToolScanner().scan(tempDir);
        SecurityRule rule = new MissingAuthRule();

        List<Finding> findings = toolMethods.stream()
                .flatMap(toolMethod -> rule.evaluate(toolMethod).stream())
                .toList();

        assertEquals(1, findings.size());
        Finding finding = findings.get(0);
        assertEquals("MISSING_AUTH", finding.ruleId());
        assertEquals(Severity.HIGH, finding.severity());
        assertEquals("unprotectedMethod", finding.methodName());
    }

    @Test
    void ruleIdIsMissingAuth() {
        assertEquals("MISSING_AUTH", new MissingAuthRule().ruleId());
    }
}
