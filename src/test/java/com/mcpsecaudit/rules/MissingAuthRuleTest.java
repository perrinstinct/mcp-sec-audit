package com.mcpsecaudit.rules;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.Severity;
import com.mcpsecaudit.scanner.McpToolScanner;
import com.mcpsecaudit.scanner.ProjectContext;
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

        List<Finding> findings = evaluate(tempDir, ProjectContext.httpExposure("test"));

        assertEquals(1, findings.size());
        assertEquals("MISSING_AUTH", findings.get(0).ruleId());
        assertEquals("unprotectedMethod", findings.get(0).methodName());
    }

    @Test
    void reportsHighWhenTheProjectIsReachableOverHttp(@TempDir Path tempDir) throws IOException {
        writeUnprotectedTool(tempDir);

        List<Finding> findings = evaluate(tempDir,
                ProjectContext.httpExposure("spring-boot-starter-web dependency in pom.xml"));

        assertEquals(1, findings.size());
        assertEquals(Severity.HIGH, findings.get(0).severity());
        assertTrue(findings.get(0).message().contains("spring-boot-starter-web"));
    }

    @Test
    void lowersToLowWhenNoHttpExposureIsDetected(@TempDir Path tempDir) throws IOException {
        writeUnprotectedTool(tempDir);

        List<Finding> findings = evaluate(tempDir, ProjectContext.noHttpExposure());

        assertEquals(1, findings.size());
        assertEquals(Severity.LOW, findings.get(0).severity());
        assertTrue(findings.get(0).message().contains("stdio"));
    }

    @Test
    void ruleIdIsMissingAuth() {
        assertEquals("MISSING_AUTH", new MissingAuthRule().ruleId());
    }

    private void writeUnprotectedTool(Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("UnprotectedTool.java"), """
                package com.example;

                public class UnprotectedTool {

                    @Tool
                    public void unprotectedMethod() {
                    }
                }
                """);
    }

    private List<Finding> evaluate(Path tempDir, ProjectContext project) throws IOException {
        List<ToolMethod> toolMethods = new McpToolScanner().scan(tempDir);
        SecurityRule rule = new MissingAuthRule();

        return toolMethods.stream()
                .flatMap(toolMethod -> rule.evaluate(toolMethod, project).stream())
                .toList();
    }
}
