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

class NetAccessRuleTest {

    @Test
    void flagsSocketUrlAndHttpClientUsage(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("NetTool.java"), """
                package com.example;

                public class NetTool {

                    @Tool
                    public void connectSocket(String host, int port) throws Exception {
                        Socket socket = new Socket(host, port);
                    }

                    @Tool
                    public void connectUrl(String urlString) throws Exception {
                        URL url = new URL(urlString);
                    }

                    @Tool
                    public void connectHttpClient() {
                        HttpClient client = HttpClient.newHttpClient();
                    }

                    @Tool
                    public String safeEcho(String message) {
                        return message;
                    }
                }
                """);

        List<ToolMethod> toolMethods = new McpToolScanner().scan(tempDir);
        SecurityRule rule = new NetAccessRule();

        List<Finding> findings = toolMethods.stream()
                .flatMap(toolMethod -> rule.evaluate(toolMethod).stream())
                .toList();

        assertEquals(3, findings.size());
        assertTrue(findings.stream().allMatch(f -> f.ruleId().equals("NET_ACCESS")));
        assertTrue(findings.stream().allMatch(f -> f.severity() == Severity.MEDIUM));
        assertEquals(1, findings.stream().filter(f -> f.methodName().equals("connectSocket")).count());
        assertEquals(1, findings.stream().filter(f -> f.methodName().equals("connectUrl")).count());
        assertEquals(1, findings.stream().filter(f -> f.methodName().equals("connectHttpClient")).count());
        assertTrue(findings.stream().noneMatch(f -> f.methodName().equals("safeEcho")));
    }

    @Test
    void ruleIdIsNetAccess() {
        assertEquals("NET_ACCESS", new NetAccessRule().ruleId());
    }
}
