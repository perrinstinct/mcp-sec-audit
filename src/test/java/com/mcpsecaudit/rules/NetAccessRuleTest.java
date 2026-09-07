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
                .flatMap(toolMethod -> rule.evaluate(toolMethod, ProjectContext.noHttpExposure()).stream())
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

    @Test
    void flagsSpringHttpClientAbstractions(@TempDir Path tempDir) throws IOException {
        // Real-world shapes found while scanning spring-ai-examples' WeatherApiClient:
        // the HTTP client is built once (constructor/field initializer) and the @Tool
        // method only ever sees a call on the field - a local instantiation or static
        // factory call inside the method body never appears for this pattern.
        Files.writeString(tempDir.resolve("SpringHttpTool.java"), """
                package com.example;

                public class SpringHttpTool {

                    private final RestClient restClient = RestClient.builder().build();

                    @Tool
                    public String fetchViaFieldInjectedRestClient(String url) {
                        return restClient.get().uri(url).retrieve().body(String.class);
                    }

                    @Tool
                    public String fetchViaRestTemplate(String url) {
                        RestTemplate restTemplate = new RestTemplate();
                        return restTemplate.getForObject(url, String.class);
                    }

                    @Tool
                    public String fetchViaWebClient(String url) {
                        WebClient webClient = WebClient.create();
                        return webClient.get().uri(url).retrieve().toEntity(String.class).block().getBody();
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
                .flatMap(toolMethod -> rule.evaluate(toolMethod, ProjectContext.noHttpExposure()).stream())
                .toList();

        assertEquals(1, findings.stream()
                .filter(f -> f.methodName().equals("fetchViaFieldInjectedRestClient")).count());
        assertEquals(1, findings.stream().filter(f -> f.methodName().equals("fetchViaRestTemplate")).count());
        assertEquals(1, findings.stream().filter(f -> f.methodName().equals("fetchViaWebClient")).count());
        assertTrue(findings.stream().noneMatch(f -> f.methodName().equals("safeEcho")));
    }
}
