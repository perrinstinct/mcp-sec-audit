package com.mcpsecaudit.scanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProjectContextDetectorTest {

    @Test
    void detectsHttpExposureFromAWebStarterDependency(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.ai</groupId>
                            <artifactId>spring-ai-starter-mcp-server-webmvc</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """);

        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertTrue(context.httpExposureDetected());
        assertTrue(context.evidence().contains("webmvc"));
    }

    @Test
    void detectsHttpExposureFromStdioDisabledInProperties(@TempDir Path tempDir) throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(tempDir.resolve("src/main/resources/application-http.properties"),
                "spring.ai.mcp.server.stdio=false\n");

        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertTrue(context.httpExposureDetected());
    }

    @Test
    void reportsNoHttpExposureForAStdioOnlyProject(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework.ai</groupId>
                            <artifactId>spring-ai-starter-mcp-server</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """);
        Files.createDirectories(tempDir.resolve("src/main/resources"));
        Files.writeString(tempDir.resolve("src/main/resources/application.properties"),
                "spring.ai.mcp.server.stdio=true\n");

        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertFalse(context.httpExposureDetected());
    }

    @Test
    void reportsNoHttpExposureWhenThereIsNothingToReadAtAll(@TempDir Path tempDir) throws IOException {
        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertFalse(context.httpExposureDetected());
    }

    @Test
    void findsTheBuildFileAboveTheScannedSubdirectory(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project><dependencies><dependency>
                    <artifactId>spring-ai-starter-mcp-server-webmvc</artifactId>
                </dependency></dependencies></project>
                """);
        Path sources = tempDir.resolve("src/main/java/com/example");
        Files.createDirectories(sources);
        Files.writeString(sources.resolve("Tool.java"), "public class Tool {}");

        ProjectContext context = new ProjectContextDetector().detect(sources);

        assertTrue(context.httpExposureDetected(),
                "scanning a subdirectory must still see the project's own build file");
    }

    @Test
    void findsTheBuildFileWhenGivenASingleFile(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project><dependencies><dependency>
                    <artifactId>spring-boot-starter-web</artifactId>
                </dependency></dependencies></project>
                """);
        Path file = tempDir.resolve("src/main/java/Tool.java");
        Files.createDirectories(file.getParent());
        Files.writeString(file, "public class Tool {}");

        ProjectContext context = new ProjectContextDetector().detect(file);

        assertTrue(context.httpExposureDetected());
    }

    @Test
    void judgesSiblingModulesIndependently(@TempDir Path tempDir) throws IOException {
        // aggregator root: lists modules, declares no dependencies of its own
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project>
                    <modules>
                        <module>web-server</module>
                        <module>stdio-server</module>
                    </modules>
                </project>
                """);

        Path webModule = tempDir.resolve("web-server");
        Files.createDirectories(webModule);
        Files.writeString(webModule.resolve("pom.xml"), """
                <project><dependencies><dependency>
                    <artifactId>spring-ai-starter-mcp-server-webmvc</artifactId>
                </dependency></dependencies></project>
                """);

        Path stdioModule = tempDir.resolve("stdio-server");
        Files.createDirectories(stdioModule);
        Files.writeString(stdioModule.resolve("pom.xml"), """
                <project><dependencies><dependency>
                    <artifactId>spring-ai-starter-mcp-server</artifactId>
                </dependency></dependencies></project>
                """);

        ProjectContextDetector detector = new ProjectContextDetector();

        assertTrue(detector.detect(webModule).httpExposureDetected());
        assertFalse(detector.detect(stdioModule).httpExposureDetected(),
                "a sibling module's web starter says nothing about this one");
    }

    @Test
    void stillInheritsFromAnAncestorModule(@TempDir Path tempDir) throws IOException {
        // a real parent that declares the dependency for its children
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project><dependencies><dependency>
                    <artifactId>spring-boot-starter-web</artifactId>
                </dependency></dependencies></project>
                """);
        Path child = tempDir.resolve("child");
        Files.createDirectories(child);
        Files.writeString(child.resolve("pom.xml"), "<project><artifactId>child</artifactId></project>");

        ProjectContext context = new ProjectContextDetector().detect(child);

        assertTrue(context.httpExposureDetected(),
                "an ancestor may genuinely pass dependencies down, so it still counts");
    }

    @Test
    void detectsAuthenticationFromAChainInTheModulesOwnSources(@TempDir Path tempDir) throws IOException {
        webModule(tempDir);
        writeJava(tempDir, "SecurityConfig.java", """
                package com.example;

                @Configuration
                public class SecurityConfig {
                    @Bean
                    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                        return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                                .with(mcpServerOAuth2(), mcp -> mcp.authorizationServer(issuerUrl))
                                .build();
                    }
                }
                """);

        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertTrue(context.httpExposureDetected());
        assertTrue(context.endpointAuthenticated());
        assertTrue(context.authenticationEvidence().contains("SecurityConfig.java"),
                context.authenticationEvidence());
    }

    @Test
    void creditsTheBootAutoConfigurationWhenAnIssuerUriIsSet(@TempDir Path tempDir) throws IOException {
        // spring-ai-community's own sample, and the setup its readme recommends: no Java at all
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project><dependencies>
                    <dependency><artifactId>spring-ai-starter-mcp-server-webmvc</artifactId></dependency>
                    <dependency><artifactId>mcp-server-security-spring-boot</artifactId></dependency>
                </dependencies></project>
                """);
        writeProperties(tempDir, "spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9000\n");

        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertTrue(context.endpointAuthenticated());
        assertTrue(context.authenticationEvidence().contains("mcp-server-security-spring-boot"),
                context.authenticationEvidence());
    }

    @Test
    void doesNotCreditTheAutoConfigurationWithoutAnIssuerUri(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project><dependencies>
                    <dependency><artifactId>spring-ai-starter-mcp-server-webmvc</artifactId></dependency>
                    <dependency><artifactId>mcp-server-security-spring-boot</artifactId></dependency>
                </dependencies></project>
                """);

        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertFalse(context.endpointAuthenticated(),
                "the auto-configuration only builds a chain when the issuer URI is set");
    }

    @Test
    void letsTheModulesOwnChainOverrideTheAutoConfiguration(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
                <project><dependencies>
                    <dependency><artifactId>spring-ai-starter-mcp-server-webmvc</artifactId></dependency>
                    <dependency><artifactId>mcp-server-security-spring-boot</artifactId></dependency>
                </dependencies></project>
                """);
        writeProperties(tempDir, "spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9000\n");
        writeJava(tempDir, "SecurityConfig.java", """
                package com.example;

                @Configuration
                public class SecurityConfig {
                    @Bean
                    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                        return http.authorizeHttpRequests(auth -> {
                                    auth.requestMatchers("/mcp").permitAll();
                                    auth.anyRequest().authenticated();
                                })
                                .build();
                    }
                }
                """);

        ProjectContext context = new ProjectContextDetector().detect(tempDir);

        assertFalse(context.endpointAuthenticated(),
                "declaring a chain switches the auto-configuration off, and this one opens /mcp");
    }

    @Test
    void ignoresASecurityChainFromAnotherModule(@TempDir Path tempDir) throws IOException {
        Path secured = tempDir.resolve("secured-server");
        Files.createDirectories(secured);
        webModule(secured);
        writeJava(secured, "SecurityConfig.java", """
                package com.example;

                @Configuration
                public class SecurityConfig {
                    @Bean
                    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                        return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).build();
                    }
                }
                """);

        Path open = tempDir.resolve("open-server");
        Files.createDirectories(open);
        webModule(open);

        ProjectContextDetector detector = new ProjectContextDetector();

        assertTrue(detector.detect(secured).endpointAuthenticated());
        assertFalse(detector.detect(open).endpointAuthenticated(),
                "code is not inherited: a sibling's security configuration protects nothing here");
    }

    @Test
    void readsACustomEndpointBeforeJudgingAPermittedPath(@TempDir Path tempDir) throws IOException {
        webModule(tempDir);
        writeProperties(tempDir, "spring.ai.mcp.server.streamable-http.mcp-endpoint=/api/ai\n");
        writeJava(tempDir, "SecurityConfig.java", """
                package com.example;

                @Configuration
                public class SecurityConfig {
                    @Bean
                    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                        return http.authorizeHttpRequests(auth -> {
                                    auth.requestMatchers("/api/**").permitAll();
                                    auth.anyRequest().authenticated();
                                })
                                .build();
                    }
                }
                """);

        assertFalse(new ProjectContextDetector().detect(tempDir).endpointAuthenticated(),
                "the server moved its endpoint under /api, which this chain opens");
    }

    private void webModule(Path module) throws IOException {
        Files.writeString(module.resolve("pom.xml"), """
                <project><dependencies><dependency>
                    <artifactId>spring-ai-starter-mcp-server-webmvc</artifactId>
                </dependency></dependencies></project>
                """);
    }

    private void writeJava(Path module, String fileName, String content) throws IOException {
        Path sources = module.resolve("src/main/java/com/example");
        Files.createDirectories(sources);
        Files.writeString(sources.resolve(fileName), content);
    }

    private void writeProperties(Path module, String content) throws IOException {
        Path resources = module.resolve("src/main/resources");
        Files.createDirectories(resources);
        Files.writeString(resources.resolve("application.properties"), content);
    }

    @Test
    void namesTheModuleItFoundTheEvidenceIn(@TempDir Path tempDir) throws IOException {
        Path module = tempDir.resolve("web-server");
        Files.createDirectories(module);
        Files.writeString(module.resolve("pom.xml"), """
                <project><dependencies><dependency>
                    <artifactId>spring-boot-starter-web</artifactId>
                </dependency></dependencies></project>
                """);

        ProjectContext context = new ProjectContextDetector().detect(module);

        assertTrue(context.evidence().contains("web-server"), context.evidence());
    }
}
