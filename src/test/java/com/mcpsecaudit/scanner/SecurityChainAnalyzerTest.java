package com.mcpsecaudit.scanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every fixture here is modelled on a real public MCP server, because that is where the
 * dangerous shapes are: half of them configure OAuth2 <em>and</em> leave the endpoint open.
 */
class SecurityChainAnalyzerTest {

    @Test
    void creditsAChainThatAuthenticatesEveryRequest(@TempDir Path dir) throws IOException {
        // shape of danvega/mcps and the mcp-security README
        Path config = write(dir, "McpServerSecurityConfig.java", """
                package com.example;

                @Configuration
                @EnableWebSecurity
                public class McpServerSecurityConfig {

                    @Bean
                    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                        return http
                                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                                .with(McpServerOAuth2Configurer.mcpServerOAuth2(), mcpAuthorization -> {
                                    mcpAuthorization.authorizationServer(this.authServerUrl);
                                })
                                .build();
                    }
                }
                """);

        SecurityChainAnalyzer.Verdict verdict = new SecurityChainAnalyzer().inspect(List.of(config));

        assertTrue(verdict.chainsDeclared());
        assertTrue(verdict.authenticated(), "every request needs a token, so the endpoint is protected");
        assertTrue(verdict.authenticationEvidence().contains("mcpServerOAuth2"),
                verdict.authenticationEvidence());
        assertTrue(verdict.authenticationEvidence().contains("McpServerSecurityConfig.java"),
                verdict.authenticationEvidence());
    }

    @Test
    void creditsAnApiKeyChain(@TempDir Path dir) throws IOException {
        // shape of habuma/spring-ai-recipes secured-mcp-server-api-key
        Path config = write(dir, "SecurityConfig.java", """
                package com.example;

                @Configuration
                public class SecurityConfig {

                    @Bean
                    SecurityFilterChain securityFilterChain(HttpSecurity http) {
                        return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                                .with(McpApiKeyConfigurer.mcpServerApiKey().headerName("X-MCP-API-KEY"),
                                        apiKey -> apiKey.apiKeyRepository(apiKeyRepository()))
                                .build();
                    }
                }
                """);

        SecurityChainAnalyzer.Verdict verdict = new SecurityChainAnalyzer().inspect(List.of(config));

        assertTrue(verdict.authenticated());
        assertTrue(verdict.authenticationEvidence().contains("mcpServerApiKey"),
                verdict.authenticationEvidence());
    }

    @Test
    void refusesCreditWhenTheMcpEndpointIsPermitted(@TempDir Path dir) throws IOException {
        // shape of habuma's secured-mcp-server-oauth and apache/solr-mcp: tools protect themselves
        Path config = write(dir, "SecurityConfig.java", """
                package com.example;

                @Configuration
                public class SecurityConfig {

                    @Bean
                    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                        return http.authorizeHttpRequests(auth -> {
                                    auth.requestMatchers("/mcp").permitAll();
                                    auth.anyRequest().authenticated();
                                })
                                .with(McpServerOAuth2Configurer.mcpServerOAuth2(), mcp -> mcp.authorizationServer(url))
                                .build();
                    }
                }
                """);

        SecurityChainAnalyzer.Verdict verdict = new SecurityChainAnalyzer().inspect(List.of(config));

        assertTrue(verdict.chainsDeclared());
        assertFalse(verdict.authenticated(),
                "OAuth2 is configured, but anyone can still reach /mcp - a tool without @PreAuthorize is public");
    }

    @Test
    void refusesCreditWhenEverythingIsPermitted(@TempDir Path dir) throws IOException {
        // the official spring-ai-community sample-mcp-server-secured-tools, and aws-samples
        Path config = write(dir, "McpServerConfiguration.java", """
                package com.example;

                @Configuration
                @EnableMethodSecurity
                class McpServerConfiguration {

                    @Bean
                    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                        return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                                .with(mcpServerOAuth2(), mcp -> mcp.authorizationServer(issuerUrl))
                                .csrf(CsrfConfigurer::disable)
                                .build();
                    }
                }
                """);

        assertFalse(new SecurityChainAnalyzer().inspect(List.of(config)).authenticated());
    }

    @Test
    void isNotFooledByPathsThatMerelyLookLikeTheEndpoint(@TempDir Path dir) throws IOException {
        // springdoc-openapi-demos permits /mcp-ui/** and /api/mcp-admin/**, not /mcp
        Path config = write(dir, "McpSecurityConfiguration.java", """
                package com.example;

                @Configuration
                class McpSecurityConfiguration {

                    @Bean
                    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                        return http.authorizeHttpRequests(auth -> {
                                    auth.requestMatchers("/mcp-ui/**", "/api/mcp-admin/**", "/v3/api-docs/**").permitAll();
                                    auth.anyRequest().authenticated();
                                })
                                .with(mcpServerOAuth2(), mcp -> mcp.authorizationServer(issuerUrl))
                                .build();
                    }
                }
                """);

        assertTrue(new SecurityChainAnalyzer().inspect(List.of(config)).authenticated(),
                "a path that merely starts with the same letters does not open /mcp");
    }

    @Test
    void refusesCreditWhenAnotherChainOpensTheEndpoint(@TempDir Path dir) throws IOException {
        // apache/solr-mcp ships a second, unsecured chain behind @ConditionalOnProperty
        Path config = write(dir, "HttpSecurityConfiguration.java", """
                package com.example;

                @Configuration
                class HttpSecurityConfiguration {

                    @Bean
                    @ConditionalOnProperty(name = "http.security.enabled", havingValue = "true")
                    SecurityFilterChain secured(HttpSecurity http) throws Exception {
                        return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).build();
                    }

                    @Bean
                    @ConditionalOnProperty(name = "http.security.enabled", havingValue = "false")
                    SecurityFilterChain unsecured(HttpSecurity http) throws Exception {
                        return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll()).build();
                    }
                }
                """);

        assertFalse(new SecurityChainAnalyzer().inspect(List.of(config)).authenticated(),
                "a profile or property can select the open chain, and we cannot know which one runs");
    }

    @Test
    void refusesCreditWhenAMatcherCannotBeRead(@TempDir Path dir) throws IOException {
        Path config = write(dir, "SecurityConfig.java", """
                package com.example;

                @Configuration
                public class SecurityConfig {

                    @Bean
                    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                        return http.authorizeHttpRequests(auth -> {
                                    auth.requestMatchers(PUBLIC_PATHS).permitAll();
                                    auth.anyRequest().authenticated();
                                })
                                .build();
                    }
                }
                """);

        assertFalse(new SecurityChainAnalyzer().inspect(List.of(config)).authenticated(),
                "a constant could hold /mcp, and assuming otherwise would hide a real hole");
    }

    @Test
    void ignoresAChainScopedToOtherPaths(@TempDir Path dir) throws IOException {
        Path config = write(dir, "SecurityConfig.java", """
                package com.example;

                @Configuration
                public class SecurityConfig {

                    @Bean
                    @Order(1)
                    SecurityFilterChain adminChain(HttpSecurity http) throws Exception {
                        return http.securityMatcher("/admin/**")
                                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                                .build();
                    }

                    @Bean
                    SecurityFilterChain defaultChain(HttpSecurity http) throws Exception {
                        return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).build();
                    }
                }
                """);

        assertTrue(new SecurityChainAnalyzer().inspect(List.of(config)).authenticated(),
                "a chain restricted to /admin cannot open /mcp");
    }

    @Test
    void refusesCreditFromAChainThatDoesNotCoverTheEndpoint(@TempDir Path dir) throws IOException {
        Path config = write(dir, "SecurityConfig.java", """
                package com.example;

                @Configuration
                public class SecurityConfig {

                    @Bean
                    SecurityFilterChain adminChain(HttpSecurity http) throws Exception {
                        return http.securityMatcher("/admin/**")
                                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                                .build();
                    }
                }
                """);

        assertFalse(new SecurityChainAnalyzer().inspect(List.of(config)).authenticated(),
                "securing /admin says nothing about /mcp, which no chain then covers");
    }

    @Test
    void creditsAReactiveChain(@TempDir Path dir) throws IOException {
        Path config = write(dir, "WebFluxSecurityConfig.java", """
                package com.example;

                @Configuration
                @EnableWebFluxSecurity
                public class WebFluxSecurityConfig {

                    @Bean
                    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
                        return http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
                                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                                .build();
                    }
                }
                """);

        SecurityChainAnalyzer.Verdict verdict = new SecurityChainAnalyzer().inspect(List.of(config));

        assertTrue(verdict.authenticated());
        assertTrue(verdict.authenticationEvidence().contains("oauth2ResourceServer"),
                verdict.authenticationEvidence());
    }

    @Test
    void refusesCreditWhenAPermittedPathCoversACustomEndpoint(@TempDir Path dir) throws IOException {
        Path config = write(dir, "SecurityConfig.java", """
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

        assertFalse(new SecurityChainAnalyzer().inspect(List.of(config), Set.of("/api/ai")).authenticated(),
                "the server moved its endpoint under /api, which this chain opens");
    }

    @Test
    void reportsNoChainsWhenTheModuleDeclaresNone(@TempDir Path dir) throws IOException {
        Path source = write(dir, "WeatherTools.java", """
                package com.example;

                public class WeatherTools {
                    @Tool
                    public String forecast(String city) {
                        return city;
                    }
                }
                """);

        SecurityChainAnalyzer.Verdict verdict = new SecurityChainAnalyzer().inspect(List.of(source));

        assertFalse(verdict.chainsDeclared(), "nothing to say, so Boot's auto-configuration may still apply");
        assertFalse(verdict.authenticated());
    }

    private Path write(Path dir, String fileName, String content) throws IOException {
        Path file = dir.resolve(fileName);
        Files.writeString(file, content);
        return file;
    }
}
