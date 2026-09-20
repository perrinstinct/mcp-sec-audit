package com.mcpsecaudit.scanner;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Reads a module's Spring Security configuration to decide whether its MCP endpoint can be
 * reached without authenticating.
 *
 * <p>Spotting the OAuth2 configurer is not enough, and assuming otherwise would be worse than
 * the false positive it fixes. Spring AI's own "secured tools" sample configures
 * {@code mcpServerOAuth2()} <em>and</em> leaves {@code /mcp} on {@code permitAll()}, because
 * there every tool carries its own {@code @PreAuthorize}; a tool without one is genuinely
 * public. So what counts is the access rules, not the authentication mechanism, and anything
 * this class cannot read - a matcher built from a constant, a chain selected by a profile -
 * is treated as leaving the endpoint open.
 */
public class SecurityChainAnalyzer {

    /** The endpoints Spring AI serves out of the box. */
    public static final Set<String> DEFAULT_MCP_ENDPOINTS = Set.of("/mcp", "/sse", "/mcp/message");

    private static final Set<String> CHAIN_TYPES = Set.of("SecurityFilterChain", "SecurityWebFilterChain");

    /** The rule that applies to requests no earlier matcher claimed. */
    private static final Set<String> CATCH_ALL = Set.of("anyRequest", "anyExchange");

    /** Access rules that all demand an identity of some kind. */
    private static final Set<String> REQUIRES_IDENTITY = Set.of(
            "authenticated", "fullyAuthenticated", "denyAll",
            "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority", "access");

    private static final Set<String> PATH_MATCHERS = Set.of(
            "requestMatchers", "pathMatchers", "antMatchers", "mvcMatchers");

    /** Restricts the whole chain to a subset of the application's URLs. */
    private static final Set<String> CHAIN_SCOPE_MATCHERS = Set.of("securityMatcher", "securityMatchers");

    /** Named in the finding, so a reader can check the claim in seconds. */
    private static final List<String> MECHANISMS = List.of(
            "mcpServerOAuth2", "mcpServerApiKey", "oauth2ResourceServer",
            "oauth2Login", "httpBasic", "saml2Login", "x509");

    private final JavaParser javaParser = new JavaParser(
            new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21)
    );

    /**
     * What the module's security chains say.
     *
     * @param chainsDeclared         whether the module declares any chain at all - if it does,
     *                               Spring Boot's auto-configuration backs off and these chains
     *                               have the final word
     * @param authenticationEvidence why the endpoint is considered authenticated, or null
     */
    public record Verdict(boolean chainsDeclared, String authenticationEvidence) {

        public boolean authenticated() {
            return authenticationEvidence != null;
        }

        public static Verdict noChains() {
            return new Verdict(false, null);
        }

        public static Verdict reachableWithoutAuthentication() {
            return new Verdict(true, null);
        }

        public static Verdict authenticatedBy(String evidence) {
            return new Verdict(true, evidence);
        }
    }

    public Verdict inspect(Collection<Path> javaFiles) {
        return inspect(javaFiles, DEFAULT_MCP_ENDPOINTS);
    }

    public Verdict inspect(Collection<Path> javaFiles, Set<String> mcpEndpoints) {
        boolean chainsDeclared = false;
        String evidence = null;

        for (Path file : javaFiles) {
            Optional<CompilationUnit> unit = parse(file);
            if (unit.isEmpty()) {
                chainsDeclared = true;  // it mentions a chain but will not parse: judge nothing
                continue;
            }
            for (MethodDeclaration chain : unit.get().findAll(MethodDeclaration.class)) {
                if (!isChainBean(chain)) {
                    continue;
                }
                chainsDeclared = true;
                if (!scopedAwayFromEndpoint(chain, mcpEndpoints) && opensEndpoint(chain, mcpEndpoints)) {
                    return Verdict.reachableWithoutAuthentication();
                }
                if (evidence == null && coversEndpoint(chain, mcpEndpoints) && requiresIdentity(chain)) {
                    evidence = evidenceFor(chain, file);
                }
            }
        }

        if (!chainsDeclared) {
            return Verdict.noChains();
        }
        return evidence == null ? Verdict.reachableWithoutAuthentication() : Verdict.authenticatedBy(evidence);
    }

    private boolean isChainBean(MethodDeclaration method) {
        boolean isBean = method.getAnnotations().stream()
                .anyMatch(annotation -> annotation.getNameAsString().equals("Bean"));
        String returnType = method.getTypeAsString();
        return isBean && CHAIN_TYPES.stream()
                .anyMatch(type -> returnType.equals(type) || returnType.endsWith("." + type));
    }

    /** True when the chain is restricted to URLs that cannot include the MCP endpoint. */
    private boolean scopedAwayFromEndpoint(MethodDeclaration chain, Set<String> endpoints) {
        List<MethodCallExpr> scopes = callsNamed(chain, CHAIN_SCOPE_MATCHERS);
        return !scopes.isEmpty() && scopes.stream()
                .noneMatch(scope -> arguments(scope).stream()
                        .anyMatch(argument -> mayCover(argument, endpoints)));
    }

    /** True only when the chain demonstrably applies to the MCP endpoint. */
    private boolean coversEndpoint(MethodDeclaration chain, Set<String> endpoints) {
        List<MethodCallExpr> scopes = callsNamed(chain, CHAIN_SCOPE_MATCHERS);
        return scopes.isEmpty() || scopes.stream()
                .anyMatch(scope -> arguments(scope).stream()
                        .anyMatch(argument -> literalCovers(argument, endpoints)));
    }

    private boolean opensEndpoint(MethodDeclaration chain, Set<String> endpoints) {
        return callsNamed(chain, Set.of("permitAll")).stream().anyMatch(permitAll -> {
            Optional<MethodCallExpr> target = permitAll.getScope()
                    .filter(Expression::isMethodCallExpr)
                    .map(Expression::asMethodCallExpr);
            if (target.isEmpty()) {
                return false;
            }
            String name = target.get().getNameAsString();
            if (CATCH_ALL.contains(name)) {
                return true;
            }
            return PATH_MATCHERS.contains(name) && arguments(target.get()).stream()
                    .anyMatch(argument -> mayCover(argument, endpoints));
        });
    }

    private boolean requiresIdentity(MethodDeclaration chain) {
        return callsNamed(chain, REQUIRES_IDENTITY).stream()
                .anyMatch(rule -> rule.getScope()
                        .filter(Expression::isMethodCallExpr)
                        .map(scope -> CATCH_ALL.contains(scope.asMethodCallExpr().getNameAsString()))
                        .orElse(false));
    }

    private String evidenceFor(MethodDeclaration chain, Path file) {
        String chainType = simpleName(chain.getTypeAsString());
        String fileName = file.getFileName().toString();
        return MECHANISMS.stream()
                .filter(mechanism -> !callsNamed(chain, Set.of(mechanism)).isEmpty())
                .findFirst()
                .map(mechanism -> "%s with %s() in %s".formatted(chainType, mechanism, fileName))
                .orElse("%s requiring authentication in %s".formatted(chainType, fileName));
    }

    /** May this argument stand for a path that reaches the MCP endpoint? Unreadable means yes. */
    private boolean mayCover(Expression argument, Set<String> endpoints) {
        if (!argument.isStringLiteralExpr()) {
            return true;
        }
        return patternCovers(argument.asStringLiteralExpr().getValue(), endpoints);
    }

    /** Does this argument demonstrably cover the MCP endpoint? Unreadable means no. */
    private boolean literalCovers(Expression argument, Set<String> endpoints) {
        return argument.isStringLiteralExpr()
                && patternCovers(argument.asStringLiteralExpr().getValue(), endpoints);
    }

    /**
     * Compares first path segments, which is enough to tell {@code /mcp-ui/**} - a real
     * springdoc sample - from {@code /mcp}, without reimplementing Spring's path matching.
     */
    private boolean patternCovers(String pattern, Set<String> endpoints) {
        String segment = firstSegment(pattern);
        if (segment.isEmpty()) {
            return false;
        }
        if (segment.contains("*") || segment.contains("?") || segment.contains("{")) {
            return true;
        }
        return endpoints.stream().anyMatch(endpoint -> segment.equals(firstSegment(endpoint)));
    }

    private String firstSegment(String path) {
        String withoutLeadingSlash = path.startsWith("/") ? path.substring(1) : path;
        int slash = withoutLeadingSlash.indexOf('/');
        return slash < 0 ? withoutLeadingSlash : withoutLeadingSlash.substring(0, slash);
    }

    private List<MethodCallExpr> callsNamed(MethodDeclaration method, Set<String> names) {
        return method.findAll(MethodCallExpr.class).stream()
                .filter(call -> names.contains(call.getNameAsString()))
                .toList();
    }

    private List<Expression> arguments(MethodCallExpr call) {
        return call.getArguments();
    }

    private String simpleName(String type) {
        int lastDot = type.lastIndexOf('.');
        return lastDot < 0 ? type : type.substring(lastDot + 1);
    }

    private Optional<CompilationUnit> parse(Path file) {
        try {
            ParseResult<CompilationUnit> result = javaParser.parse(file);
            return result.isSuccessful() ? result.getResult() : Optional.empty();
        } catch (IOException e) {
            return Optional.empty();
        }
    }
}
