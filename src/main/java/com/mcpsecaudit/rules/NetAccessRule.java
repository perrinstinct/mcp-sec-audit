package com.mcpsecaudit.rules;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.Severity;
import com.mcpsecaudit.scanner.ProjectContext;
import com.mcpsecaudit.scanner.ToolMethod;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class NetAccessRule implements SecurityRule {

    public static final String RULE_ID = "NET_ACCESS";

    private static final Set<String> NET_TYPES = Set.of("Socket", "URL", "RestTemplate");

    private static final Set<String> NET_UTILITY_CLASSES = Set.of("HttpClient", "RestClient", "WebClient");

    /** Types worth flagging when held in a class field, not just constructed inline. */
    private static final Set<String> NET_CLIENT_FIELD_TYPES =
            Set.of("Socket", "URL", "HttpClient", "RestClient", "RestTemplate", "WebClient");

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<Finding> evaluate(ToolMethod toolMethod, ProjectContext project) {
        ParameterTaint taint = ParameterTaint.of(toolMethod.methodDeclaration());
        List<SinkMatch> matches = new ArrayList<>();
        matches.addAll(findNetInstantiations(toolMethod));
        matches.addAll(findNetUtilityCalls(toolMethod));
        matches.addAll(findNetClientFieldUsages(toolMethod));

        return SinkMatch.outermost(matches).stream()
                .map(match -> toFinding(toolMethod, taint, match))
                .toList();
    }

    private List<SinkMatch> findNetInstantiations(ToolMethod toolMethod) {
        return toolMethod.methodDeclaration().findAll(ObjectCreationExpr.class).stream()
                .filter(expr -> NET_TYPES.contains(expr.getType().getNameAsString()))
                .map(expr -> new SinkMatch(expr,
                        expr.getType().getNameAsString() + " instantiation gives direct network access"))
                .toList();
    }

    private List<SinkMatch> findNetUtilityCalls(ToolMethod toolMethod) {
        return toolMethod.methodDeclaration().findAll(MethodCallExpr.class).stream()
                .filter(call -> scopeSimpleName(call).filter(NET_UTILITY_CLASSES::contains).isPresent())
                .map(call -> new SinkMatch(call,
                        scopeSimpleName(call).orElseThrow() + "." + call.getNameAsString()
                                + "() gives direct network access"))
                .toList();
    }

    /**
     * Catches the constructor/field-injection shape common in real Spring code
     * (e.g. WeatherApiClient in spring-ai-examples): the client is built once as a
     * field, and the @Tool method only ever calls that field, so neither
     * instantiation nor a static factory call ever appears inside the method body.
     */
    private List<SinkMatch> findNetClientFieldUsages(ToolMethod toolMethod) {
        Map<String, String> netClientFields = toolMethod.methodDeclaration()
                .findAncestor(ClassOrInterfaceDeclaration.class)
                .map(this::netClientFieldsByName)
                .orElse(Map.of());

        if (netClientFields.isEmpty()) {
            return List.of();
        }

        return toolMethod.methodDeclaration().findAll(MethodCallExpr.class).stream()
                .flatMap(call -> call.getScope().stream()
                        .flatMap(scope -> fieldNameReferencedBy(scope, netClientFields.keySet()).stream())
                        .map(fieldName -> new SinkMatch(call,
                                "Call on field '" + fieldName + "' (" + netClientFields.get(fieldName)
                                        + ") gives network access")))
                .toList();
    }

    private Map<String, String> netClientFieldsByName(ClassOrInterfaceDeclaration classDeclaration) {
        Map<String, String> fields = new HashMap<>();
        for (FieldDeclaration field : classDeclaration.getFields()) {
            for (VariableDeclarator variable : field.getVariables()) {
                String typeName = variable.getType().asString();
                if (NET_CLIENT_FIELD_TYPES.contains(typeName)) {
                    fields.put(variable.getNameAsString(), typeName);
                }
            }
        }
        return fields;
    }

    private Optional<String> fieldNameReferencedBy(Expression scope, Set<String> fieldNames) {
        String name = switch (scope) {
            case NameExpr nameExpr -> nameExpr.getNameAsString();
            case FieldAccessExpr fieldAccessExpr -> fieldAccessExpr.getNameAsString();
            default -> null;
        };
        return Optional.ofNullable(name).filter(fieldNames::contains);
    }

    private Optional<String> scopeSimpleName(MethodCallExpr call) {
        return call.getScope()
                .map(Node::toString)
                .map(scope -> scope.substring(scope.lastIndexOf('.') + 1));
    }

    private Finding toFinding(ToolMethod toolMethod, ParameterTaint taint, SinkMatch match) {
        int line = match.node().getBegin().map(position -> position.line).orElse(toolMethod.line());
        Optional<String> taintedParameter = taint.nameReaching(match.node());
        String message = match.description();
        return new Finding(
                RULE_ID,
                taintedParameter.isPresent() ? Severity.HIGH : Severity.MEDIUM,
                taintedParameter
                        .map(parameter -> message + ", driven by tool parameter '" + parameter
                                + "' with no validation in between")
                        .orElse(message),
                toolMethod.filePath(),
                line,
                toolMethod.className(),
                toolMethod.methodName()
        );
    }
}
