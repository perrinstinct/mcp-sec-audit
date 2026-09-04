package com.mcpsecaudit.rules;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.Severity;
import com.mcpsecaudit.scanner.ToolMethod;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class NetAccessRule implements SecurityRule {

    public static final String RULE_ID = "NET_ACCESS";

    private static final Set<String> NET_TYPES = Set.of("Socket", "URL");

    private static final Set<String> NET_UTILITY_CLASSES = Set.of("HttpClient");

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<Finding> evaluate(ToolMethod toolMethod) {
        List<Finding> findings = new ArrayList<>();
        findings.addAll(findNetInstantiations(toolMethod));
        findings.addAll(findNetUtilityCalls(toolMethod));
        return findings;
    }

    private List<Finding> findNetInstantiations(ToolMethod toolMethod) {
        return toolMethod.methodDeclaration().findAll(ObjectCreationExpr.class).stream()
                .filter(expr -> NET_TYPES.contains(expr.getType().getNameAsString()))
                .map(expr -> toFinding(toolMethod, expr,
                        expr.getType().getNameAsString() + " instantiation gives direct network access"))
                .toList();
    }

    private List<Finding> findNetUtilityCalls(ToolMethod toolMethod) {
        return toolMethod.methodDeclaration().findAll(MethodCallExpr.class).stream()
                .filter(call -> scopeSimpleName(call).filter(NET_UTILITY_CLASSES::contains).isPresent())
                .map(call -> toFinding(toolMethod, call,
                        scopeSimpleName(call).orElseThrow() + "." + call.getNameAsString()
                                + "() gives direct network access"))
                .toList();
    }

    private Optional<String> scopeSimpleName(MethodCallExpr call) {
        return call.getScope()
                .map(Node::toString)
                .map(scope -> scope.substring(scope.lastIndexOf('.') + 1));
    }

    private Finding toFinding(ToolMethod toolMethod, Node node, String message) {
        int line = node.getBegin().map(position -> position.line).orElse(toolMethod.line());
        return new Finding(
                RULE_ID,
                Severity.MEDIUM,
                message,
                toolMethod.filePath(),
                line,
                toolMethod.className(),
                toolMethod.methodName()
        );
    }
}
