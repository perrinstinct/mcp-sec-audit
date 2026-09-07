package com.mcpsecaudit.rules;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.Severity;
import com.mcpsecaudit.scanner.ProjectContext;
import com.mcpsecaudit.scanner.ToolMethod;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class FsAccessRule implements SecurityRule {

    public static final String RULE_ID = "FS_ACCESS";

    private static final Set<String> FILE_TYPES = Set.of(
            "File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile"
    );

    private static final Set<String> FILE_UTILITY_CLASSES = Set.of("Files", "Paths");

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<Finding> evaluate(ToolMethod toolMethod, ProjectContext project) {
        List<Finding> findings = new ArrayList<>();
        findings.addAll(findFileInstantiations(toolMethod));
        findings.addAll(findFileUtilityCalls(toolMethod));
        return findings;
    }

    private List<Finding> findFileInstantiations(ToolMethod toolMethod) {
        return toolMethod.methodDeclaration().findAll(ObjectCreationExpr.class).stream()
                .filter(expr -> FILE_TYPES.contains(expr.getType().getNameAsString()))
                .map(expr -> toFinding(toolMethod, expr,
                        expr.getType().getNameAsString() + " instantiation gives direct filesystem access"))
                .toList();
    }

    private List<Finding> findFileUtilityCalls(ToolMethod toolMethod) {
        return toolMethod.methodDeclaration().findAll(MethodCallExpr.class).stream()
                .filter(call -> scopeSimpleName(call).filter(FILE_UTILITY_CLASSES::contains).isPresent())
                .map(call -> toFinding(toolMethod, call,
                        scopeSimpleName(call).orElseThrow() + "." + call.getNameAsString()
                                + "() gives direct filesystem access"))
                .toList();
    }

    private java.util.Optional<String> scopeSimpleName(MethodCallExpr call) {
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
