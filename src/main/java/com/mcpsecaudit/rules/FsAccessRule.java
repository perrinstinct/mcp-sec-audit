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
import java.util.Optional;
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
        ParameterTaint taint = ParameterTaint.of(toolMethod.methodDeclaration());
        List<SinkMatch> matches = new ArrayList<>();
        matches.addAll(findFileInstantiations(toolMethod));
        matches.addAll(findFileUtilityCalls(toolMethod));

        return SinkMatch.outermost(matches).stream()
                .map(match -> toFinding(toolMethod, taint, match))
                .toList();
    }

    private List<SinkMatch> findFileInstantiations(ToolMethod toolMethod) {
        return toolMethod.methodDeclaration().findAll(ObjectCreationExpr.class).stream()
                .filter(expr -> FILE_TYPES.contains(expr.getType().getNameAsString()))
                .map(expr -> new SinkMatch(expr,
                        expr.getType().getNameAsString() + " instantiation gives direct filesystem access"))
                .toList();
    }

    private List<SinkMatch> findFileUtilityCalls(ToolMethod toolMethod) {
        return toolMethod.methodDeclaration().findAll(MethodCallExpr.class).stream()
                .filter(call -> scopeSimpleName(call).filter(FILE_UTILITY_CLASSES::contains).isPresent())
                .map(call -> new SinkMatch(call,
                        scopeSimpleName(call).orElseThrow() + "." + call.getNameAsString()
                                + "() gives direct filesystem access"))
                .toList();
    }

    private java.util.Optional<String> scopeSimpleName(MethodCallExpr call) {
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
