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

public class ProcExecRule implements SecurityRule {

    public static final String RULE_ID = "PROC_EXEC";

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<Finding> evaluate(ToolMethod toolMethod, ProjectContext project) {
        ParameterTaint taint = ParameterTaint.of(toolMethod.methodDeclaration());
        List<Finding> findings = new ArrayList<>();
        findings.addAll(findRuntimeExecCalls(toolMethod, taint));
        findings.addAll(findProcessBuilderInstantiations(toolMethod, taint));
        return findings;
    }

    private List<Finding> findRuntimeExecCalls(ToolMethod toolMethod, ParameterTaint taint) {
        return toolMethod.methodDeclaration().findAll(MethodCallExpr.class).stream()
                .filter(call -> call.getNameAsString().equals("exec"))
                .filter(call -> call.getScope().map(Node::toString).orElse("").contains("Runtime"))
                .map(call -> toFinding(toolMethod, taint, call, "Runtime.exec()"))
                .toList();
    }

    private List<Finding> findProcessBuilderInstantiations(ToolMethod toolMethod, ParameterTaint taint) {
        return toolMethod.methodDeclaration().findAll(ObjectCreationExpr.class).stream()
                .filter(expr -> expr.getType().getNameAsString().equals("ProcessBuilder"))
                .map(expr -> toFinding(toolMethod, taint, expr, "ProcessBuilder"))
                .toList();
    }

    private Finding toFinding(ToolMethod toolMethod, ParameterTaint taint, Node node, String sink) {
        int line = node.getBegin().map(position -> position.line).orElse(toolMethod.line());
        Optional<String> taintedParameter = taint.nameReaching(node);
        return new Finding(
                RULE_ID,
                taintedParameter.isPresent() ? Severity.CRITICAL : Severity.HIGH,
                taintedParameter
                        .map(parameter -> sink + " runs a command built from tool parameter '" + parameter
                                + "' - the model chooses what is executed")
                        .orElse(sink + " executes a command, but no tool parameter reaches it"),
                toolMethod.filePath(),
                line,
                toolMethod.className(),
                toolMethod.methodName()
        );
    }
}
