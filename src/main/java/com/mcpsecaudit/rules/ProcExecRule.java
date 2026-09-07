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

public class ProcExecRule implements SecurityRule {

    public static final String RULE_ID = "PROC_EXEC";

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<Finding> evaluate(ToolMethod toolMethod, ProjectContext project) {
        List<Finding> findings = new ArrayList<>();
        findings.addAll(findRuntimeExecCalls(toolMethod));
        findings.addAll(findProcessBuilderInstantiations(toolMethod));
        return findings;
    }

    private List<Finding> findRuntimeExecCalls(ToolMethod toolMethod) {
        return toolMethod.methodDeclaration().findAll(MethodCallExpr.class).stream()
                .filter(call -> call.getNameAsString().equals("exec"))
                .filter(call -> call.getScope().map(Node::toString).orElse("").contains("Runtime"))
                .map(call -> toFinding(toolMethod, call, "Runtime.exec() call allows arbitrary OS command execution"))
                .toList();
    }

    private List<Finding> findProcessBuilderInstantiations(ToolMethod toolMethod) {
        return toolMethod.methodDeclaration().findAll(ObjectCreationExpr.class).stream()
                .filter(expr -> expr.getType().getNameAsString().equals("ProcessBuilder"))
                .map(expr -> toFinding(toolMethod, expr, "ProcessBuilder instantiation allows arbitrary OS command execution"))
                .toList();
    }

    private Finding toFinding(ToolMethod toolMethod, Node node, String message) {
        int line = node.getBegin().map(position -> position.line).orElse(toolMethod.line());
        return new Finding(
                RULE_ID,
                Severity.CRITICAL,
                message,
                toolMethod.filePath(),
                line,
                toolMethod.className(),
                toolMethod.methodName()
        );
    }
}
