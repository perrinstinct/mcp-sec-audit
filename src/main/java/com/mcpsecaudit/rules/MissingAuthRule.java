package com.mcpsecaudit.rules;

import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.Severity;
import com.mcpsecaudit.scanner.ToolMethod;

import java.util.List;
import java.util.Set;

public class MissingAuthRule implements SecurityRule {

    public static final String RULE_ID = "MISSING_AUTH";

    private static final Set<String> AUTH_ANNOTATIONS = Set.of("PreAuthorize", "Secured", "RolesAllowed");

    @Override
    public String ruleId() {
        return RULE_ID;
    }

    @Override
    public List<Finding> evaluate(ToolMethod toolMethod) {
        if (hasAuthAnnotation(toolMethod)) {
            return List.of();
        }
        return List.of(new Finding(
                RULE_ID,
                Severity.HIGH,
                "MCP tool method has no @PreAuthorize/@Secured/@RolesAllowed on itself or its class",
                toolMethod.filePath(),
                toolMethod.line(),
                toolMethod.className(),
                toolMethod.methodName()
        ));
    }

    private boolean hasAuthAnnotation(ToolMethod toolMethod) {
        MethodDeclaration method = toolMethod.methodDeclaration();
        if (hasAnyAuthAnnotation(method.getAnnotations())) {
            return true;
        }
        return method.findAncestor(ClassOrInterfaceDeclaration.class)
                .map(classDeclaration -> hasAnyAuthAnnotation(classDeclaration.getAnnotations()))
                .orElse(false);
    }

    private boolean hasAnyAuthAnnotation(NodeList<AnnotationExpr> annotations) {
        return annotations.stream()
                .anyMatch(annotation -> AUTH_ANNOTATIONS.contains(annotation.getNameAsString()));
    }
}
