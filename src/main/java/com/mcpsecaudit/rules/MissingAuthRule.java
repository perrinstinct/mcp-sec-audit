package com.mcpsecaudit.rules;

import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.model.Severity;
import com.mcpsecaudit.scanner.ProjectContext;
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
    public List<Finding> evaluate(ToolMethod toolMethod, ProjectContext project) {
        if (hasAuthAnnotation(toolMethod)) {
            return List.of();
        }
        return List.of(new Finding(
                RULE_ID,
                reachableByAnyone(project) ? Severity.HIGH : Severity.LOW,
                message(project),
                toolMethod.filePath(),
                toolMethod.line(),
                toolMethod.className(),
                toolMethod.methodName()
        ));
    }

    /** An unprotected tool only matters if an unauthenticated caller can reach it. */
    private boolean reachableByAnyone(ProjectContext project) {
        return project.httpExposureDetected() && !project.endpointAuthenticated();
    }

    private String message(ProjectContext project) {
        if (reachableByAnyone(project)) {
            return "MCP tool method has no @PreAuthorize/@Secured/@RolesAllowed, and the project is"
                    + " reachable over HTTP (" + project.evidence() + ")";
        }
        if (project.httpExposureDetected()) {
            return "MCP tool method has no @PreAuthorize/@Secured/@RolesAllowed (lowered to LOW: the"
                    + " MCP endpoint already requires authentication - " + project.authenticationEvidence()
                    + " - so any authenticated client can call this tool, but nobody else)";
        }
        return "MCP tool method has no @PreAuthorize/@Secured/@RolesAllowed (lowered to LOW: "
                + project.evidence() + ", so the server is most likely a local stdio process)";
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
