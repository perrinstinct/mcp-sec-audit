package com.mcpsecaudit.rules;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Intra-method taint analysis over one MCP tool method.
 *
 * <p>The parameters of a {@code @Tool} method are the untrusted source: the model fills
 * them, and the model can be steered by anything in its context. A value derived from a
 * tainted value is itself tainted, so taint is propagated through local assignments to a
 * fixpoint before asking whether it reaches a given sink.
 *
 * <p>Sanitizers are deliberately not modelled. Wrongly believing a value was validated
 * would hide a real vulnerability, whereas reporting a validated one only costs the
 * author a suppression comment.
 */
public final class ParameterTaint {

    /** Tainted name to the tool parameter it ultimately derives from. */
    private final Map<String, String> originByName;

    private ParameterTaint(Map<String, String> originByName) {
        this.originByName = originByName;
    }

    public static ParameterTaint of(MethodDeclaration method) {
        return new ParameterTaint(propagate(seedFromParameters(method), method));
    }

    /** The tool parameter whose value reaches this sink, directly or through locals. */
    public Optional<String> nameReaching(Node sink) {
        return outermostCallChain(sink).findAll(NameExpr.class).stream()
                .map(NameExpr::getNameAsString)
                .filter(originByName::containsKey)
                .map(originByName::get)
                .findFirst();
    }

    private static Map<String, String> seedFromParameters(MethodDeclaration method) {
        Map<String, String> tainted = new HashMap<>();
        for (Parameter parameter : method.getParameters()) {
            tainted.put(parameter.getNameAsString(), parameter.getNameAsString());
        }
        return tainted;
    }

    private static Map<String, String> propagate(Map<String, String> tainted, MethodDeclaration method) {
        boolean grew = true;
        while (grew) {
            grew = false;
            for (VariableDeclarator variable : method.findAll(VariableDeclarator.class)) {
                if (tainted.containsKey(variable.getNameAsString())) {
                    continue;
                }
                Optional<String> origin = variable.getInitializer().flatMap(init -> originIn(init, tainted));
                if (origin.isPresent()) {
                    tainted.put(variable.getNameAsString(), origin.get());
                    grew = true;
                }
            }
            for (AssignExpr assignment : method.findAll(AssignExpr.class)) {
                String target = simpleNameOf(assignment.getTarget());
                if (target == null || tainted.containsKey(target)) {
                    continue;
                }
                Optional<String> origin = originIn(assignment.getValue(), tainted);
                if (origin.isPresent()) {
                    tainted.put(target, origin.get());
                    grew = true;
                }
            }
        }
        return tainted;
    }

    private static Optional<String> originIn(Node node, Map<String, String> tainted) {
        return node.findAll(NameExpr.class).stream()
                .map(NameExpr::getNameAsString)
                .filter(tainted::containsKey)
                .map(tainted::get)
                .findFirst();
    }

    private static String simpleNameOf(Expression expression) {
        return switch (expression) {
            case NameExpr nameExpr -> nameExpr.getNameAsString();
            case FieldAccessExpr fieldAccessExpr -> fieldAccessExpr.getNameAsString();
            default -> null;
        };
    }

    /**
     * Widens a sink to the fluent chain it starts, so that {@code client.get().uri(userPath)}
     * counts as reaching the client. Only climbs while the node is the parent's scope -
     * climbing into a call that merely takes the sink as an argument would pull in
     * unrelated arguments and invent flows.
     */
    private static Node outermostCallChain(Node sink) {
        Node current = sink;
        while (true) {
            Optional<Node> parent = current.getParentNode();
            if (parent.isEmpty()) {
                return current;
            }
            Node candidate = parent.get();
            Node child = current;
            boolean currentIsScope = switch (candidate) {
                case MethodCallExpr call -> call.getScope().filter(scope -> scope == child).isPresent();
                case FieldAccessExpr access -> access.getScope() == child;
                default -> false;
            };
            if (!currentIsScope) {
                return current;
            }
            current = candidate;
        }
    }
}
