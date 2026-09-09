package com.mcpsecaudit.rules;

import com.github.javaparser.ast.Node;

import java.util.List;

/** A risky AST node a rule matched, with the wording its finding should carry. */
record SinkMatch(Node node, String description) {

    /**
     * Drops matches sitting inside another match of the same rule. {@code
     * Files.exists(Paths.get(p))} is one thing to fix, not two, so it is reported once at
     * the outermost call - while a {@code Paths.get(p)} nothing else wraps still stands on
     * its own.
     */
    static List<SinkMatch> outermost(List<SinkMatch> matches) {
        return matches.stream()
                .filter(match -> matches.stream().noneMatch(other -> isNestedIn(match.node(), other.node())))
                .toList();
    }

    private static boolean isNestedIn(Node node, Node ancestor) {
        for (Node current = node.getParentNode().orElse(null);
             current != null;
             current = current.getParentNode().orElse(null)) {
            if (current == ancestor) {
                return true;
            }
        }
        return false;
    }
}
