package com.mcpsecaudit.audit;

import com.github.javaparser.ast.comments.Comment;
import com.mcpsecaudit.scanner.ToolMethod;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Reads {@code mcp-sec-audit:ignore} markers from comments attached to, or contained in,
 * a tool method. A bare marker suppresses every rule; a marker followed by rule ids
 * suppresses only those.
 */
final class Suppressions {

    private static final Pattern MARKER = Pattern.compile("mcp-sec-audit:ignore([^\\r\\n]*)");

    private static final Pattern RULE_ID = Pattern.compile("[A-Z][A-Z0-9_]+");

    private Suppressions() {
    }

    static boolean suppresses(ToolMethod toolMethod, String ruleId) {
        for (String markerArguments : markersOn(toolMethod)) {
            Set<String> suppressedRuleIds = ruleIdsIn(markerArguments);
            if (suppressedRuleIds.isEmpty() || suppressedRuleIds.contains(ruleId)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> markersOn(ToolMethod toolMethod) {
        Stream<Comment> comments = Stream.concat(
                toolMethod.methodDeclaration().getComment().stream(),
                toolMethod.methodDeclaration().getAllContainedComments().stream()
        );

        List<String> markerArguments = new ArrayList<>();
        comments.map(Comment::getContent).forEach(content -> {
            Matcher matcher = MARKER.matcher(content);
            while (matcher.find()) {
                markerArguments.add(matcher.group(1));
            }
        });
        return markerArguments;
    }

    private static Set<String> ruleIdsIn(String markerArguments) {
        return RULE_ID.matcher(markerArguments).results()
                .map(match -> match.group())
                .collect(Collectors.toSet());
    }
}
