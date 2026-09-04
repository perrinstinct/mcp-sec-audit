package com.mcpsecaudit.rules;

import com.mcpsecaudit.model.Finding;
import com.mcpsecaudit.scanner.ToolMethod;

import java.util.List;

public interface SecurityRule {

    String ruleId();

    List<Finding> evaluate(ToolMethod toolMethod);
}
