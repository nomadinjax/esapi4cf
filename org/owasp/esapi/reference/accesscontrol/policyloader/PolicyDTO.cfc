/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */

/**
 * The point of the loaders is to create this
 */
component extends="org.owasp.esapi.util.Object" {
	variables.ESAPI = "";
	variables.accessControlRules = "";

	public PolicyDTO function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;
		variables.accessControlRules = {};
		return this;
	}

	public struct function getAccessControlRules() {
		return variables.accessControlRules;
	}

	public void function addAccessControlRule(required string key, required string accessControlRuleClassName, required policyParameter) {
		if (!isNull(variables.accessControlRules.get(arguments.key))) {
			throws(new AccessControlException(variables.ESAPI, "Duplicate keys are not allowed. " & "Key: " & arguments.key, ""));
		}
		var accessControlRuleConstructor = "";
		try {
			var accessControlRuleClass = Class.forName(arguments.accessControlRuleClassName, false, this.getClass().getClassLoader());
			accessControlRuleConstructor = accessControlRuleClass.getConstructor();
			var accessControlRule = accessControlRuleConstructor.newInstance();
			accessControlRule.setPolicyParameters(arguments.policyParameter);
			variables.accessControlRules.put(arguments.key, accessControlRule);
		} catch (Exception e) {
			throws(variables.ESAPI, new AccessControlException(variables.ESAPI, "Unable to create Access Control Rule for key: " & chr(34) & arguments.key & chr(34) & " with policyParameters: " & chr(34) & arguments.policyParameter & chr(34), "", e));
		}
	}
	public string function toString() {
		return variables.accessControlRules.toString();
	}
}
