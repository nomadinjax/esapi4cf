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
 * Answers the question: Is the policy file being loaded properly?
 */
component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	variables.accessController = "";

	public void function setUp() {
		variables.accessController = variables.ESAPI.accessController();
	}

	public void function testSetup() {
		/**
		 * This tests the policy file
		 */
		var policyDescriptor = new ACRPolicyFileLoader();
		var policyDTO = policyDescriptor.load();
		var accessControlRules = policyDTO.getAccessControlRules();
		assertTrue("Some AccessControlRules are loaded", !accessControlRules
				.isEmpty());
		assertTrue("Access Control Map Contains AlwaysTrue", accessControlRules
				.containsKey("AlwaysTrue"));
		assertTrue("Access Control Map Contains AlwaysFalse",
				accessControlRules.containsKey("AlwaysFalse"));
		assertTrue("Access Control Map Contains EchoRuntimeParameter",
				accessControlRules.containsKey("EchoRuntimeParameter"));
		assertTrue("Access Control Map Contains EchoPolicyParameter",
				accessControlRules.containsKey("EchoPolicyParameter"));
	}

	public void function isAuthorizedEchoPolicyParameter() {
		assertEquals("EchoPolicyParameter", variables.accessController
				.isAuthorized("EchoPolicyParameter", null), true);
		assertEquals("EchoRuntimeParameterClassCastException", variables.accessController
				.isAuthorized("EchoRuntimeParameterClassCastException", null),
				false);
		// Policy parameter value null, empty or missing. (TODO add more fail
		// state tests
		// assertEquals("EchoRuntimeParameterValueNull",
		// variables.accessController.isAuthorized("EchoRuntimeParameterValueNull", null),
		// false);
		// assertEquals("EchoRuntimeParameterValueEmpty",
		// variables.accessController.isAuthorized("EchoRuntimeParameterValueEmpty",
		// null), false);
		// assertEquals("EchoRuntimeParameterValueMissing",
		// variables.accessController.isAuthorized("EchoRuntimeParameterValueMissing",
		// null), false);
	}

	public void function enforceAuthorizationRuleNotFoundNullKey() {
		variables.accessController.assertAuthorized(null, null);
	}
}
