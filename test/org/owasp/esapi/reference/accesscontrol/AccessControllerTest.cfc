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
 * Answers the question: is the AccessController itself working properly?
 */
component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	variables.accessController = "";

	public void function setup() {
		var accessControlRules = {};
		accessControlRules.put("AlwaysTrue", new AlwaysTrueACR());
		accessControlRules.put("AlwaysFalse", new AlwaysFalseACR());
		accessControlRules.put("EchoRuntimeParameter", new EchoRuntimeParameterACR());
		variables.accessController = new ExperimentalAccessController(accessControlRules);
	}

	public void function testIsAuthorized() {
		assertEquals("Rule Not Found: null", variables.accessController.isAuthorized(null, null), false);
		assertEquals("Rule Not Found: Invalid Key", variables.accessController.isAuthorized("A key that does not map to a rule", null), false);

		assertEquals("AlwaysTrue", variables.accessController.isAuthorized("AlwaysTrue", null), true);
		assertEquals("AlwaysFalse", variables.accessController.isAuthorized("AlwaysFalse", null), false);

		assertEquals("EchoRuntimeParameter: True", variables.accessController.isAuthorized("EchoRuntimeParameter", Boolean.TRUE), true );
		assertEquals("EchoRuntimeParameter: False", variables.accessController.isAuthorized("EchoRuntimeParameter", Boolean.FALSE), false);
		assertEquals("EchoRuntimeParameter: ClassCastException", variables.accessController.isAuthorized("EchoRuntimeParameter", "This is not a boolean"), false);
		assertEquals("EchoRuntimeParameter: null Runtime Parameter", variables.accessController.isAuthorized("EchoRuntimeParameter", null), false);
	}

	public void function testEnforceAuthorizationRuleNotFoundNullKey() throws Exception {
		variables.accessController.assertAuthorized(null, null);
	}
	public void function testEnforceAuthorizationRuleAKeyThatDoesNotMapToARule() throws Exception {
		variables.accessController.assertAuthorized("A key that does not map to a rule", null);
	}


	//Should not throw an exception
	public void function testEnforceAuthorizationAlwaysTrue() throws Exception {
		variables.accessController.assertAuthorized("AlwaysTrue", null);
	}

	public void function testEenforceAuthorizationAlwaysFalse() throws Exception {
		variables.accessController.assertAuthorized("AlwaysFalse", null);
	}

	/**
	 * Ensure that isAuthorized does nothing if enforceAuthorization
	 * is called and isAuthorized returns true
	 */
	//Should not throw an exception
	public void function testEnforceAuthorizationEchoRuntimeParameterTrue() throws Exception {
		variables.accessController.assertAuthorized("EchoRuntimeParameter", Boolean.TRUE);
	}

	/**
	 * Ensure that isAuthorized translates into an exception if enforceAuthorization
	 * is called and isAuthorized returns false
	 */
	public void function testEnforceAuthorizationEchoRuntimeParameterFalse() throws Exception {
		variables.accessController.assertAuthorized("EchoRuntimeParameter", Boolean.FALSE);
	}

	public void function testEnforceAuthorizationEchoRuntimeParameterClassCastException() throws Exception {
		variables.accessController.assertAuthorized("EchoRuntimeParameter", "This is not a boolean");
	}

	public void function testEnforceAuthorizationEchoRuntimeParameterNullRuntimeParameter() throws Exception {
		variables.accessController.assertAuthorized("EchoRuntimeParameter", null);
	}

	public void function testDelegatingACR() {
		var delegatingACR = new DelegatingACR();
		var policyParameter = new DynaBeanACRParameter();

		/* not valid test case - all delegateClasses must be CFC's
		delegatingACR = new DelegatingACR();
		policyParameter = new DynaBeanACRParameter();
		policyParameter.set("delegateClass", "java.lang.Object");
		policyParameter.set("delegateMethod", "equals");
		policyParameter.set("parameterClasses", "java.lang.Object");
		delegatingACR.setPolicyParameters(policyParameter);
		assertFalse(delegatingACR.isAuthorized(new Object[] {new Object()}));
		assertFalse(delegatingACR.isAuthorized(new Object[] {delegatingACR}));
		*/

		policyParameter.set("delegateClass", "org.owasp.esapi.reference.accesscontrol.AlwaysTrueACR");
		policyParameter.set("delegateMethod", "isAuthorized");
		policyParameter.set("parameterClasses", []);
		delegatingACR.setPolicyParameters(policyParameter);
		assertTrue(delegatingACR.isAuthorized({}));

		delegatingACR = new DelegatingACR();
		policyParameter = new DynaBeanACRParameter();
		policyParameter.set("delegateClass", "org.owasp.esapi.reference.accesscontrol.AlwaysFalseACR");
		policyParameter.set("delegateMethod", "isAuthorized");
		policyParameter.set("parameterClasses", []);
		delegatingACR.setPolicyParameters(policyParameter);
		assertFalse(delegatingACR.isAuthorized({}));
	}

}
