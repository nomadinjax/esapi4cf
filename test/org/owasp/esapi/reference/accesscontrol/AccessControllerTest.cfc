/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Damon Miller
 * @created 2011
 */
/**
 * Answers the question: is the AccessController itself working properly?
 *
 */
component AccessControllerTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();
	instance.accessController = "";

	// @Before
	
	public void function setUp() {
		local.accessControlRules = {};
		local.alwaysTrue = new cfesapi.org.owasp.esapi.reference.accesscontrol.AlwaysTrueACR(instance.ESAPI);
		local.accessControlRules.put("AlwaysTrue", local.alwaysTrue);
		local.alwaysFalse = new cfesapi.org.owasp.esapi.reference.accesscontrol.AlwaysFalseACR(instance.ESAPI);
		local.accessControlRules.put("AlwaysFalse", local.alwaysFalse);
		local.erp = new cfesapi.org.owasp.esapi.reference.accesscontrol.EchoRuntimeParameterACR(instance.ESAPI);
		local.accessControlRules.put("EchoRuntimeParameter", local.erp);
		instance.accessController = new cfesapi.org.owasp.esapi.reference.accesscontrol.ExperimentalAccessController(instance.ESAPI, local.accessControlRules);
	}
	
	// @Test
	
	public void function isAuthorized() {
		assertEquals(instance.accessController.isAuthorized("", ""), false, "Rule Not Found: null");
		assertEquals(instance.accessController.isAuthorized("A key that does not map to a rule", ""), false, "Rule Not Found: Invalid Key");
	
		assertEquals(instance.accessController.isAuthorized("AlwaysTrue", {}), true, "AlwaysTrue");
		assertEquals(instance.accessController.isAuthorized("AlwaysFalse", {}), false, "AlwaysFalse");
	
		// CFB throws syntax errors when newJava() used in assertX()
		Boolean = newJava("java.lang.Boolean");
		assertEquals(instance.accessController.isAuthorized("EchoRuntimeParameter", Boolean.TRUE), true, "EchoRuntimeParameter: True");
		assertEquals(instance.accessController.isAuthorized("EchoRuntimeParameter", Boolean.FALSE), false, "EchoRuntimeParameter: False");
		assertEquals(instance.accessController.isAuthorized("EchoRuntimeParameter", "This is not a boolean"), false, "EchoRuntimeParameter: ClassCastException");
		assertEquals(instance.accessController.isAuthorized("EchoRuntimeParameter", ""), false, "EchoRuntimeParameter: null Runtime Parameter");
	}
	
	// @Test (expected = AccessControlException.class)
	
	public void function enforceAuthorizationRuleNotFoundNullKey() {
		try {
			instance.accessController.assertAuthorized("", "");
			fail("");
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			// expected
		}
	}
	
	// @Test (expected = AccessControlException.class)
	
	public void function enforceAuthorizationRuleAKeyThatDoesNotMapToARule() {
		try {
			instance.accessController.assertAuthorized("A key that does not map to a rule", "");
			fail("");
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			// expected
		}
	}
	
	// @Test
	//Should not throw an exception
	
	public void function enforceAuthorizationAlwaysTrue() {
		try {
			instance.accessController.assertAuthorized("AlwaysTrue", {});
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			//Should not throw an exception
			fail("");
		}
	}
	
	// @Test (expected = AccessControlException.class)
	
	public void function enforceAuthorizationAlwaysFalse() {
		try {
			instance.accessController.assertAuthorized("AlwaysFalse", {});
			fail("");
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			// expected
		}
	}
	
	/**
	 * Ensure that isAuthorized does nothing if enforceAuthorization 
	 * is called and isAuthorized returns true
	 */
	// @Test
	//Should not throw an exception
	
	public void function enforceAuthorizationEchoRuntimeParameterTrue() {
		// CFB throws syntax errors when newJava() used in assertX()
		Boolean = newJava("java.lang.Boolean");
		try {
			instance.accessController.assertAuthorized("EchoRuntimeParameter", Boolean.TRUE);
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			//Should not throw an exception
			fail("");
		}
	}
	
	/**
	 * Ensure that isAuthorized translates into an exception if enforceAuthorization 
	 * is called and isAuthorized returns false
	 */
	// @Test (expected = AccessControlException.class)
	
	public void function enforceAuthorizationEchoRuntimeParameterFalse() {
		// CFB throws syntax errors when newJava() used in assertX()
		Boolean = newJava("java.lang.Boolean");
		try {
			instance.accessController.assertAuthorized("EchoRuntimeParameter", Boolean.FALSE);
			fail("");
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			// expected
		}
	}
	
	// @Test (expected = AccessControlException.class)
	
	public void function enforceAuthorizationEchoRuntimeParameterClassCastException() {
		try {
			instance.accessController.assertAuthorized("EchoRuntimeParameter", "This is not a boolean");
			fail("");
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			// expected
		}
	}
	
	// @Test (expected = AccessControlException.class)
	
	public void function enforceAuthorizationEchoRuntimeParameterNullRuntimeParameter() {
		try {
			instance.accessController.assertAuthorized("EchoRuntimeParameter", "");
			fail("");
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			// expected
		}
	}
	
	// @org.junit.Test
	
	public void function delegatingACR() {
		/* not valid test case - all delegateClasses must be CFC's
		local.delegatingACR = new cfesapi.org.owasp.esapi.reference.accesscontrol.DelegatingACR();
		local.policyParameter = new cfesapi.org.owasp.esapi.reference.accesscontrol.DynaBeanACRParameter();
		local.policyParameter.set("delegateClass", "java.lang.Object");
		local.policyParameter.set("delegateMethod", "equals");
		local.policyParameter.set("parameterClasses", []);
		local.delegatingACR.setPolicyParameters(local.policyParameter);
		assertFalse(local.delegatingACR.isAuthorized([]));
		assertFalse(local.delegatingACR.isAuthorized([local.delegatingACR]));
		*/
		local.delegatingACR = new cfesapi.org.owasp.esapi.reference.accesscontrol.DelegatingACR(instance.ESAPI);
		local.policyParameter = new cfesapi.org.owasp.esapi.reference.accesscontrol.DynaBeanACRParameter();
		local.policyParameter.set("delegateClass", "cfesapi.org.owasp.esapi.reference.accesscontrol.AlwaysTrueACR");
		local.policyParameter.set("delegateMethod", "isAuthorized");
		local.policyParameter.set("parameterClasses", []);
		local.delegatingACR.setPolicyParameters(local.policyParameter);
		assertTrue(local.delegatingACR.isAuthorized({runtimeParameter={}}));
	
		local.delegatingACR = new cfesapi.org.owasp.esapi.reference.accesscontrol.DelegatingACR(instance.ESAPI);
		local.policyParameter = new cfesapi.org.owasp.esapi.reference.accesscontrol.DynaBeanACRParameter();
		local.policyParameter.set("delegateClass", "cfesapi.org.owasp.esapi.reference.accesscontrol.AlwaysFalseACR");
		local.policyParameter.set("delegateMethod", "isAuthorized");
		local.policyParameter.set("parameterClasses", []);
		local.delegatingACR.setPolicyParameters(local.policyParameter);
		assertFalse(local.delegatingACR.isAuthorized({runtimeParameter={}}));
	}
	
}