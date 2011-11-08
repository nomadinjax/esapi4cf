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
 * Answers the question: Is the policy file being loaded properly?
 */
component ACRPolicyFileLoaderTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();

	instance.accessController = "";

	// @Before
	
	public void function setUp() {
		instance.accessController = instance.ESAPI.accessController();
	}
	
	// @Test
	
	public void function testSetup() {
		local.policyDescriptor = new cfesapi.org.owasp.esapi.reference.accesscontrol.policyloader.ACRPolicyFileLoader(instance.ESAPI);
		local.policyDTO = local.policyDescriptor.load();
		local.accessControlRules = local.policyDTO.getAccessControlRules();
		assertTrue(!local.accessControlRules.isEmpty(), "Some AccessControlRules are loaded");
		assertTrue(local.accessControlRules.containsKey("AlwaysTrue"), "Access Control Map Contains AlwaysTrue");
		assertTrue(local.accessControlRules.containsKey("AlwaysFalse"), "Access Control Map Contains AlwaysFalse");
		assertTrue(local.accessControlRules.containsKey("EchoRuntimeParameter"), "Access Control Map Contains EchoRuntimeParameter");
		assertTrue(local.accessControlRules.containsKey("EchoPolicyParameter"), "Access Control Map Contains EchoPolicyParameter");
	}
	
	// @Test
	/* NULL test not valid for CF
	public void function isAuthorizedEchoPolicyParameter() {
	    assertEquals("EchoPolicyParameter", instance.accessController.isAuthorized("EchoPolicyParameter", null), true);
	    assertEquals("EchoRuntimeParameterClassCastException", instance.accessController.isAuthorized("EchoRuntimeParameterClassCastException", null), false);
	    // Policy parameter value null, empty or missing. (TODO add more fail state tests
	    // assertEquals("EchoRuntimeParameterValueNull", instance.accessController.isAuthorized("EchoRuntimeParameterValueNull", null), false);
	    // assertEquals("EchoRuntimeParameterValueEmpty", instance.accessController.isAuthorized("EchoRuntimeParameterValueEmpty", null), false);
	    // assertEquals("EchoRuntimeParameterValueMissing", instance.accessController.isAuthorized("EchoRuntimeParameterValueMissing", null), false);
	} */
	// @Test(expected = AccessControlException.class)
	/* NULL test not valid for CF
	public void function enforceAuthorizationRuleNotFoundNullKey() {
	    instance.accessController.assertAuthorized(null, null);
	} */
}