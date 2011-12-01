<!--- /**
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
 */ --->
<cfcomponent displayname="ACRPolicyFileLoaderTest" extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false" hint="Answers the question: Is the policy file being loaded properly?">

	<cfscript>
		instance.ESAPI = newComponent("cfesapi.org.owasp.esapi.ESAPI").init();

		instance.accessController = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			instance.accessController = instance.ESAPI.accessController();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetup" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.policyDescriptor = newComponent("cfesapi.org.owasp.esapi.reference.accesscontrol.policyloader.ACRPolicyFileLoader").init(instance.ESAPI);
			local.policyDTO = local.policyDescriptor.load();
			local.accessControlRules = local.policyDTO.getAccessControlRules();
			assertTrue(!local.accessControlRules.isEmpty(), "Some AccessControlRules are loaded");
			assertTrue(local.accessControlRules.containsKey("AlwaysTrue"), "Access Control Map Contains AlwaysTrue");
			assertTrue(local.accessControlRules.containsKey("AlwaysFalse"), "Access Control Map Contains AlwaysFalse");
			assertTrue(local.accessControlRules.containsKey("EchoRuntimeParameter"), "Access Control Map Contains EchoRuntimeParameter");
			assertTrue(local.accessControlRules.containsKey("EchoPolicyParameter"), "Access Control Map Contains EchoPolicyParameter");
		</cfscript>

	</cffunction>

	<!--- NULL test not valid for CF
	<cffunction access="public" returntype="void" name="isAuthorizedEchoPolicyParameter" output="false">

	    <cfscript>
	        assertEquals("EchoPolicyParameter", instance.accessController.isAuthorized("EchoPolicyParameter", null), true);
	        assertEquals("EchoRuntimeParameterClassCastException", instance.accessController.isAuthorized("EchoRuntimeParameterClassCastException", null), false);
	        // Policy parameter value null, empty or missing. (TODO add more fail state tests
	        // assertEquals("EchoRuntimeParameterValueNull", instance.accessController.isAuthorized("EchoRuntimeParameterValueNull", null), false);
	        // assertEquals("EchoRuntimeParameterValueEmpty", instance.accessController.isAuthorized("EchoRuntimeParameterValueEmpty", null), false);
	        // assertEquals("EchoRuntimeParameterValueMissing", instance.accessController.isAuthorized("EchoRuntimeParameterValueMissing", null), false);
	    </cfscript>

	</cffunction> --->
	<!--- NULL test not valid for CF
	<cffunction access="public" returntype="void" name="enforceAuthorizationRuleNotFoundNullKey" output="false">

	    <cfscript>
	        instance.accessController.assertAuthorized(null, null);
	    </cfscript>

	</cffunction> --->
</cfcomponent>