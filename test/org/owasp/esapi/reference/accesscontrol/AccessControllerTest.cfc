<!---
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
	--->
<cfcomponent extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false">

	<cfscript>
		Boolean = createObject("java", "java.lang.Boolean");

		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
		instance.accessController = "";
	</cfscript>
 
	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			local.accessControlRules = {};
			local.accessControlRules.put("AlwaysTrue", createObject("component", "cfesapi.org.owasp.esapi.reference.accesscontrol.AlwaysTrueACR"));
			local.accessControlRules.put("AlwaysFalse", createObject("component", "cfesapi.org.owasp.esapi.reference.accesscontrol.AlwaysFalseACR"));
			local.accessControlRules.put("EchoRuntimeParameter", createObject("component", "cfesapi.org.owasp.esapi.reference.accesscontrol.EchoRuntimeParameterACR"));
			instance.accessController = createObject("component", "cfesapi.org.owasp.esapi.reference.accesscontrol.ExperimentalAccessController").init(instance.ESAPI, local.accessControlRules);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			instance.accessController = "";
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="isAuthorized" output="false">
		<cfscript>
			assertEquals(instance.accessController.isAuthorized("", ""), false, "Rule Not Found: null");
			assertEquals(instance.accessController.isAuthorized("A key that does not map to a rule", ""), false, "Rule Not Found: Invalid Key");

			assertEquals(instance.accessController.isAuthorized("AlwaysTrue", {}), true, "AlwaysTrue");
			assertEquals(instance.accessController.isAuthorized("AlwaysFalse", {}), false, "AlwaysFalse");

			assertEquals(instance.accessController.isAuthorized("EchoRuntimeParameter", Boolean.TRUE), true, "EchoRuntimeParameter: True");
			assertEquals(instance.accessController.isAuthorized("EchoRuntimeParameter", Boolean.FALSE), false, "EchoRuntimeParameter: False");
			assertEquals(instance.accessController.isAuthorized("EchoRuntimeParameter", "This is not a boolean"), false, "EchoRuntimeParameter: ClassCastException");
			assertEquals(instance.accessController.isAuthorized("EchoRuntimeParameter", ""), false, "EchoRuntimeParameter: null Runtime Parameter");
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="enforceAuthorizationRuleNotFoundNullKey" output="false">
		<cfscript>
			try {
				instance.accessController.assertAuthorized("", "");
				fail("");
			}
			catch (cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				// expected
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="enforceAuthorizationRuleAKeyThatDoesNotMapToARule" output="false">
		<cfscript>
			try {
				instance.accessController.assertAuthorized("A key that does not map to a rule", "");
				fail("");
			}
			catch (cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				// expected
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="enforceAuthorizationAlwaysTrue" output="false">
		<cfscript>
			try {
				instance.accessController.assertAuthorized("AlwaysTrue", {});
			} catch (cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				//Should not throw an exception
				fail("");
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="enforceAuthorizationAlwaysFalse" output="false">
		<cfscript>
			try {
				instance.accessController.assertAuthorized("AlwaysFalse", {});
				fail("");
			} catch (cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				// expected
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="enforceAuthorizationEchoRuntimeParameterTrue" output="false" hint="Ensure that isAuthorized does nothing if enforceAuthorization is called and isAuthorized returns true">
		<cfscript>
			try {
				instance.accessController.assertAuthorized("EchoRuntimeParameter", Boolean.TRUE);
			} catch (cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				//Should not throw an exception
				fail("");
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="enforceAuthorizationEchoRuntimeParameterFalse" output="false" hint="Ensure that isAuthorized translates into an exception if enforceAuthorization is called and isAuthorized returns false">
		<cfscript>
			try {
				instance.accessController.assertAuthorized("EchoRuntimeParameter", Boolean.FALSE);
				fail("");
			} catch (cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				// expected
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="enforceAuthorizationEchoRuntimeParameterClassCastException" output="false">
		<cfscript>
			try {
				instance.accessController.assertAuthorized("EchoRuntimeParameter", "This is not a boolean");
				fail("");
			} catch (cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				// expected
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="enforceAuthorizationEchoRuntimeParameterNullRuntimeParameter" output="false">
		<cfscript>
			try {
				instance.accessController.assertAuthorized("EchoRuntimeParameter", "");
				fail("");
			} catch (cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				// expected
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="delegatingACR" output="false">
		<cfscript>
			/* not valid test case - all delegateClasses must be CFC's
			local.delegatingACR = createObject("component", "cfesapi.org.owasp.esapi.reference.accesscontrol.DelegatingACR").init();
			local.policyParameter = createObject("component", "cfesapi.org.owasp.esapi.reference.accesscontrol.DynaBeanACRParameter").init();
			local.policyParameter.set("delegateClass", "java.lang.Object");
			local.policyParameter.set("delegateMethod", "equals");
			local.policyParameter.set("parameterClasses", []);
			local.delegatingACR.setPolicyParameters(local.policyParameter);
			assertFalse(local.delegatingACR.isAuthorized([]));
			assertFalse(local.delegatingACR.isAuthorized([local.delegatingACR]));
			*/

			local.delegatingACR = createObject("component", "cfesapi.org.owasp.esapi.reference.accesscontrol.DelegatingACR").init(instance.ESAPI);
			local.policyParameter = createObject("component", "cfesapi.org.owasp.esapi.reference.accesscontrol.DynaBeanACRParameter").init();
			local.policyParameter.set("delegateClass", "cfesapi.org.owasp.esapi.reference.accesscontrol.AlwaysTrueACR");
			local.policyParameter.set("delegateMethod", "isAuthorized");
			local.policyParameter.set("parameterClasses", []);
			local.delegatingACR.setPolicyParameters(local.policyParameter);
			assertTrue(local.delegatingACR.isAuthorized({runtimeParameter={}}));

			local.delegatingACR = createObject("component", "cfesapi.org.owasp.esapi.reference.accesscontrol.DelegatingACR").init(instance.ESAPI);
			local.policyParameter = createObject("component", "cfesapi.org.owasp.esapi.reference.accesscontrol.DynaBeanACRParameter").init();
			local.policyParameter.set("delegateClass", "cfesapi.org.owasp.esapi.reference.accesscontrol.AlwaysFalseACR");
			local.policyParameter.set("delegateMethod", "isAuthorized");
			local.policyParameter.set("parameterClasses", []);
			local.delegatingACR.setPolicyParameters(local.policyParameter);
			assertFalse(local.delegatingACR.isAuthorized({runtimeParameter={}}));
		</cfscript> 
	</cffunction>


</cfcomponent>
