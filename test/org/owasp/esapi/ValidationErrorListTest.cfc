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
<cfcomponent displayname="ValidationErrorListTest" extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false">

	<cfscript>
		instance.ESAPI = newComponent("cfesapi.org.owasp.esapi.ESAPI").init();
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			// none
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			// none
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testAddError" output="false">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testAddError");
			local.vel = newComponent("cfesapi.org.owasp.esapi.ValidationErrorList").init();
			local.vex = createValidationException();
			local.vel.addError("context", local.vex);
			/* NULL test not valid in CF
			try {
			    local.vel.addError(null, local.vex);
			    fail("");
			}
			catch(java.lang.RuntimeException e) {
			    // expected
			}*/
			/* NULL test not valid in CF
			try {
			    local.vel.addError("context1", null);
			    fail("");
			}
			catch(java.lang.RuntimeException e) {
			    // expected
			} */
			try {
				local.vel.addError("context", local.vex);// add the same context again
				fail("");
			}
			catch(java.lang.RuntimeException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testErrors" output="false">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testErrors");
			local.vel = newComponent("cfesapi.org.owasp.esapi.ValidationErrorList").init();
			local.vex = createValidationException();
			local.vel.addError("context", local.vex);
			assertTrue(local.vel.errors().get(0).toESAPIString() == local.vex.toESAPIString());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetError" output="false">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testGetError");
			local.vel = newComponent("cfesapi.org.owasp.esapi.ValidationErrorList").init();
			local.vex = createValidationException();
			local.vel.addError("context", local.vex);
			assertTrue(local.vel.getError("context").toESAPIString() == local.vex.toESAPIString());
			local.result = local.vel.getError("ridiculous");
			assertFalse(structKeyExists(local, "result"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsEmpty" output="false">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testIsEmpty");
			local.vel = newComponent("cfesapi.org.owasp.esapi.ValidationErrorList").init();
			assertTrue(local.vel.isEmpty());
			local.vex = createValidationException();
			local.vel.addError("context", local.vex);
			assertFalse(local.vel.isEmpty());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSize" output="false">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testSize");
			local.vel = newComponent("cfesapi.org.owasp.esapi.ValidationErrorList").init();
			assertTrue(local.vel.size() == 0);
			local.vex = createValidationException();
			local.vel.addError("context", local.vex);
			assertTrue(local.vel.size() == 1);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="cfesapi.org.owasp.esapi.errors.ValidationException" name="createValidationException" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.vex = "";
			try {
				local.vex = newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "User message", "Log Message");
			}
			catch(cfesapi.org.owasp.esapi.errors.IntrusionException e) {
				// expected occasionally
			}
			return local.vex;
		</cfscript>

	</cffunction>

</cfcomponent>