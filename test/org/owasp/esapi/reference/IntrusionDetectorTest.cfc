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
		System = createObject("java", "java.lang.System");
		
		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
	</cfscript>
 
	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			structClear(request);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			structClear(request);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testAddException" output="false" hint="Test of addException method, of class org.owasp.esapi.IntrusionDetector.">
		<cfscript>
			System.out.println("addException");
			instance.ESAPI.intrusionDetector().addException( createObject("java", "java.lang.RuntimeException").init("message") );
			instance.ESAPI.intrusionDetector().addException( createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "user message", "log message") );
			instance.ESAPI.intrusionDetector().addException( createObject("component", "cfesapi.org.owasp.esapi.errors.IntrusionException").init(instance.ESAPI, "user message", "log message") );
			local.username = instance.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
	        local.auth = instance.ESAPI.authenticator();
			local.user = local.auth.createUser(local.username, "addException", "addException");
			local.user.enable();
		    local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse").init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.user.loginWithPassword(password="addException");

			// Now generate some exceptions to disable account
			for (local.i = 1; local.i <= instance.ESAPI.securityConfiguration().getQuota("cfesapi.org.owasp.esapi.errors.IntegrityException").count; local.i++ ) {
	            // EnterpriseSecurityExceptions are added to IntrusionDetector automatically
	            createObject("component", "cfesapi.org.owasp.esapi.errors.IntegrityException").init( instance.ESAPI, "IntegrityException " & i, "IntegrityException " & i );
			}
	        assertFalse( local.user.isLoggedIn() );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testAddEvent" output="false" hint="Test of addEvent method, of class org.owasp.esapi.IntrusionDetector.">
		<cfscript>
	        System.out.println("addEvent");
			local.username = instance.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
	        local.auth = instance.ESAPI.authenticator();
			local.user = local.auth.createUser(local.username, "addEvent", "addEvent");
			local.user.enable();
		    local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse").init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.user.loginWithPassword(password="addEvent");

	        // Now generate some events to disable user account
	        for ( local.i = 1; local.i <= instance.ESAPI.securityConfiguration().getQuota("event.test").count; local.i++ ) {
	            instance.ESAPI.intrusionDetector().addEvent("test", "test message");
	        }
	        assertFalse( local.user.isEnabled() );
    	</cfscript> 
	</cffunction>


</cfcomponent>
