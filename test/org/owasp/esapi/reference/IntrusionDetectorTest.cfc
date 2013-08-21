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
<cfcomponent extends="esapi4cf.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		variables.ESAPI = createObject("component", "org.owasp.esapi.ESAPI").init();
		clearUserFile();
	</cfscript>
	
	<cffunction access="public" returntype="void" name="testAddException" output="false"
	            hint="Test of addException method, of class org.owasp.esapi.IntrusionDetector.">
		
		<cfscript>
			// CF8 requires 'var' at the top
			var httpRequest = "";
			var httpResponse = "";
			var username = "";
			var auth = "";
			var user = "";
			var i = "";
		
			System.out.println("addException");
			httpRequest = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse").init();
			variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			variables.ESAPI.intrusionDetector().addException(createObject("component", "org.owasp.esapi.errors.IntrusionException").init(variables.ESAPI, "user message", "log message"));
			username = variables.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			auth = variables.ESAPI.authenticator();
			user = auth.createUser(username, "addException", "addException");
			user.enable();
			user.loginWithPassword(password="addException");
		
			// Now generate some exceptions to disable account
			for(i = 0; i < variables.ESAPI.securityConfiguration().getQuota("org.owasp.esapi.errors.IntegrityException").count; i++) {
				// EnterpriseSecurityExceptions are added to IntrusionDetector automatically
				createObject("component", "org.owasp.esapi.errors.IntegrityException").init(variables.ESAPI, "IntegrityException " & i, "IntegrityException " & i);
			}
			assertFalse(user.isLoggedIn());
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="testAddEvent" output="false"
	            hint="Test of addEvent method, of class org.owasp.esapi.IntrusionDetector.">
		
		<cfscript>
			// CF8 requires 'var' at the top
			var username = "";
			var auth = "";
			var user = "";
			var httpRequest = "";
			var httpResponse = "";
			var i = "";
		
			System.out.println("addEvent");
			username = variables.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			auth = variables.ESAPI.authenticator();
			user = auth.createUser(username, "addEvent", "addEvent");
			user.enable();
			httpRequest = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse").init();
			variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			user.loginWithPassword(password="addEvent");
		
			// Now generate some events to disable user account
			for(i = 0; i < variables.ESAPI.securityConfiguration().getQuota("event.test").count; i++) {
				variables.ESAPI.intrusionDetector().addEvent("test", "test message");
			}
			assertFalse(user.isEnabled());
		</cfscript>
		
	</cffunction>
	
</cfcomponent>