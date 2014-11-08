<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent extends="esapi4cf.test.unit.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		// imports
		Utils = createObject("component", "org.owasp.esapi.util.Utils");

		Utils.clearUserFile();
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
			httpRequest = createObject("java", "org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("java", "org.owasp.esapi.http.TestHttpServletResponse").init();
			request.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			request.ESAPI.intrusionDetector().addException(createObject("component", "org.owasp.esapi.errors.IntrusionException").init(request.ESAPI, "user message", "log message"));
			username = request.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			auth = request.ESAPI.authenticator();
			user = auth.createUser(username, "addException", "addException");
			user.enable();
			user.loginWithPassword(password="addException");

			// Now generate some exceptions to disable account
			for(i = 0; i < request.ESAPI.securityConfiguration().getQuota("org.owasp.esapi.errors.IntegrityException").count; i++) {
				// EnterpriseSecurityExceptions are added to IntrusionDetector automatically
				createObject("component", "org.owasp.esapi.errors.IntegrityException").init(request.ESAPI, "IntegrityException " & i, "IntegrityException " & i);
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
			username = request.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			auth = request.ESAPI.authenticator();
			user = auth.createUser(username, "addEvent", "addEvent");
			user.enable();
			httpRequest = createObject("java", "org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("java", "org.owasp.esapi.http.TestHttpServletResponse").init();
			request.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			user.loginWithPassword(password="addEvent");

			// Now generate some events to disable user account
			for(i = 0; i < request.ESAPI.securityConfiguration().getQuota("event.test").count; i++) {
				request.ESAPI.intrusionDetector().addEvent("test", "test message");
			}
			assertFalse(user.isEnabled());
		</cfscript>

	</cffunction>

</cfcomponent>