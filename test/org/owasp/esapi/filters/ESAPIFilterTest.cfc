<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent extends="cfesapi.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject( "component", "cfesapi.org.owasp.esapi.ESAPI" ).init();
	</cfscript>

	<cffunction access="public" returntype="void" name="testFilter" output="false">
		<cfscript>
			var local = {};

	        System.out.println("ESAPIFilter");
	        local.filter = createObject("component", "cfesapi.org.owasp.esapi.filters.ESAPIFilter").init(instance.ESAPI);
	        System.out.println(">>>" & instance.ESAPI.securityConfiguration().getResourceDirectory() );

	        // setup the user in session
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, getJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			local.authenticator = instance.ESAPI.authenticator();
			local.password = local.authenticator.generateStrongPassword();
			local.user = local.authenticator.createUser(local.accountName, local.password, local.password);
			local.authenticator.setCurrentUser(local.user);
			local.user.enable();
	   	    local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse").init();
	        local.session = local.request.getSession();
	        local.session.setAttribute("ESAPIUserSessionKey", local.user);

	        // setup the URI
	        local.request.setRequestURI("/test/all");

	        // basic test
	        local.filter.onRequestStartFilter(local.request, local.response);
	        local.filter.onRequestEndFilter(instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse());

	        // header injection test
	        local.request.addParameter("test", "test%0d%0a%0d%0awordpad" );
	        local.filter.onRequestStartFilter(local.request, local.response);
	        local.filter.onRequestEndFilter(instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse());

	        // access control test
	        local.request.setRequestURI( "/ridiculous" );
	        local.filter.onRequestStartFilter(local.request, local.response);
	        local.filter.onRequestEndFilter(instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse());

	        // authentication test
	        // TODO: why isn't this invoking the authentication code
	        local.session.removeAttribute("ESAPIUserSessionKey");
	        local.filter.onRequestStartFilter(local.request, local.response);
	        local.filter.onRequestEndFilter(instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse());
    	</cfscript>
	</cffunction>

</cfcomponent>