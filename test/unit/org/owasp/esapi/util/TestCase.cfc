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
<cfcomponent extends="mxunit.framework.TestCase" output="false">

	<cfscript>
		// only initialize once
		if (!structKeyExists(request, "ESAPI")) {
			request.ESAPI = createObject("component", "org.owasp.esapi.ESAPI").init();
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(createObject("java", "java.util.Locale").getDefault());
		}

		System = createObject("java", "java.lang.System");
	</cfscript>

	<!---<cfinclude template="../backport/backport.cfm">--->

</cfcomponent>