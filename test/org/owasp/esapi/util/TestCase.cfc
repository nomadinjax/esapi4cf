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
<cfcomponent extends="mxunit.framework.TestCase" output="false">

	<cfscript>
		this.ESAPI4JVERSION = 1;					// ESAPI4J version
		if (structKeyExists(createObject("java", "org.owasp.esapi.ESAPI").securityConfiguration(), "APPLICATION_NAME")) {
			this.ESAPI4JVERSION = 2;
		}

		// only initialize once
		if (!structKeyExists(request, "ESAPI")) {
			request.ESAPI = createObject("component", "org.owasp.esapi.ESAPI").init();
		}

		System = createObject("java", "java.lang.System");
	</cfscript>

	<cffunction access="private" returntype="void" name="clearUserFile" output="false">
		<!--- clear the User file to prep for tests --->

		<cfscript>
			var filePath = request.ESAPI.securityConfiguration().getResourceDirectory() & "users.txt";
			var writer = "";
			writer &= "## This is the user file associated with the ESAPI library from http://www.owasp.org" & chr(13) & chr(10);
			writer &= "## accountName | hashedPassword | roles | locked | enabled | rememberToken | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount" & chr(13) & chr(10);
			writer &= chr(13) & chr(10);
		</cfscript>

		<cffile action="write" file="#expandPath(filePath)#" output="#writer#"/>
	</cffunction>

	<cfinclude template="/org/owasp/esapi/util/utils.cfm"/>

</cfcomponent>