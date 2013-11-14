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
		variables.ESAPI = createObject("component", "org.owasp.esapi.ESAPI").init();

		// ESAPI4J version
		try {
			// cannot use newJava() here
			createObject("java", "org.owasp.esapi.util.ObjFactory");
			this.ESAPI4JVERSION = 2;
		}
		catch(Object e) {
			// occurs if this version is less than 2.0
			this.ESAPI4JVERSION = 1;
		}

		System = createObject("java", "java.lang.System");
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			structClear(session);
			structClear(request);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			structClear(session);
			structClear(request);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="clearUserFile" output="false">
		<!--- clear the User file to prep for tests --->

		<cfscript>
			var filePath = variables.ESAPI.securityConfiguration().getResourceDirectory() & "users.txt";
			var writer = "";
			writer &= "## This is the user file associated with the ESAPI library from http://www.owasp.org" & chr(13) & chr(10);
			writer &= "## accountName | hashedPassword | roles | locked | enabled | rememberToken | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount" & chr(13) & chr(10);
			writer &= chr(13) & chr(10);
		</cfscript>

		<cffile action="write" file="#expandPath(filePath)#" output="#writer#"/>
	</cffunction>

	<cfinclude template="/org/owasp/esapi/util/utils.cfm"/>

</cfcomponent>