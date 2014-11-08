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
<cfcomponent extends="cfselenium.CFSeleniumTestCase_Tags" output="false">

	<cffunction access="public" returntype="void" name="beforeTests" output="false">
		<cfscript>
			if (!structKeyExists(variables, "browserUrl")) {
				variables.browserUrl = "http://localhost";
			}
			super.beforeTests();
		</cfscript>
	</cffunction>
	
	<cffunction access="public" returntype="void" name="afterTests" output="false">
		<cfscript>
			// delete JSESSIONID cookie to force logout
			variables.selenium.deleteCookie("JSESSIONID", "path=" & getContextRoot());
			
			super.afterTests();
		</cfscript>
	</cffunction>
	
</cfcomponent>