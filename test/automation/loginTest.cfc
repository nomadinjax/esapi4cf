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
			variables.browserUrl = request.engine.secureURL;
			variables.browserCommand = request.browser;
			super.beforeTests();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testInsecureLogin" output="false">
		<cfscript>
			variables.selenium.open(request.engine.insecureURL & "/esapi4cf/samples/tutorials/login.cfm");
			variables.selenium.type("id=accountName", "admin");
			variables.selenium.type("id=password", "Admin123");
			variables.selenium.click("id=loginButton");
			variables.selenium.waitForPageToLoad("30000");
			assertEquals("Attempt to login with an insecure request", selenium.getText("id=alertMessage"));
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testValidLogin" output="false">
		<cfscript>
			variables.selenium.open(request.engine.secureURL & "/esapi4cf/samples/tutorials/login.cfm");
			variables.selenium.type("id=accountName", "admin");
			variables.selenium.type("id=password", "Admin123");
			variables.selenium.click("id=loginButton");
			variables.selenium.waitForPageToLoad("30000");
			assertEquals("Logged in as admin (admin)", selenium.getText("id=loggedInAs"));
		</cfscript>
	</cffunction>

</cfcomponent>