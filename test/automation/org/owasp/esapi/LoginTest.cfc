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
<cfcomponent extends="esapi4cf.test.automation.org.owasp.esapi.util.TestCase" output="false">

	<cffunction access="public" returntype="void" name="beforeTests" output="false">
		<cfscript>
			variables.browserUrl = request.engine.secureURL;
			variables.browserCommand = request.browser;
			super.beforeTests();
		</cfscript>
	</cffunction>
	
	<cffunction access="public" returntype="void" name="testInsecureLogin" output="false">
		<cfscript>
			variables.selenium.open(request.engine.insecureURL & "/esapi4cf/demo/basic/index.cfm?action=main.login");
			assertEquals("Login", variables.selenium.getText("id=loginLink"));
			variables.selenium.type("id=accountName", "admin");
			variables.selenium.type("id=password", "Admin123");
			variables.selenium.click("id=loginButton");
			variables.selenium.waitForPageToLoad("30000");
			assertEquals("Attempt to login with an insecure request", variables.selenium.getText("id=alertMessage"));
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testValidLogin" output="false">
		<cfscript>
			variables.selenium.open(request.engine.secureURL & "/esapi4cf/demo/basic/index.cfm?action=main.login");
			assertEquals("Login", variables.selenium.getText("id=loginLink"));
			variables.selenium.type("id=accountName", "admin");
			variables.selenium.type("id=password", "Admin123");
			variables.selenium.click("id=loginButton");
			variables.selenium.waitForPageToLoad("30000");
			assertTrue(variables.selenium.isCookiePresent("JSESSIONID"));
			assertEquals("admin", variables.selenium.getText("id=loggedInAs"));
		</cfscript>
	</cffunction>
	
	<cffunction access="public" returntype="void" name="testSessionPersistence" output="false">
		<cfscript>
			var jsessionid = "";
			variables.selenium.open(request.engine.secureURL & "/esapi4cf/demo/basic/index.cfm?action=main.login");
			assertEquals("Login", variables.selenium.getText("id=loginLink"));
			variables.selenium.type("id=accountName", "admin");
			variables.selenium.type("id=password", "Admin123");
			variables.selenium.click("id=loginButton");
			variables.selenium.waitForPageToLoad("30000");
			jsessionid = variables.selenium.getCookieByName("JSESSIONID");
			
			variables.selenium.click("id=loggedInAs");
			variables.selenium.click("id=myProfileLink");
			variables.selenium.waitForPageToLoad("30000");
			assertEquals(jsessionid, variables.selenium.getCookieByName("JSESSIONID"));
			assertEquals("admin", variables.selenium.getText("id=loggedInAs"));
		</cfscript>
	</cffunction>
	
	<cffunction access="public" returntype="void" name="testLogout" output="false">
		<cfscript>
			var jsessionid = "";
			variables.selenium.open(request.engine.secureURL & "/esapi4cf/demo/basic/index.cfm?action=main.login");
			assertEquals("Login", variables.selenium.getText("id=loginLink"));
			variables.selenium.type("id=accountName", "admin");
			variables.selenium.type("id=password", "Admin123");
			variables.selenium.click("id=loginButton");
			variables.selenium.waitForPageToLoad("30000");
			jsessionid = variables.selenium.getCookieByName("JSESSIONID");
			
			variables.selenium.click("id=loggedInAs");
			variables.selenium.click("id=logoutLink");
			variables.selenium.waitForPageToLoad("30000");
			assertNotEquals(jsessionid, variables.selenium.getCookieByName("JSESSIONID"));
			assertEquals("Login", variables.selenium.getText("id=loginLink"));
		</cfscript>
	</cffunction>

</cfcomponent>