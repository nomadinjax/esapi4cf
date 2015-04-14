<!---
/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent output="false" hint="ESAPI Automation Tests">

	<!---
		These automation tests are still very young so please excuse the mess!
		Over time these will get better organized into a POM design pattern.
	 --->

	<cfscript>
		this.name = "ESAPI-AutomationTests";
		this.sessionManagement = false;
		this.clientManagement = false;
		this.setClientCookies = false;

		this.mappings["/org"] = expandPath("/esapi4cf/org");
		this.mappings["/test"] = expandPath("/esapi4cf/test/automation");
	</cfscript>

	<cffunction access="public" returntype="void" name="onApplicationStart" output="false">
		<cfscript>
			// TODO: move these to a properties file and make available via java.util.Properties instance
			application.engines = {};
			application.engines["railo"] = {};
			application.engines["railo"].insecureURL = "http://localhost:8080/esapi4cf-development";
			application.engines["railo"].secureURL = "https://localhost:8081/esapi4cf-development";
			application.engines["cf10"] = {};
			application.engines["cf10"].insecureURL = "http://esapi4cf-development.cf10.local";
			application.engines["cf10"].secureURL = "https://esapi4cf-development.cf10.local";
			application.engines["cf9"] = {};
			application.engines["cf9"].insecureURL = "http://esapi4cf-development.cf9.local";
			application.engines["cf9"].secureURL = "https://esapi4cf-development.cf9.local";
			//application.engines["cf8"] = {};
			//application.engines["cf8"].insecureURL = "http://esapi4cf-trunk.cf8.local";
			//application.engines["cf8"].secureURL = "https://esapi4cf-trunk.cf8.local";

			application.browsers = {};
			application.browsers["chrome"] = "*googlechrome C:\Program Files (x86)\Google\Chrome\Application\chrome.exe";
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="onRequestStart" output="false">
		<cfscript>
			if (structKeyExists(url, "reload") && url["reload"] == "true") {
				onApplicationStart();
			}

			request.browser = application.browsers["chrome"];
			if (structKeyExists(url, "browser")) {
				request.browser = application.browsers[url.browser];
			}

			request.engine = application.engines["railo"];
			if (structKeyExists(url, "engine")) {
				request.engine = application.engines[url.engine];
			}
		</cfscript>
	</cffunction>

</cfcomponent>