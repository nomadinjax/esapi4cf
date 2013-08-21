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

<cfscript>
	serverVersion = "[CF " & server.coldfusion.ProductVersion & "]";
	if(structKeyExists(server, "railo")) {
		serverVersion = "[Railo " & server.railo.version & "]";
	}
</cfscript>

<cfoutput>
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="utf-8"/>
			<title>
				ESAPI4CF
				#serverVersion#
			</title>
		</head>
		<body>
			<h1>
				ESAPI for ColdFusion/CFML (ESAPI4CF) Links
			</h1>
			<h2>
				Documentation
			</h2>
			<dl>
				<dt>
					<a href="swingset/">
						The ESAPI Swingset is a web application which demonstrates the many uses of the Enterprise
						Security API (ESAPI).
					</a>
				</dt>
				<dd>
					The ESAPI Swingset is a web application which demonstrates common security vulnerabilities and
					asks users to secure the application against these vulnerabilities using the ESAPI library. The
					application is intended for ColdFusion/CFML Developers. The goal of the application is to teach
					developers about the functionality of the ESAPI library and give users a practical
					understanding of how it can be used to protect web applications against common security
					vulnerabilities.
				</dd>
				<dt>
					<a href="apiref/">
						ESAPI4CF API Documentation
					</a>
				</dt>
				<dd>
					Technical documentation for the ESAPI4CF library.
				</dd>
			</dl>
			<h2>
				Tests
			</h2>
			<dl>
				<dt>
					<a href="test/org/owasp/esapi/AllTests.cfm">
						ESAPI4CF Unit Tests
					</a>
				</dt>
				<dd>
					The ESAPI Unit Tests ported into ColdFusion/CFML using MXUnit (not included).
				</dd>
			</dl>
			<h2>
				Utilities
			</h2>
			<dl>
				<dt>
					<a href="utilities/DefaultEncryptedProperties.cfm">
						Encrypted Properties files
					</a>
				</dt>
				<dd>
					Loads encrypted properties file based on the location passed in args then prompts the user to
					input key-value pairs.
				</dd>
				<dt>
					<a href="utilities/FileBasedAuthenticator.cfm">
						Fail safe main program to add or update an account in an emergency
					</a>
				</dt>
				<dd>
					WARNING: this method does not perform the level of validation and checks generally required in
					ESAPI, and can therefore be used to create a username and password that do not comply with the
					username and password strength requirements.
				</dd>
			</dl>
		</body>
	</html>
</cfoutput>