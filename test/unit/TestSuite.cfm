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
<cfsetting requesttimeout="120">
<cfscript>
	serverVersion = "CF " & server.coldfusion.ProductVersion;
	if(structKeyExists(server, "railo")) {
		serverVersion = "Railo " & server.railo.version;
	}
	ESAPI = createObject("component", "org.owasp.esapi.ESAPI");

	results = createObject("component", "mxunit.runner.DirectoryTestSuite").run(directory=expandPath("."), componentPath="esapi4cf.test.unit", recurse=true);
</cfscript>
<cfoutput><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Unit | #ESAPI.ESAPINAME# #ESAPI.VERSION# [#serverVersion#]</title>
</head>
<body>
<h1>Unit | #ESAPI.ESAPINAME# #ESAPI.VERSION# [#serverVersion#]</h1>
#results.getResultsOutput("html")#
</body>
</html>
</cfoutput>
