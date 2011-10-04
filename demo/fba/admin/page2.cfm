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
	currentUser = ESAPI().authenticator().getCurrentUser();
</cfscript> 
<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8" />
		<title>
			CFESAPI Demo Admin - Page 2 
		</title>
	</head>
	<body>
		<cfinclude template="/cfesapi/demo/fba/includes/header.cfm" />
		<h2>
			Administrators Only
		</h2>
		<p>
			This is page 2 of the admin only area 
		</p>
		<p>
			<a href="index.cfm">
				Back to Admin Home 
			</a>
		</p>
	</body>
</html>
