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
<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8" />
		<title>
			CFESAPI Demo - Access Denied! 
		</title>
	</head>
	<body>
		<cfinclude template="/cfesapi/demo/fba/includes/header.cfm" />
		<h2>
			Access Denied! 
		</h2>
		<cfoutput>
			<p>
				<strong>
					#encodeForHTML(ESAPI().currentRequest().getAttribute("message"))# 
				</strong>
			</p>
		</cfoutput>
		<p>
			You do not have permission to view this page 
		</p>
	</body>
</html>
