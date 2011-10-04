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
<cfparam name="form.username" type="string" default="" />
<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8" />
		<title>
			CFESAPI Demo Login 
		</title>
	</head>
	<body>
		<cfinclude template="/cfesapi/demo/fba/includes/header.cfm" />
		<h2>
			Login
		</h2>
		<cfoutput>
			<p>
				<strong>
					#encodeForHTML(ESAPI().currentRequest().getAttribute("message"))# 
				</strong>
			</p>
			<!--- submit the login form to itself so we are directed to the original destination --->
			<form method="post" action="#encodeForHTMLAttribute(ESAPI().currentRequest().getPathInfo())#">
				<label for="username">
					Username 
				</label>
				<input type="text" name="username" value="#encodeForHTMLAttribute(form.username)#" />
				<br />
				<label for="password">
					Password 
				</label>
				<input type="password" name="password" />
				<br />
				<button type="submit">
					Login 
				</button>
			</form>
		</cfoutput>
		<p>
			<a href="/cfesapi/demo/fba/createUser.cfm">
				Create New User 
			</a>
		</p>
	</body>
</html>
