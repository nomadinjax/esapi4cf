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
			CFESAPI Demo - Profile Page
		</title>
	</head>
	<body>
		<cfinclude template="/cfesapi/demo/fba/includes/header.cfm" />
		<h2>
			My Profile (User Properties)
		</h2>
		<cfoutput>
			<ul>
				<li>
					AccountId: #encodeForHTML(currentUser.getAccountId())# 
				</li>
				<li>
					AccountName: #encodeForHTML(currentUser.getAccountName())# 
				</li>
				<li>
					CSRFToken: #encodeForHTML(currentUser.getCSRFToken())# 
				</li>
				<li>
					ExpirationTime: #encodeForHTML(currentUser.getExpirationTime())# 
				</li>
				<li>
					FailedLoginCount: #encodeForHTML(currentUser.getFailedLoginCount())# 
				</li>
				<li>
					LastFailedLoginTime: #encodeForHTML(currentUser.getLastFailedLoginTime())# 
				</li>
				<li>
					LastHostAddress: #encodeForHTML(currentUser.getLastHostAddress())# 
				</li>
				<li>
					LastLoginTime: #encodeForHTML(currentUser.getLastLoginTime())# 
				</li>
				<li>
					LastPasswordChangeTime: #encodeForHTML(currentUser.getLastPasswordChangeTime())# 
				</li>
				<li>
					Roles: #encodeForHTML(arrayToList(currentUser.getRoles()))# 
				</li>
				<li>
					ScreenName: #encodeForHTML(currentUser.getScreenName())# 
				</li>
				<li>
					isAnonymous: #encodeForHTML(currentUser.isAnonymous())# 
				</li>
				<li>
					isEnabled: #encodeForHTML(currentUser.isEnabled())# 
				</li>
				<li>
					isExpired: #encodeForHTML(currentUser.isExpired())# 
				</li>
				<li>
					isInRole(user): #encodeForHTML(currentUser.isInRole("user"))# 
				</li>
				<li>
					isInRole(admin): #encodeForHTML(currentUser.isInRole("admin"))# 
				</li>
				<li>
					isLocked: #encodeForHTML(currentUser.isLocked())# 
				</li>
				<li>
					isLoggedIn: #encodeForHTML(currentUser.isLoggedIn())# 
				</li>
				<li>
					isSessionAbsoluteTimeout: #encodeForHTML(currentUser.isSessionAbsoluteTimeout())# 
				</li>
				<li>
					isSessionTimeout: #encodeForHTML(currentUser.isSessionTimeout())# 
				</li>
				<li>
					toString: #encodeForHTML(currentUser.toString())# 
				</li>
				<li>
					Locale: #encodeForHTML(currentUser.getLocale())# 
				</li>
			</ul>
		</cfoutput>
	</body>
</html>
