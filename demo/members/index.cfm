<cfscript>
	currentUser = ESAPI().authenticator().getCurrentUser();
</cfscript>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>CFESAPI Demo Logged In</title>
</head>
<body>
	<p>Congratulations!!! If you are seeing this page than you have successfully used CFESAPI to login.</p>

	<p>This is an example of a page accessed by an DefaultUser</p>
	<cfoutput>
		<ul>
			<li>AccountId: #encodeForHTML(currentUser.getAccountId())#</li>
			<li>AccountName: #encodeForHTML(currentUser.getAccountName())#</li>
			<li>CSRFToken: #encodeForHTML(currentUser.getCSRFToken())#</li>
			<li>ExpirationTime: #encodeForHTML(currentUser.getExpirationTime())#</li>
			<li>FailedLoginCount: #encodeForHTML(currentUser.getFailedLoginCount())#</li>
			<li>LastFailedLoginTime: #encodeForHTML(currentUser.getLastFailedLoginTime())#</li>
			<li>LastHostAddress: #encodeForHTML(currentUser.getLastHostAddress())#</li>
			<li>LastLoginTime: #encodeForHTML(currentUser.getLastLoginTime())#</li>
			<li>LastPasswordChangeTime: #encodeForHTML(currentUser.getLastPasswordChangeTime())#</li>
			<li>Roles: #encodeForHTML(arrayToList(currentUser.getRoles()))#</li>
			<li>ScreenName: #encodeForHTML(currentUser.getScreenName())#</li>
			<li>isAnonymous: #encodeForHTML(currentUser.isAnonymous())#</li>
			<li>isEnabled: #encodeForHTML(currentUser.isEnabled())#</li>
			<li>isExpired: #encodeForHTML(currentUser.isExpired())#</li>
			<li>isInRole(user): #encodeForHTML(currentUser.isInRole("user"))#</li>
			<li>isInRole(admin): #encodeForHTML(currentUser.isInRole("admin"))#</li>
			<li>isLocked: #encodeForHTML(currentUser.isLocked())#</li>
			<li>isLoggedIn: #encodeForHTML(currentUser.isLoggedIn())#</li>
			<li>isSessionAbsoluteTimeout: #encodeForHTML(currentUser.isSessionAbsoluteTimeout())#</li>
			<li>isSessionTimeout: #encodeForHTML(currentUser.isSessionTimeout())#</li>
			<li>toString: #encodeForHTML(currentUser.toString())#</li>
			<li>Locale: #encodeForHTML(currentUser.getLocale())#</li>
		</ul>
	</cfoutput>

	<p><a href="/cfesapi/demo/members/logout.cfm">Test logout</a></p>
</body>
</html>
