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
			<li>AccountId: #currentUser.getAccountId()#</li>
			<li>AccountName: #currentUser.getAccountName()#</li>
			<li>CSRFToken: #currentUser.getCSRFToken()#</li>
			<li>ExpirationTime: #currentUser.getExpirationTime()#</li>
			<li>FailedLoginCount: #currentUser.getFailedLoginCount()#</li>
			<li>LastFailedLoginTime: #currentUser.getLastFailedLoginTime()#</li>
			<li>LastHostAddress: #currentUser.getLastHostAddress()#</li>
			<li>LastLoginTime: #currentUser.getLastLoginTime()#</li>
			<li>LastPasswordChangeTime: #currentUser.getLastPasswordChangeTime()#</li>
			<li>Roles: #arrayToList(currentUser.getRoles())#</li>
			<li>ScreenName: #currentUser.getScreenName()#</li>
			<li>isAnonymous: #currentUser.isAnonymous()#</li>
			<li>isEnabled: #currentUser.isEnabled()#</li>
			<li>isExpired: #currentUser.isExpired()#</li>
			<li>isInRole(user): #currentUser.isInRole("user")#</li>
			<li>isInRole(admin): #currentUser.isInRole("admin")#</li>
			<li>isLocked: #currentUser.isLocked()#</li>
			<li>isLoggedIn: #currentUser.isLoggedIn()#</li>
			<li>isSessionAbsoluteTimeout: #currentUser.isSessionAbsoluteTimeout()#</li>
			<li>isSessionTimeout: #currentUser.isSessionTimeout()#</li>
			<li>toString: #currentUser.toString()#</li>
			<li>Locale: #currentUser.getLocale()#</li>
		</ul>
	</cfoutput>

	<p><a href="/cfesapi/demo/members/logout.cfm">Test logout</a></p>
</body>
</html>
