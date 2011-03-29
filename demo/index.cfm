<cfscript>
	currentUser = ESAPI().authenticator().getCurrentUser();
</cfscript>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>CFESAPI Demo</title>
</head>
<body>
	<p>This is an example of a page accessed by an AnonymousUser</p>
	<cfoutput>
		<ul>
			<li>AccountId: #currentUser.getAccountId()#</li>
			<li>AccountName: #currentUser.getAccountName()#</li>
			<li>isAnonymous: #currentUser.isAnonymous()#</li>
			<li>isEnabled: #currentUser.isEnabled()#</li>
			<li>isLoggedIn: #currentUser.isLoggedIn()#</li>
			<li>Locale: #currentUser.getLocale()#</li>
		</ul>
	</cfoutput>
	<p><a href="/cfesapi/demo/members/index.cfm">Login</a></p>
</body>
</html>
