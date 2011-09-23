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
			<li>AccountId: #encodeForHTML(currentUser.getAccountId())#</li>
			<li>AccountName: #encodeForHTML(currentUser.getAccountName())#</li>
			<li>isAnonymous: #encodeForHTML(currentUser.isAnonymous())#</li>
			<li>isEnabled: #encodeForHTML(currentUser.isEnabled())#</li>
			<li>isLoggedIn: #encodeForHTML(currentUser.isLoggedIn())#</li>
			<li>Locale: #encodeForHTML(currentUser.getLocale())#</li>
		</ul>
	</cfoutput>
	<p><a href="/cfesapi/demo/members/index.cfm">Login</a></p>
</body>
</html>
