<cfparam name="form.username" type="string" default="" />
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>CFESAPI Demo Login</title>
</head>
<body>
	<cfoutput>
		<p><strong>#encodeForHTML(ESAPI().currentRequest().getAttribute("message"))#</strong></p>
	</cfoutput>
	<form method="post" action="/cfesapi/demo/members/index.cfm">
		<label for="username">Username</label>
		<cfoutput>
			<input type="text" name="username" value="#encodeForHTMLAttribute(form.username)#" />
		</cfoutput>
		<br />
		<label for="password">Password</label>
		<input type="password" name="password" />
		<br />
		<button type="submit">Login</button>
	</form>
	<p><a href="/cfesapi/demo/createUser.cfm">Create user</a></p>
</body>
</html>
