<cfparam name="form.accountName" type="string" default="" />
<cfscript>
	message = "";
	if (ESAPI().currentRequest().getMethod() == "post") {
		try {
			newUser = ESAPI().authenticator().createUser(form.accountName, form.password1, form.password2);
			newUser.enable();
			newUser.addRole('user');
			message = "User created successfully!";
		}
		catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			message = e.message;
		}
		catch (cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException e) {
			message = e.message;
		}
	}
</cfscript>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>CFESAPI Demo CreateUser</title>
</head>
<body>
	<p>This allows you to create a username/password that will be saved to users.txt and can be used to test the ESAPIFilter.cfm login page.</p>
	<h3>Although this utility has created your user, you will need to <em>edit the users.txt file and enable this user.</em></h3>
	<p>NOTES:</p>
	<ul>
		<li>The user created is only good for this CF session.</li>
		<li>Running the MXUnit tests deletes the users.txt file so all users will be lost.</li>
	</ul>
	<cfoutput>
		<p><strong>#encodeForHTML(message)#</strong></p>
	</cfoutput>
	<form method="post" action="/cfesapi/demo/createUser.cfm">
		<label for="username">Username</label>
		<cfoutput>
			<input type="text" name="accountName" value="#encodeForHTMLAttribute(form.accountName)#" />
		</cfoutput>
		<br />
		<label for="password">Password</label>
		<input type="password" name="password1" />
		<br />
		<label for="password">Confirm Password</label>
		<input type="password" name="password2" />
		<br />
		<button type="submit">Create User</button>
	</form>
	<p><a href="/cfesapi/demo/members/index.cfm">Login</a></p>
</body>
</html>
