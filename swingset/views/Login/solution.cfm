﻿<cfoutput>
<div id="navigation">
	<a href="#buildURL('')#">Home</a> |
	<a href="#buildURL('Login')#">Tutorial</a> |
	<a href="#buildURL('Login.lab')#">Lab : Authenticator Functions</a>|
	<b><a href="#buildURL('Login.solution')#">Solution</a></b>
</div>
</cfoutput>
<div id="header"></div>
<p>
<hr>
<h2>Authenticator Methods Solution</h2>
<cfoutput>
<h4>CFM Location: #getCurrentTemplatePath()#</h4>
</cfoutput>
<p>The following CFM creates a user account with - ESAPI().authenticator().createUser()</p>
<p>And logs the user in with ESAPI().authenticator().login()</p>
<p>After creating a user you should see a users.txt file in your .esapi folder.</p>
<p>Please see the source of the CFM for full details.</p>
<cfscript>

	user = "";

	try {
		if (structKeyExists(form, "create_username")){
			ESAPI().authenticator().createUser(form.create_username, form.create_password1, form.create_password2);
			ESAPI().authenticator().getUserByAccountName(form.create_username).enable();
			ESAPI().authenticator().getUserByAccountName(form.create_username).unlock();
			ESAPI().currentRequest().setAttribute("userMessage", "User " & form.create_username & " Created");
			ESAPI().currentRequest().setAttribute("logMessage", "User Created");
			writeOutput("User Created : " & form.create_username );
		}
		else {
			user = ESAPI().authenticator().login(ESAPI().currentRequest(), ESAPI().currentResponse());
			writeOutput("Current User: " & user.getAccountName() & "<br>");
			writeOutput("Last Successful Login: " & user.getLastLoginTime() & "<br>");
			writeOutput("Last Failed Login: " & user.getLastFailedLoginTime() & "<br>");
			writeOutput("Failed Login Count: " & user.getFailedLoginCount() & "<br>");
			writeOutput("Current Roles: " & user.getRoles() & "<br>");
			writeOutput("Last Host Name: " & user.getLastHostAddress() & "><br>");
			writeOutput("Current Cookies: <br />");
			cookies = ESAPI().httpUtilities().getCurrentRequest().getCookies();
			for (i=0; i<cookies.length; i++) {
				writeOutput( "&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp " & cookies[i].getName() & "=" & cookies[i].getValue() & "; <br />" );
			}
			writeOutput("Browser Cookies: <script>document.write(document.cookie)</script><br><br>");
			writeOutput('<a href="main?function=Login&logout&solution">logout</a>');
		}
	}
	// authentication failure
	catch( esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e ) {
		ESAPI().currentRequest().setAttribute("userMessage", e.message );
		ESAPI().currentRequest().setAttribute("logMessage", e.detail );
		e.printStackTrace();
	}
	// duplicate accountName
	catch( esapi4cf.org.owasp.esapi.errors.AuthenticationAccountsException e ) {
		ESAPI().currentRequest().setAttribute("userMessage", e.message );
		ESAPI().currentRequest().setAttribute("logMessage", e.detail );
		e.printStackTrace();
	}
	catch( Exception e){
		ESAPI().currentRequest().setAttribute("userMessage", e.message);
		e.printStackTrace();
	}
</cfscript>
<cfif user EQ "" OR user.isAnonymous() >
<cfoutput>
	<h2>Create User</h2>
	<form action="#buildURL('Login.solution')#" method="POST">
		<table>
			<tr>
				<td>Username:</td><td><input name="create_username"></td>
			</tr>
			<tr>
				<td>Password:</td><td><input type="password" name="create_password1" autocomplete="off"></td>
			</tr>
			<tr>
				<td>Confirm Password:</td><td><input type="password" name="create_password2" autocomplete="off"></td>
			</tr>
		</table>
		<input type="submit" value="Create User"><br>
	</form>

	<h2>Please login</h2>
	<form action="#buildURL('Login.solution')#" method="POST">
		<table>
			<tr>
				<td>Username:</td><td><input name="username"></td>
			</tr>
			<tr>
				<td>Password:</td><td><input type="password" name="password" autocomplete="off"></td>
			</tr>
			<tr>
				<td>Remember me on this computer:</td>
				<td><input type="checkbox" name="remember"></td>
			</tr>
		</table>
		<input type="submit" value="login"><br>
	</form>
</cfoutput>
</cfif>
