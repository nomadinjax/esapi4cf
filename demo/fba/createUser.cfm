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
<cfparam name="form.accountName" type="string" default="" />
<cfscript>
	message = "";
	if (ESAPI().currentRequest().getMethod() == "post") {
		try {
			newUser = ESAPI().authenticator().createUser(form.accountName, form.password1, form.password2);
			newUser.enable();
			newUser.setRoles(listToArray(form.roles));
			// commit the enable and role changes to the users.txt file
			ESAPI().authenticator().saveUsers();
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
		<title>
			CFESAPI Demo CreateUser 
		</title>
	</head>
	<body>
		<cfinclude template="/cfesapi/demo/fba/includes/header.cfm" />
		<h2>
			Create New User
		</h2>
		<p>
			This allows you to create a username/password that will be saved to users.txt and can be used to test the FileBasedAuthenticator demo app. 
		</p>
		<cfoutput>
			<p>
				<strong>
					#encodeForHTML(message)# 
				</strong>
			</p>
		</cfoutput>
		<form method="post" action="createUser.cfm">
			<label for="roles">
				Roles 
			</label>
			<select name="roles" multiple="multiple" required="true">
				<option value="user">
					User 
				</option>
				<option value="admin">
					Administrator 
				</option>
			</select>
			<br />
			<label for="username">
				Username 
			</label>
			<cfoutput>
				<input type="text" name="accountName" required="true" value="#encodeForHTMLAttribute(form.accountName)#" />
			</cfoutput>
			<br />
			<label for="password">
				Password 
			</label>
			<input type="password" name="password1" required="true" />
			<br />
			<label for="password">
				Confirm Password 
			</label>
			<input type="password" name="password2" required="true" />
			<br />
			<button type="submit">
				Create User 
			</button>
		</form>
	</body>
</html>
