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
<!---
    * Fail safe main program to add or update an account in an emergency.
    *
    * Warning: this method does not perform the level of validation and checks
    * generally required in ESAPI, and can therefore be used to create a username and password that do not comply
    * with the username and password strength requirements.
    --->
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8"/>
		<title>
			FileBasedAuthenticator Fail Safe
		</title>
	</head>
	<body>
		<p>
			Fail safe main program to add or update an account in an emergency.
		</p>
		<p>
			Warning: this method does not perform the level of validation and checks generally required in
			ESAPI, and can therefore be used to create a username and password that do not comply with the
			username and password strength requirements.
		</p>

		<cfscript>
			if(cgi.request_method == "post") {
				ESAPI = createObject("component", "org.owasp.esapi.ESAPI").init();
				ESAPI.securityConfiguration().setResourceDirectory("../test/resources/");

				if(listLen(form.fieldNames) != 3) {
					writeOutput("<p>Usage: Authenticator accountname password role</p>");
					return;
				}
				auth = ESAPI.authenticator();
				accountName = form.accountName.toLowerCase();
				password = form.password;
				role = form.role;
				user = auth.getUserByAccountName(form.accountName);
				if(!isObject(user)) {
					user = createObject("component", "org.owasp.esapi.reference.DefaultUser").init(ESAPI, accountName);
					newHash = auth.hashPassword(password, accountName);
					auth.setHashedPassword(user, newHash);
					user.addRole(role);
					user.enable();
					user.unlock();
					auth.userMap.put(javaCast("long", user.getAccountId()), user);
					writeOutput("<p>New user created: " & accountName & "</p>");
					auth.saveUsers();
					writeOutput("<p>User account " & user.getAccountName() & " updated</p>");
				}
				else {
					writeOutput("<p>User account " & user.getAccountName() & " already exists!</p>");
				}
			}
		</cfscript>

		<form method="post">
			<label for="accountName">
				Account Name
			</label>
			<input type="text" id="accountName" name="accountName" required="required"/>
			<br/>
			<label for="password">
				Password
			</label>
			<input type="password" id="password" name="password" required="required"/>
			<br/>
			<label for="role">
				Role
			</label>
			<input type="text" id="role" name="role" required="required"/>
			<br/>
			<button type="submit">
				Submit
			</button>
		</form>
	</body>
</html>