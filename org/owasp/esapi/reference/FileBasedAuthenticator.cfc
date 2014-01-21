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
<cfcomponent implements="org.owasp.esapi.Authenticator" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Authenticator interface. This reference implementation is backed by a simple text file that contains serialized information about users. Many organizations will want to create their own implementation of the methods provided in the Authenticator interface backed by their own user repository. This reference implementation captures information about users in a simple text file format that contains user information separated by the pipe '|' character.">

	<cfscript>
		System = createObject("java", "java.lang.System");

		variables.ESAPI = "";

		/** Key for user in session */
		variables.USER = "ESAPIUserSessionKey";

		/** The logger. */
		variables.logger = "";

		/** The file that contains the user db */
		variables.userDB = "";

		/** How frequently to check the user db for external modifications */
		variables.checkInterval = 60 * 1000;

		/** The last modified time we saw on the user db. */
		variables.lastModified = 0;

		/** The last time we checked if the user db had been modified externally */
		variables.lastChecked = 0;

		variables.MAX_ACCOUNT_NAME_LENGTH = 250;
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.reference.AnonymousUser" name="getAnonymousUserInstance" output="false">
		<cfscript>
			return createObject("component", "org.owasp.esapi.reference.AnonymousUser").init(variables.ESAPI);
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="org.owasp.esapi.reference.DefaultUser" name="getDefaultUserInstance" output="false">
		<cfargument required="true" type="String" name="accountName">
		<cfscript>
			return createObject("component", "org.owasp.esapi.reference.DefaultUser").init(variables.ESAPI, arguments.accountName);
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="setHashedPassword" output="false"
	            hint="Add a hash to a User's hashed password list.  This method is used to store a user's old password hashes to be sure that any new passwords are not too similar to old passwords.">
		<cfargument required="true" type="org.owasp.esapi.User" name="user" hint="the user to associate with the new hash"/>
		<cfargument required="true" type="String" name="hash" hint="the hash to store in the user's password hash list"/>

		<cfscript>
			var hashes = getAllHashedPasswords(arguments.user, true);
			arrayPrepend(hashes, arguments.hash);
			if(hashes.size() > variables.ESAPI.securityConfiguration().getMaxOldPasswordHashes())
				hashes.remove(hashes.size() - 1);
			variables.passwordMap.put(arguments.user.getAccountId(), hashes);
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "New hashed password stored for " & arguments.user.getAccountName());
		</cfscript>

	</cffunction>

	<cffunction returntype="String" name="getHashedPassword" output="false" hint="Return the specified User's current hashed password.">
		<cfargument required="true" type="org.owasp.esapi.User" name="user" hint="this User's current hashed password will be returned"/>

		<cfscript>
			var hashes = getAllHashedPasswords(arguments.user, false);
			if(arrayLen(hashes)) {
				return hashes[1];
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction returntype="void" name="setOldPasswordHashes" output="false" hint="Set the specified User's old password hashes.  This will not set the User's current password hash.">
		<cfargument required="true" type="org.owasp.esapi.User" name="user" hint="the User's whose old password hashes will be set"/>
		<cfargument required="true" type="Array" name="oldHashes" hint="a list of the User's old password hashes"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";

			var hashes = getAllHashedPasswords(arguments.user, true);
			if(hashes.size() > 1)
				hashes.removeAll(hashes.subList(1, hashes.size() - 1));
			for(i = 1; i <= arrayLen(arguments.oldHashes); i++) {
				arrayAppend(hashes, arguments.oldHashes[i]);
			}
			variables.passwordMap.put(arguments.user.getAccountId(), hashes);
		</cfscript>

	</cffunction>

	<cffunction returntype="Array" name="getAllHashedPasswords" output="false" hint="Returns all of the specified User's hashed passwords.  If the User's list of passwords is null, and create is set to true, an empty password list will be associated with the specified User and then returned. If the User's password map is null and create is set to false, an exception will be thrown.">
		<cfargument required="true" type="org.owasp.esapi.User" name="user" hint="the User whose old hashes should be returned"/>
		<cfargument required="true" type="boolean" name="create" hint="true - if no password list is associated with this user, create one; false - if no password list is associated with this user, do not create one"/>

		<cfscript>
			var hashes = variables.passwordMap.get(arguments.user.getAccountId());
			if(isDefined("hashes") && !isNull(hashes))
				return hashes;
			if(arguments.create) {
				hashes = [];
				variables.passwordMap.put(arguments.user.getAccountId(), hashes);
				return hashes;
			}
			throw(object=createObject("java", "java.lang.RuntimeException").init("No hashes found for " & arguments.user.getAccountName() & ". Is User.hashcode() and equals() implemented correctly?"));
		</cfscript>

	</cffunction>

	<cffunction returntype="Array" name="getOldPasswordHashes" output="false" hint="Get a List of the specified User's old password hashes.  This will not return the User's current password hash.">
		<cfargument required="true" type="org.owasp.esapi.User" name="user" hint="the user whose old password hashes should be returned"/>

		<cfscript>
			var hashes = getAllHashedPasswords(arguments.user, false);
			if(hashes.size() > 1) {
				return duplicate(listToArray(listRest(arrayToList(hashes))));
			}
			return arrayNew(1);
		</cfscript>

	</cffunction>

	<cfscript>
		/** The user map. */
		this.userMap = {};

		// Map<User, List<String>>, where the strings are password hashes, with the current hash in entry 0
		variables.passwordMap = {};

		/**
		 * The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an
		 * application. Otherwise, each thread would have to pass the User object through the calltree to any methods that
		 * need it. Because we want exceptions and log calls to contain user data, that could be almost anywhere. Therefore,
		 * the ThreadLocal approach simplifies things greatly. <P> As a possible extension, one could create a delegation
		 * framework by adding another ThreadLocal to hold the delegating user identity.
		 */
		variables.currentUser = "";
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.Authenticator" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("Authenticator");

			variables.currentUser = createObject("component", "FileBasedAuthenticator$ThreadLocalUser").init(variables.ESAPI);

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="clearCurrent" output="false">

		<cfscript>
			// variables.logger.logWarning(createObject("java", "org.owasp.esapi.Logger").SECURITY, "************Clearing threadlocals. Thread" & Thread.currentThread().getName() );
			variables.currentUser.remove();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="org.owasp.esapi.User" name="createUser" output="false">
		<cfargument required="true" type="String" name="accountName"/>
		<cfargument required="true" type="String" name="password1"/>
		<cfargument required="true" type="String" name="password2"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";

			loadUsersIfNecessary();
			if(isNull(arguments.accountName)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(variables.ESAPI, "Account creation failed", "Attempt to create user with null accountName"));
			}
			if(isObject(getUserByAccountName(arguments.accountName))) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(variables.ESAPI, "Account creation failed", "Duplicate user creation denied for " & arguments.accountName));
			}

			verifyAccountNameStrength(arguments.accountName);

			if(isNull(arguments.password1)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Invalid account name", "Attempt to create account " & arguments.accountName & " with a null password"));
			}

			user = getDefaultUserInstance(arguments.accountName);

			verifyPasswordStrength(newPassword=arguments.password1, user=user);

			if(!arguments.password1.equals(arguments.password2))
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Passwords do not match", "Passwords for " & arguments.accountName & " do not match"));

			try {
				setHashedPassword(user, hashPassword(arguments.password1, arguments.accountName));
			}
			catch(org.owasp.esapi.errors.EncryptionException ee) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI, "Internal error", "Error hashing password for " & arguments.accountName, ee));
			}
			this.userMap.put(user.getAccountId(), user);
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "New user created: " & arguments.accountName);
			saveUsers();
			return user;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="exists" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			return isObject(getUserByAccountName(arguments.accountName));
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="_generateStrongPassword" output="false"
	            hint="Generate a strong password that is not similar to the specified old password.">
		<cfargument required="true" type="String" name="oldPassword" hint="the password to be compared to the new password for similarity"/>

		<cfscript>
			var encoder = createObject("java", "org.owasp.esapi.reference.DefaultEncoder");
			var r = variables.ESAPI.randomizer();
			var letters = r.getRandomInteger(4, 6);// inclusive, exclusive
			var digits = 7 - letters;
			var passLetters = r.getRandomString(letters, encoder.CHAR_PASSWORD_LETTERS);
			var passDigits = r.getRandomString(digits, encoder.CHAR_PASSWORD_DIGITS);
			var passSpecial = r.getRandomString(1, encoder.CHAR_PASSWORD_SPECIALS);
			var newPassword = passLetters & passSpecial & passDigits;
			return newPassword;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfargument required="true" type="org.owasp.esapi.User" name="user"/>
		<cfargument required="true" type="String" name="currentPassword"/>
		<cfargument required="true" type="String" name="newPassword"/>
		<cfargument required="true" type="String" name="newPassword2"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var currentHash = "";
			var verifyHash = "";
			var newHash = "";

			var accountName = arguments.user.getAccountName();
			try {
				currentHash = getHashedPassword(arguments.user);
				verifyHash = hashPassword(arguments.currentPassword, accountName);
				if(!currentHash.equals(verifyHash)) {
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Password change failed", "Authentication failed for password change on user: " & accountName));
				}
				if(isNull(arguments.newPassword) || isNull(arguments.newPassword2) || !arguments.newPassword.equals(arguments.newPassword2)) {
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Password change failed", "Passwords do not match for password change on user: " & accountName));
				}
				verifyPasswordStrength(arguments.currentPassword, arguments.newPassword, arguments.user);
				newHash = hashPassword(arguments.newPassword, accountName);
				if(arrayFind(getOldPasswordHashes(arguments.user), newHash)) {
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Password change failed", "Password change matches a recent password for user: " & accountName));
				}
				setHashedPassword(arguments.user, newHash);
				arguments.user.setLastPasswordChangeTime(now());
				variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Password changed for user: " & accountName);
			}
			catch(org.owasp.esapi.errors.EncryptionException ee) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI, "Password change failed", "Encryption exception changing password for " & accountName, ee));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false">
		<cfargument required="true" type="org.owasp.esapi.User" name="user"/>
		<cfargument required="true" type="String" name="password"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var attemptedHash = "";
			var currentHash = "";

			var accountName = arguments.user.getAccountName();
			try {
				attemptedHash = hashPassword(arguments.password, accountName);
				currentHash = getHashedPassword(arguments.user);
				if(attemptedHash.equals(currentHash)) {
					arguments.user.setLastLoginTime(now());
					arguments.user.setFailedLoginCount(0);
					variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Password verified for " & accountName);
					return true;
				}
			}
			catch(org.owasp.esapi.errors.EncryptionException e) {
				variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, "Encryption error verifying password for " & accountName);
			}
			variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, "Password verification failed for " & accountName);
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="generateStrongPassword" output="false">
		<cfargument type="org.owasp.esapi.User" name="user"/>
		<cfargument type="String" name="oldPassword"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var newPassword = "";

			if(structKeyExists(arguments, "user") && structKeyExists(arguments, "oldPassword")) {
				newPassword = _generateStrongPassword(arguments.oldPassword);
				if(isDefined("newPassword") && !isNull(newPassword))
					variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Generated strong password for " & arguments.user.getAccountName());
				return newPassword;
			}
			else {
				return _generateStrongPassword("");
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="org.owasp.esapi.User" name="getCurrentUser" output="false"
	            hint="Returns the currently logged user as set by the setCurrentUser() methods. Must not log in this method because the logger calls getCurrentUser() and this could cause a loop.">

		<cfscript>
			var user = variables.currentUser.get();
			if(!isObject(user)) {
				user = getAnonymousUserInstance();
			}
			return user;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserByAccountId" output="false">
		<cfargument required="true" type="numeric" name="accountId"/>

		<cfscript>
			if(arguments.accountId == 0) {
				return getAnonymousUserInstance();
			}
			loadUsersIfNecessary();
			if(structKeyExists(this.userMap, arguments.accountId)) {
				return this.userMap.get(arguments.accountId);
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserByAccountName" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var u = "";

			if(isNull(arguments.accountName)) {
				return getAnonymousUserInstance();
			}
			loadUsersIfNecessary();
			for(u in this.userMap) {
				if(this.userMap[u].getAccountName().equalsIgnoreCase(arguments.accountName))
					return this.userMap[u];
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserFromSession" output="false" hint="Gets the user from session.">
		<cfargument name="httpRequest" default="#variables.ESAPI.httpUtilities().getCurrentRequest()#"/>

		<cfscript>
			var httpSession = arguments.httpRequest.getSession(false);
			if(isNull(httpSession) || !isObject(httpSession))
				return "";
			return httpSession.getAttribute(variables.USER);
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserFromRememberToken" output="false" hint="Returns the user if a matching remember token is found, or null if the token is missing, token is corrupt, token is expired, account name does not match and existing account, or hashed password does not match user's hashed password.">
		<cfargument name="httpRequest" default="#variables.ESAPI.httpUtilities().getCurrentRequest()#"/>
		<cfargument name="httpResponse" default="#variables.ESAPI.httpUtilities().getCurrentResponse()#"/>

		<cfscript>
			var data = "";
			var username = "";
			var password = "";
			var user = "";

			var token = variables.ESAPI.httpUtilities().getCookie(arguments.httpRequest, variables.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);
			if(!isObject(token)) {
				return "";
			}

			data = "";
			try {
				data = variables.ESAPI.encryptor().unseal(token.getValue()).split(":");
			}
			catch(org.owasp.esapi.errors.EncryptionException e) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Found corrupt or expired remember token");
				variables.ESAPI.httpUtilities().killCookie(arguments.httpRequest, arguments.httpResponse, variables.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);
				return "";
			}

			if(arrayLen(data) != 3) {
				return "";
			}
			// data[1] is a random nonce, which can be ignored
			username = data[2];
			password = data[3];
			user = getUserByAccountName(username);
			if(!isObject(user)) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Found valid remember token but no user matching " & username);
				return "";
			}

			variables.logger.warning(getSecurityType("SECURITY_SUCCESS"), true, "Logging in user with remember token: " & user.getAccountName());
			try {
				user.loginWithPassword(password);
			}
			catch(org.owasp.esapi.errors.AuthenticationException ae) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Login via remember me cookie failed for user " & username, ae);
				variables.ESAPI.httpUtilities().killCookie(arguments.httpRequest, arguments.httpResponse, HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME);
				return "";
			}
			return user;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getUserNames" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var results = "";
			var u = "";

			loadUsersIfNecessary();
			results = [];
			for(u in this.userMap) {
				results.add(this.userMap[u].getAccountName());
			}
			return results;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="hashPassword" output="false">
		<cfargument required="true" type="String" name="password"/>
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			var salt = arguments.accountName.toLowerCase();
			return variables.ESAPI.encryptor().hashString(arguments.password, salt);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="loadUsersIfNecessary" output="false"
	            hint="Load users if they haven't been loaded in a while.">

		<cfscript>
			// CF8 requires 'var' at the top
			var timestamp = "";

			if(isNull(variables.userDB) || !isObject(variables.userDB)) {
				variables.userDB = createObject("java", "java.io.File").init(expandPath(variables.ESAPI.securityConfiguration().getResourceDirectory()), "users.txt");
			}

			// We only check at most every checkInterval milliseconds
			timestamp = System.currentTimeMillis();
			if(timestamp - variables.lastChecked < variables.checkInterval) {
				return;
			}
			variables.lastChecked = timestamp;

			if(variables.lastModified == variables.userDB.lastModified()) {
				return;
			}
			loadUsersImmediately();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="loadUsersImmediately" output="false"
	            hint="file was touched so reload it">

		<cfscript>
			// CF8 requires 'var' at the top
			var reader = "";
			var map = "";
			var line = "";
			var user = "";

			variables.logger.trace(getSecurityType("SECURITY_SUCCESS"), true, "Loading users from " & variables.userDB.getAbsolutePath());

			reader = "";
			try {
				map = {};
				reader = createObject("java", "java.io.BufferedReader").init(createObject("java", "java.io.FileReader").init(variables.userDB));
				line = reader.readLine();
				while(isDefined("line") && !isNull(line)) {
					if(line.length() > 0 && line.charAt(0) != chr(35)) {
						user = _createUser(line);
						if(map.containsKey(javaCast("long", user.getAccountId()))) {
							variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, "Problem in user file. Skipping duplicate user: " & user);
						}
						map.put(user.getAccountId(), user);
					}
					line = reader.readLine();
				}
				this.userMap = map;
				variables.lastModified = System.currentTimeMillis();
				variables.logger.trace(getSecurityType("SECURITY_SUCCESS"), true, "User file reloaded: " & map.size());
			}
			catch(java.lang.Exception e) {
				variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, "Failure loading user file: " & variables.userDB.getAbsolutePath(), e);
			}
			try {
				if(isObject(reader)) {
					reader.close();
				}
			}
			catch(java.io.IOException e) {
				variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, "Failure closing user file: " & variables.userDB.getAbsolutePath(), e);
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="org.owasp.esapi.reference.DefaultUser" name="_createUser" output="false"
	            hint="Create a new user with all attributes from a String.  The format is: [ accountId | accountName | password | roles (comma separated) | unlocked | enabled | old password hashes (comma separated) | last host address | last password change time | last long time | last failed login time | expiration time | failed login count ] This method verifies the account name and password strength, creates a new CSRF token, then returns the newly created user.">
		<cfargument required="true" type="String" name="line" hint="parameters to set as attributes for the new User."/>

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var password = "";
			var roles = "";
			var i = "";
			var jDate = createObject("java", "java.util.Date");

			var parts = arguments.line.split(" *\| *");
			var accountIdString = parts[1];
			var accountId = javaCast("long", accountIdString);
			var accountName = parts[2];

			verifyAccountNameStrength(accountName);
			user = getDefaultUserInstance(accountName);
			user.accountId = accountId;

			password = parts[3];
			verifyPasswordStrength(newPassword=password, user=user);
			setHashedPassword(user, password);

			roles = parts[4].toLowerCase().split(" *, *");
			for(i = 1; i <= arrayLen(roles); i++)
				if("" != roles[i])
					user.addRole(roles[i]);
			if("unlocked" != parts[5])
				user.lock();
			if("enabled" == parts[6]) {
				user.enable();
			}
			else {
				user.disable();
			}

			// generate a new csrf token
			user.resetCSRFToken();

			setOldPasswordHashes(user, parts[7].split(" *, *"));
			user.setLastHostAddress(iif("local" == parts[8], de(''), de(parts[8])));
			user.setLastPasswordChangeTime(jDate.init(javaCast("long", parts[9])));
			user.setLastLoginTime(jDate.init(javaCast("long", parts[10])));
			user.setLastFailedLoginTime(jDate.init(javaCast("long", parts[11])));
			user.setExpirationTime(jDate.init(javaCast("long", parts[12])));
			user.setFailedLoginCount(int(parts[13]));
			return user;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="org.owasp.esapi.User" name="loginWithUsernameAndPassword" output="false"
	            hint="Utility method to extract credentials and verify them.">
		<cfargument required="true" name="httpRequest" hint="The current HTTP request"/>
		<cfargument required="true" name="httpResponse" hint="The HTTP response being prepared"/>

		<cfscript>
			var username = arguments.httpRequest.getParameter(variables.ESAPI.securityConfiguration().getUsernameParameterName());
			var password = arguments.httpRequest.getParameter(variables.ESAPI.securityConfiguration().getPasswordParameterName());

			// if a logged-in user is requesting to login, log them out first
			var user = getCurrentUser();
			if(isObject(user) && !user.isAnonymous()) {
				variables.logger.warning(getSecurityType("SECURITY_SUCCESS"), true, "User requested relogin. Performing logout then authentication");
				user.logout();
			}

			// now authenticate with username and password
			if(isNull(username) || isNull(password)) {
				if(isNull(username)) {
					username = "unspecified user";
				}
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Authentication failed", "Authentication failed for " & username & " because of null username or password"));
			}
			user = getUserByAccountName(username);
			if(!isObject(user)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Authentication failed", "Authentication failed because user " & username & " doesn't exist"));
			}
			user.loginWithPassword(password);

			arguments.httpRequest.setAttribute(user.getCSRFToken(), "authenticated");
			return user;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeUser" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";

			loadUsersIfNecessary();
			user = getUserByAccountName(arguments.accountName);
			if(!isObject(user)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(variables.ESAPI, "Remove user failed", "Can't remove invalid accountName " & arguments.accountName));
			}
			this.userMap.remove(createObject("java", "java.lang.Long").init(user.getAccountId()));
			System.out.println("Removing user " & user.getAccountName());
			variables.passwordMap.remove(user.getAccountId());
			saveUsers();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="saveUsers" output="false"
	            hint="Save users.">
		<cfargument required="false" name="writer" hint="the print writer to use for saving"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var accountName = "";
			var u = "";
			var printWriter = "";

			if(structKeyExists(arguments, "writer")) {
				i = getUserNames().iterator();
				while(i.hasNext()) {
					accountName = i.next();
					u = getUserByAccountName(accountName);
					if(isObject(u) && !u.isAnonymous()) {
						arguments.writer.println(save(u));
					}
					else {
						createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Problem saving user", "Skipping save of user " & accountName);
					}
				}
			}
			else {
				printWriter = "";
				try {
					printWriter = createObject("java", "java.io.PrintWriter").init(createObject("java", "java.io.FileWriter").init(variables.userDB));
					printWriter.println("## This is the user file associated with the ESAPI library from http://www.owasp.org");
					printWriter.println("## accountId | accountName | hashedPassword | roles | locked | enabled | oldPasswordHashes | lastHostAddress | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount");
					printWriter.println();
					saveUsers(printWriter);
					printWriter.flush();
					variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "User file written to disk");
				}
				catch(java.io.IOException e) {
					variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, "Problem saving user file " & variables.userDB.getAbsolutePath(), e);
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI, "Internal Error", "Problem saving user file " & variables.userDB.getAbsolutePath(), e));
				}
				if(isObject(printWriter)) {
					printWriter.close();
					variables.lastModified = variables.userDB.lastModified();
					variables.lastChecked = variables.lastModified;
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="save" output="false"
	            hint="Save.">
		<cfargument required="true" type="org.owasp.esapi.reference.DefaultUser" name="user" hint="the User to save"/>

		<cfscript>
			var sb = createObject("java", "java.lang.StringBuffer").init();
			sb.append(arguments.user.getAccountId());
			sb.append(" | ");
			sb.append(arguments.user.getAccountName());
			sb.append(" | ");
			sb.append(getHashedPassword(arguments.user));
			sb.append(" | ");
			sb.append(arrayToList(arguments.user.getRoles()));
			sb.append(" | ");
			sb.append(iif(arguments.user.isLocked(), de("locked"), de("unlocked")));
			sb.append(" | ");
			sb.append(iif(arguments.user.isEnabled(), de("enabled"), de("disabled")));
			sb.append(" | ");
			sb.append(arrayToList(getOldPasswordHashes(arguments.user)));
			sb.append(" | ");
			sb.append(arguments.user.getLastHostAddress());
			sb.append(" | ");
			sb.append(arguments.user.getLastPasswordChangeTime().getTime());
			sb.append(" | ");
			sb.append(arguments.user.getLastLoginTime().getTime());
			sb.append(" | ");
			sb.append(arguments.user.getLastFailedLoginTime().getTime());
			sb.append(" | ");
			sb.append(arguments.user.getExpirationTime().getTime());
			sb.append(" | ");
			sb.append(arguments.user.getFailedLoginCount());
			return sb.toString();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="org.owasp.esapi.User" name="login" output="false">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="httpResponse"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var httpSession = "";

			if(!isObject(arguments.httpRequest) || !isObject(arguments.httpResponse)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Invalid request", "Request or response objects were null"));
			}

			// if there's a user in the session then use that
			user = getUserFromSession(arguments.httpRequest);

			// else if there's a remember token then use that
			if(!(isDefined("user") && !isNull(user) && isObject(user))) {
				user = getUserFromRememberToken(arguments.httpRequest, arguments.httpResponse);
			}

			// else try to verify credentials - throws exception if login fails
			if(!(isDefined("user") && !isNull(user) && isObject(user))) {
				user = loginWithUsernameAndPassword(arguments.httpRequest, arguments.httpResponse);

				// warn if this authentication request was not POST or non-SSL connection, exposing credentials or session id
				try {
					variables.ESAPI.httpUtilities().assertSecureRequest(arguments.httpRequest);
				}
				catch(org.owasp.esapi.errors.AccessControlException e) {
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI, "Attempt to login with an insecure request", e.detail, e));
				}
			}

			// if we have a user, verify we are on SSL (POST not required)
			else {

				// warn if this authentication request was non-SSL connection, exposing session id
				if (!variables.ESAPI.httpUtilities().isSecureChannel(arguments.httpRequest)) {
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI, "Attempt to access secure content with an insecure request", "Received non-SSL request"));
				}
			}

			// set last host address
			user.setLastHostAddress(arguments.httpRequest.getRemoteHost());

			// don't let anonymous user log in
			if(user.isAnonymous()) {
				user.logout();
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, "Login failed", "Anonymous user cannot be set to current user. User: " & user.getAccountName()));
			}

			// don't let disabled users log in
			if(!user.isEnabled()) {
				user.logout();
				user.incrementFailedLoginCount();
				user.setLastFailedLoginTime(now());
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, "Login failed", "Disabled user cannot be set to current user. User: " & user.getAccountName()));
			}

			// don't let locked users log in
			if(user.isLocked()) {
				user.logout();
				user.incrementFailedLoginCount();
				user.setLastFailedLoginTime(now());
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, "Login failed", "Locked user cannot be set to current user. User: " & user.getAccountName()));
			}

			// don't let expired users log in
			if(user.isExpired()) {
				user.logout();
				user.incrementFailedLoginCount();
				user.setLastFailedLoginTime(now());
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, "Login failed", "Expired user cannot be set to current user. User: " & user.getAccountName()));
			}

			// check session inactivity timeout
			if(user.isSessionTimeout()) {
				user.logout();
				user.incrementFailedLoginCount();
				user.setLastFailedLoginTime(now());
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, "Login failed", "Session inactivity timeout: " & user.getAccountName()));
			}

			// check session absolute timeout
			if(user.isSessionAbsoluteTimeout()) {
				user.logout();
				user.incrementFailedLoginCount();
				user.setLastFailedLoginTime(now());
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, "Login failed", "Session absolute timeout: " & user.getAccountName()));
			}

			// create new session for this User
			httpSession = arguments.httpRequest.getSession();
			user.addSession(httpSession);
			httpSession.setAttribute(variables.USER, user);
			setCurrentUser(user);
			return user;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="logout" output="false">

		<cfscript>
			var user = getCurrentUser();
			if(isObject(user) && !user.isAnonymous()) {
				user.logout();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCurrentUser" output="false">
		<cfargument required="true" type="org.owasp.esapi.User" name="user"/>

		<cfscript>
			variables.currentUser.setUser(arguments.user);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="verifyAccountNameStrength" output="false"
	            hint="This implementation simply verifies that account names are at least 5 characters long. This helps to defeat a brute force attack, however the real strength comes from the name length and complexity.">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			if(isNull(arguments.accountName)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Invalid account name", "Attempt to create account with a null account name"));
			}
			if(!variables.ESAPI.validator().isValidInput("verifyAccountNameStrength", arguments.accountName, "AccountName", variables.MAX_ACCOUNT_NAME_LENGTH, false)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Invalid account name", "New account name is not valid: " & arguments.accountName));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="verifyPasswordStrength" output="false"
	            hint="This implementation checks: - for any 3 character substrings of the old password - for use of a length character sets &gt; 16 (where character sets are upper, lower, digit, and special">
		<cfargument type="String" name="oldPassword"/>
		<cfargument required="true" type="String" name="newPassword"/>
		<cfargument required="true" type="org.owasp.esapi.User" name="user"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var length = "";
			var i = "";
			var sub = "";
			var charsets = "";
			var strength = "";
			var accountName = "";

			if(isNull(arguments.newPassword))
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Invalid password", "New password cannot be null"));

			// can't change to a password that contains any 3 character substring of old password
			if(structKeyExists(arguments, "oldPassword") && !isNull(arguments.oldPassword)) {
				length = arguments.oldPassword.length();
				for(i = 0; i < length - 2; i++) {
					sub = arguments.oldPassword.substring(i, i + 3);
					if(arguments.newPassword.indexOf(sub) > -1) {
						throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Invalid password", "New password cannot contain pieces of old password"));
					}
				}
			}

			// new password must have enough character sets and length
			charsets = 0;
			jArrays = createObject("java", "java.util.Arrays");
			jEncoder = createObject("java", "org.owasp.esapi.reference.DefaultEncoder");
			for(i = 0; i < arguments.newPassword.length(); i++) {
				if(jArrays.binarySearch(jEncoder.CHAR_LOWERS, arguments.newPassword.charAt(i)) > 0) {
					charsets++;
					break;
				}
			}
			for(i = 0; i < arguments.newPassword.length(); i++) {
				if(jArrays.binarySearch(jEncoder.CHAR_UPPERS, arguments.newPassword.charAt(i)) > 0) {
					charsets++;
					break;
				}
			}
			for(i = 0; i < arguments.newPassword.length(); i++) {
				if(jArrays.binarySearch(jEncoder.CHAR_DIGITS, arguments.newPassword.charAt(i)) > 0) {
					charsets++;
					break;
				}
			}
			for(i = 0; i < arguments.newPassword.length(); i++) {
				if(jArrays.binarySearch(jEncoder.CHAR_SPECIALS, arguments.newPassword.charAt(i)) > 0) {
					charsets++;
					break;
				}
			}

			// [serialization] release reference
			jEncoder = "";

			// calculate and verify password strength
			strength = arguments.newPassword.length() * charsets;
			if(strength < 16) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Invalid password", "New password is not long and complex enough"));
			}

			accountName = arguments.user.getAccountName();

			//jtm - 11/3/2010 - fix for bug http://code.google.com/p/owasp-esapi-java/issues/detail?id=108
			if (accountName.equalsIgnoreCase(arguments.newPassword)) {
				//password can't be account name
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, "Invalid password", "Password matches account name, irrespective of case"));
			}
		</cfscript>

	</cffunction>

</cfcomponent>