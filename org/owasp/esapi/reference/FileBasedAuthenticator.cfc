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
			var msgParams = [];

			arrayPrepend(hashes, arguments.hash);
			if(hashes.size() > variables.ESAPI.securityConfiguration().getMaxOldPasswordHashes())
				hashes.remove(hashes.size() - 1);
			variables.passwordMap.put(arguments.user.getAccountId(), hashes);
			msgParams = [arguments.user.getAccountName()];
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, variables.ESAPI.resourceBundle().messageFormat("Authenticator_setHashedPassword_success_message", msgParams));
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
			var msgParams = [];

			if(isDefined("hashes") && !isNull(hashes))
				return hashes;
			if(arguments.create) {
				hashes = [];
				variables.passwordMap.put(arguments.user.getAccountId(), hashes);
				return hashes;
			}
			msgParams = [arguments.user.getAccountName()];
			throw(object=createObject("java", "java.lang.RuntimeException").init(variables.ESAPI.resourceBundle().messageFormat("Authenticator_getAllHashedPasswords_notFound_message", msgParams)));
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
			var msgParams = [arguments.accountName];

			loadUsersIfNecessary();
			if(isNull(arguments.accountName)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_createUser_accountNameValueMissing_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_createUser_accountNameValueMissing_logMessage", msgParams)));
			}
			if(isObject(getUserByAccountName(arguments.accountName))) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_createUser_accountNameDuplicate_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_createUser_accountNameDuplicate_logMessage", msgParams)));
			}

			verifyAccountNameStrength(arguments.accountName);

			if(isNull(arguments.password1)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_createUser_passwordValueMissing_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_createUser_passwordValueMissing_logMessage", msgParams)));
			}

			user = getDefaultUserInstance(arguments.accountName);

			verifyPasswordStrength(newPassword=arguments.password1, user=user);

			if(!arguments.password1.equals(arguments.password2))
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_createUser_passwordMismatch_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_createUser_passwordMismatch_logMessage", msgParams)));

			try {
				setHashedPassword(user, hashPassword(arguments.password1, arguments.accountName));
			}
			catch(org.owasp.esapi.errors.EncryptionException ee) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_createUser_passwordHashFailure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_createUser_passwordHashFailure_logMessage", msgParams), ee));
			}
			this.userMap.put(user.getAccountId(), user);
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, variables.ESAPI.resourceBundle().messageFormat("Authenticator_createUser_success_message", msgParams));
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
			var msgParams = [accountName];

			try {
				currentHash = getHashedPassword(arguments.user);
				verifyHash = hashPassword(arguments.currentPassword, accountName);
				if(!currentHash.equals(verifyHash)) {
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_changePassword_authenticationFailure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_changePassword_authenticationFailure_logMessage", msgParams)));
				}
				if(isNull(arguments.newPassword) || isNull(arguments.newPassword2) || !arguments.newPassword.equals(arguments.newPassword2)) {
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_changePassword_passwordMismatch_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_changePassword_passwordMismatch_logMessage", msgParams)));
				}
				verifyPasswordStrength(arguments.currentPassword, arguments.newPassword, arguments.user);
				newHash = hashPassword(arguments.newPassword, accountName);
				if(arrayFind(getOldPasswordHashes(arguments.user), newHash)) {
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_changePassword_passwordHistoryFailure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_changePassword_passwordHistoryFailure_logMessage", msgParams)));
				}
				setHashedPassword(arguments.user, newHash);
				arguments.user.setLastPasswordChangeTime(now());
				variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, variables.ESAPI.resourceBundle().messageFormat("Authenticator_changePassword_success_message", msgParams));
			}
			catch(org.owasp.esapi.errors.EncryptionException ee) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_changePassword_encyptionFailure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_changePassword_encyptionFailure_logMessage", msgParams), ee));
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
			var msgParams = [accountName];

			try {
				attemptedHash = hashPassword(arguments.password, accountName);
				currentHash = getHashedPassword(arguments.user);
				if(attemptedHash.equals(currentHash)) {
					arguments.user.setLastLoginTime(now());
					arguments.user.setFailedLoginCount(0);
					variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, variables.ESAPI.resourceBundle().messageFormat("Authenticator_verifyPassword_success_message", msgParams));
					return true;
				}
			}
			catch(org.owasp.esapi.errors.EncryptionException e) {
				variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, variables.ESAPI.resourceBundle().messageFormat("Authenticator_verifyPassword_encyptionFailure_message", msgParams));
			}
			variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, variables.ESAPI.resourceBundle().messageFormat("Authenticator_verifyPassword_failue_message", msgParams));
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="generateStrongPassword" output="false">
		<cfargument type="org.owasp.esapi.User" name="user"/>
		<cfargument type="String" name="oldPassword"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var newPassword = "";
			var msgParams = [];

			if(structKeyExists(arguments, "user") && structKeyExists(arguments, "oldPassword")) {
				newPassword = _generateStrongPassword(arguments.oldPassword);
				if(isDefined("newPassword") && !isNull(newPassword))
					variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, variables.ESAPI.resourceBundle().messageFormat("Authenticator_generateStrongPassword_success_message", msgParams));
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
			var msgParams = [];

			var token = variables.ESAPI.httpUtilities().getCookie(arguments.httpRequest, variables.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);
			if(!isObject(token)) {
				return "";
			}

			data = "";
			try {
				data = variables.ESAPI.encryptor().unseal(token.getValue()).split(":");
			}
			catch(org.owasp.esapi.errors.EncryptionException e) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, variables.ESAPI.resourceBundle().getString("Authenticator_getUserFromRememberToken_failure_message"));
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
				msgParams = [username];
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, variables.ESAPI.resourceBundle().messageFormat("Authenticator_getUserFromRememberToken_userInvalid_message", msgParams));
				return "";
			}

			msgParams = [user.getAccountName()];
			variables.logger.warning(getSecurityType("SECURITY_SUCCESS"), true, variables.ESAPI.resourceBundle().messageFormat("Authenticator_getUserFromRememberToken_success_message", msgParams));
			try {
				user.loginWithPassword(arguments.httpRequest, arguments.httpResponse, password);
			}
			catch(org.owasp.esapi.errors.AuthenticationException ae) {
				msgParams = [username];
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, variables.ESAPI.resourceBundle().messageFormat("Authenticator_getUserFromRememberToken_loginFailure_message", msgParams), ae);
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
			var msgParams = [variables.userDB.getAbsolutePath()];

			variables.logger.trace(getSecurityType("SECURITY_SUCCESS"), true, variables.ESAPI.resourceBundle().messageFormat("Authenticator_loadUsersImmediately_loading_message", msgParams));

			reader = "";
			try {
				map = {};
				reader = createObject("java", "java.io.BufferedReader").init(createObject("java", "java.io.FileReader").init(variables.userDB));
				line = reader.readLine();
				while(isDefined("line") && !isNull(line)) {
					if(line.length() > 0 && line.charAt(0) != chr(35)) {
						user = _createUser(line);
						if(map.containsKey(javaCast("long", user.getAccountId()))) {
							msgParams = [user];
							variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, variables.ESAPI.resourceBundle().messageFormat("Authenticator_loadUsersImmediately_duplicateUser_message", msgParams));
						}
						map.put(user.getAccountId(), user);
					}
					line = reader.readLine();
				}
				this.userMap = map;
				variables.lastModified = System.currentTimeMillis();
				msgParams = [map.size()];
				variables.logger.trace(getSecurityType("SECURITY_SUCCESS"), true, variables.ESAPI.resourceBundle().messageFormat("Authenticator_loadUsersImmediately_reloaded_message", msgParams));
			}
			catch(java.lang.Exception e) {
				msgParams = [variables.userDB.getAbsolutePath()];
				variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, variables.ESAPI.resourceBundle().messageFormat("Authenticator_loadUsersImmediately_loadingFailure_message", msgParams), e);
			}
			try {
				if(isObject(reader)) {
					reader.close();
				}
			}
			catch(java.io.IOException e) {
				msgParams = [variables.userDB.getAbsolutePath()];
				variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, variables.ESAPI.resourceBundle().messageFormat("Authenticator_loadUsersImmediately_closingFailure_message", msgParams), e);
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
			var msgParams = [];

			// if a logged-in user is requesting to login, log them out first
			var user = getCurrentUser();
			if(isObject(user) && !user.isAnonymous()) {
				variables.logger.warning(getSecurityType("SECURITY_SUCCESS"), true, variables.ESAPI.resourceBundle().getString("Authenticator_loginWithUsernameAndPassword_relogin_message"));
				user.logout(arguments.httpRequest, arguments.httpResponse);
			}

			// now authenticate with username and password
			if(isNull(username) || isNull(password)) {
				if(isNull(username)) {
					username = "unspecified user";
				}
				msgParams = [username];
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_loginWithUsernameAndPassword_failure_message"), variables.ESAPI.resourceBundle().messageFormat("Authenticator_loginWithUsernameAndPassword_userPassValueMissing_logMessage", msgParams)));
			}
			user = getUserByAccountName(username);
			if(!isObject(user)) {
				msgParams = [username];
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_loginWithUsernameAndPassword_failure_message"), variables.ESAPI.resourceBundle().messageFormat("Authenticator_loginWithUsernameAndPassword_userInvalid_logMessage", msgParams)));
			}
			user.loginWithPassword(arguments.httpRequest, arguments.httpResponse, password);

			arguments.httpRequest.setAttribute(user.getCSRFToken(), "authenticated");
			return user;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeUser" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var msgParams = [arguments.accountName];

			loadUsersIfNecessary();
			user = getUserByAccountName(arguments.accountName);
			if(!isObject(user)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_removeUser_userInvalid_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_removeUser_userInvalid_logMessage", msgParams)));
			}
			this.userMap.remove(user.getAccountId());
			//System.out.println("Removing user " & user.getAccountName());
			variables.passwordMap.remove(user.getAccountId());
			saveUsers();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="saveUsers" output="false"
	            hint="Save users.">
		<cfargument name="writer" hint="the print writer to use for saving"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var accountName = "";
			var u = "";
			var printWriter = "";
			var msgParams = [];

			if(structKeyExists(arguments, "writer")) {
				i = getUserNames().iterator();
				while(i.hasNext()) {
					accountName = i.next();
					u = getUserByAccountName(accountName);
					if(isObject(u) && !u.isAnonymous()) {
						arguments.writer.println(save(u));
					}
					else {
						msgParams = [accountName];
						createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_saveUsers_skippingUser_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_saveUsers_skippingUser_logMessage", msgParams));
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
					variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, variables.ESAPI.resourceBundle().messageFormat("Authenticator_saveUsers_success_message", msgParams));
				}
				catch(java.io.IOException e) {
					msgParams = [variables.userDB.getAbsolutePath()];
					variables.logger.fatal(getSecurityType("SECURITY_FAILURE"), false, variables.ESAPI.resourceBundle().messageFormat("Authenticator_saveUsers_failure_message", msgParams), e);
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_saveUsers_failure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_saveUsers_failure_logMessage", msgParams), e));
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
			var remoteHost = "";
			var msgParams = [];

			if(!isObject(arguments.httpRequest) || !isObject(arguments.httpResponse)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_login_requestResponseValueMissing_userMessage"), variables.ESAPI.resourceBundle().getString("Authenticator_login_requestResponseValueMissing_logMessage")));
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
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_login_insecureLogin_userMessage"), e.detail, e));
				}
			}

			// if we have a user, verify we are on SSL (POST not required)
			else {

				// warn if this authentication request was non-SSL connection, exposing session id
				if (!variables.ESAPI.httpUtilities().isSecureChannel(arguments.httpRequest)) {
					throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_login_insecureRequest_userMessage"), variables.ESAPI.resourceBundle().getString("Authenticator_login_insecureRequest_logMessage")));
				}
			}

			// set last host address
			remoteHost = arguments.httpRequest.getRemoteHost();
			if (isNull(remoteHost)) remoteHost = "";
			user.setLastHostAddress(remoteHost);

			msgParams = [user.getAccountName()];

			// don't let anonymous user log in
			if(user.isAnonymous()) {
				user.logout();
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_login_loginFailed_message"), variables.ESAPI.resourceBundle().messageFormat("Authenticator_login_anonymousUserAttempt_logMessage", msgParams)));
			}

			// don't let disabled users log in
			if(!user.isEnabled()) {
				user.logout(arguments.httpRequest, arguments.httpResponse);
				user.incrementFailedLoginCount();
				user.setLastFailedLoginTime(now());
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_login_loginFailed_message"), variables.ESAPI.resourceBundle().messageFormat("Authenticator_login_disabledUserAttempt_logMessage", msgParams)));
			}

			// don't let locked users log in
			if(user.isLocked()) {
				user.logout();
				user.incrementFailedLoginCount();
				user.setLastFailedLoginTime(now());
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_login_loginFailed_message"), variables.ESAPI.resourceBundle().messageFormat("Authenticator_login_lockedUserAttempt_logMessage", msgParams)));
			}

			// don't let expired users log in
			if(user.isExpired()) {
				user.logout();
				user.incrementFailedLoginCount();
				user.setLastFailedLoginTime(now());
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_login_loginFailed_message"), variables.ESAPI.resourceBundle().messageFormat("Authenticator_login_expiredUserAttempt_logMessage", msgParams)));
			}

			// check session inactivity timeout
			if(user.isSessionTimeout(arguments.httpRequest)) {
				user.logout();
				user.incrementFailedLoginCount();
				user.setLastFailedLoginTime(now());
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_login_loginFailed_message"), variables.ESAPI.resourceBundle().messageFormat("Authenticator_login_idleTimeout_logMessage", msgParams)));
			}

			// check session absolute timeout
			if(user.isSessionAbsoluteTimeout(arguments.httpRequest)) {
				user.logout();
				user.incrementFailedLoginCount();
				user.setLastFailedLoginTime(now());
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_login_loginFailed_message"), variables.ESAPI.resourceBundle().messageFormat("Authenticator_login_absoluteTimeout_logMessage", msgParams)));
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
		<cfargument name="httpRequest" default="#variables.ESAPI.currentRequest()#" hint="The current HTTP request"/>
		<cfargument name="httpResponse" default="#variables.ESAPI.currentResponse()#" hint="The HTTP response being prepared"/>

		<cfscript>
			var user = getCurrentUser();
			if(isObject(user) && !user.isAnonymous()) {
				user.logout(arguments.httpRequest, arguments.httpResponse);
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
			var msgParams = [arguments.accountName];

			if(isNull(arguments.accountName)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_verifyAccountNameStrength_accountNameValueMissing_userMessage"), variables.ESAPI.resourceBundle().getString("Authenticator_verifyAccountNameStrength_accountNameValueMissing_logMessage")));
			}
			if(!variables.ESAPI.validator().isValidInput("verifyAccountNameStrength", arguments.accountName, "AccountName", variables.MAX_ACCOUNT_NAME_LENGTH, false)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Authenticator_verifyAccountNameStrength_accountNameInvalid_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Authenticator_verifyAccountNameStrength_accountNameInvalid_logMessage", msgParams)));
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
			var msgParams = [];

			if(isNull(arguments.newPassword))
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_verifyPasswordStrength_passwordInvalid_message"), variables.ESAPI.resourceBundle().getString("Authenticator_verifyPasswordStrength_passwordValudMissing_logMessage")));

			// can't change to a password that contains any 3 character substring of old password
			if(structKeyExists(arguments, "oldPassword") && !isNull(arguments.oldPassword)) {
				length = arguments.oldPassword.length();
				for(i = 0; i < length - 2; i++) {
					sub = arguments.oldPassword.substring(i, i + 3);
					if(arguments.newPassword.indexOf(sub) > -1) {
						throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_verifyPasswordStrength_passwordInvalid_message"), variables.ESAPI.resourceBundle().getString("Authenticator_verifyPasswordStrength_passwordSubstringFailure_logMessage")));
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
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_verifyPasswordStrength_passwordInvalid_message"), variables.ESAPI.resourceBundle().getString("Authenticator_verifyPasswordStrength_passwordComplexityFailure_logMessage")));
			}

			accountName = arguments.user.getAccountName();

			//jtm - 11/3/2010 - fix for bug http://code.google.com/p/owasp-esapi-java/issues/detail?id=108
			if (accountName.equalsIgnoreCase(arguments.newPassword)) {
				//password can't be account name
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationCredentialsException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Authenticator_verifyPasswordStrength_passwordInvalid_message"), variables.ESAPI.resourceBundle().getString("Authenticator_verifyPasswordStrength_passwordMatchesAccountName_logMessage")));
			}
		</cfscript>

	</cffunction>

</cfcomponent>