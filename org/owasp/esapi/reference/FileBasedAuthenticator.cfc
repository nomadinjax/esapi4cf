<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent implements="cfesapi.org.owasp.esapi.Authenticator" extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Authenticator interface. This reference implementation is backed by a simple text file that contains serialized information about users. Many organizations will want to create their own implementation of the methods provided in the Authenticator interface backed by their own user repository. This reference implementation captures information about users in a simple text file format that contains user information separated by the pipe '|' character.">

	<cfscript>
		instance.ESAPI = "";

		/** Key for user in session */
		instance.USER = "ESAPIUserSessionKey";

		/** The logger. */
		instance.logger = "";

		/** The file that contains the user db */
		instance.userDB = "";

		/** How frequently to check the user db for external modifications */
		instance.checkInterval = 60 * 1000;

		/** The last modified time we saw on the user db. */
		instance.lastModified = 0;

		/** The last time we checked if the user db had been modified externally */
		instance.lastChecked = 0;

		instance.MAX_ACCOUNT_NAME_LENGTH = 250;
	</cfscript>

	<cffunction access="public" returntype="void" name="setHashedPassword" output="false"
	            hint="Add a hash to a User's hashed password list.  This method is used to store a user's old password hashes to be sure that any new passwords are not too similar to old passwords.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user" hint="the user to associate with the new hash"/>
		<cfargument required="true" type="String" name="hash" hint="the hash to store in the user's password hash list"/>

		<cfscript>
			var local = {};

			local.hashes = getAllHashedPasswords( arguments.user, true );
			arrayPrepend( local.hashes, arguments.hash );
			if(local.hashes.size() > instance.ESAPI.securityConfiguration().getMaxOldPasswordHashes())
				local.hashes.remove( local.hashes.size() - 1 );
			instance.passwordMap.put( arguments.user.getAccountId(), local.hashes );
			instance.logger.info( getSecurity("SECURITY_SUCCESS"), true, "New hashed password stored for " & arguments.user.getAccountName() );
		</cfscript>

	</cffunction>

	<cffunction returntype="String" name="getHashedPassword" output="false" hint="Return the specified User's current hashed password.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user" hint="this User's current hashed password will be returned"/>

		<cfscript>
			var local = {};

			local.hashes = getAllHashedPasswords( arguments.user, false );
			if(arrayLen( local.hashes )) {
				return local.hashes[1];
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction returntype="void" name="setOldPasswordHashes" output="false" hint="Set the specified User's old password hashes.  This will not set the User's current password hash.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user" hint="the User's whose old password hashes will be set"/>
		<cfargument required="true" type="Array" name="oldHashes" hint="a list of the User's old password hashes"/>

		<cfscript>
			var local = {};

			local.hashes = getAllHashedPasswords( arguments.user, true );
			if(local.hashes.size() > 1)
				local.hashes.removeAll( local.hashes.subList( 1, local.hashes.size() - 1 ) );
			for(local.i = 1; local.i <= arrayLen( arguments.oldHashes ); local.i++) {
				arrayAppend( local.hashes, arguments.oldHashes[local.i] );
			}
			instance.passwordMap.put( arguments.user.getAccountId(), local.hashes );
		</cfscript>

	</cffunction>

	<cffunction returntype="Array" name="getAllHashedPasswords" output="false" hint="Returns all of the specified User's hashed passwords.  If the User's list of passwords is null, and create is set to true, an empty password list will be associated with the specified User and then returned. If the User's password map is null and create is set to false, an exception will be thrown.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user" hint="the User whose old hashes should be returned"/>
		<cfargument required="true" type="boolean" name="create" hint="true - if no password list is associated with this user, create one; false - if no password list is associated with this user, do not create one"/>

		<cfscript>
			var local = {};

			local.hashes = instance.passwordMap.get( arguments.user.getAccountId() );
			if(structKeyExists( local, "hashes" ))
				return local.hashes;
			if(arguments.create) {
				local.hashes = [];
				instance.passwordMap.put( arguments.user.getAccountId(), local.hashes );
				return local.hashes;
			}
			throwException( createObject( "java", "java.lang.RuntimeException" ).init( "No hashes found for " & arguments.user.getAccountName() & ". Is User.hashcode() and equals() implemented correctly?" ) );
		</cfscript>

	</cffunction>

	<cffunction returntype="Array" name="getOldPasswordHashes" output="false" hint="Get a List of the specified User's old password hashes.  This will not return the User's current password hash.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user" hint="the user whose old password hashes should be returned"/>

		<cfscript>
			var local = {};

			local.hashes = getAllHashedPasswords( arguments.user, false );
			if(local.hashes.size() > 1) {
				return duplicate( listToArray( listRest( arrayToList( local.hashes ) ) ) );
			}
			return arrayNew( 1 );
		</cfscript>

	</cffunction>

	<cfscript>
		/** The user map. */
		this.userMap = {};

		// Map<User, List<String>>, where the strings are password hashes, with the current hash in entry 0
		instance.passwordMap = {};

		/**
		 * The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an
		 * application. Otherwise, each thread would have to pass the User object through the calltree to any methods that
		 * need it. Because we want exceptions and log calls to contain user data, that could be almost anywhere. Therefore,
		 * the ThreadLocal approach simplifies things greatly. <P> As a possible extension, one could create a delegation
		 * framework by adding another ThreadLocal to hold the delegating user identity.
		 */
		instance.currentUser = "";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Authenticator" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger( "Authenticator" );

			instance.currentUser = createObject( "component", "FileBasedAuthenticator$ThreadLocalUser" ).init( instance.ESAPI );

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="clearCurrent" output="false">

		<cfscript>
			// instance.logger.logWarning(getJava("org.owasp.esapi.Logger").SECURITY, "************Clearing threadlocals. Thread" & Thread.currentThread().getName() );
			instance.currentUser.remove();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="createUser" output="false">
		<cfargument required="true" type="String" name="accountName"/>
		<cfargument required="true" type="String" name="password1"/>
		<cfargument required="true" type="String" name="password2"/>

		<cfscript>
			var local = {};

			loadUsersIfNecessary();
			if(arguments.accountName == "") {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException" ).init( instance.ESAPI, "Account creation failed", "Attempt to create user with blank accountName" ) );
			}
			if(isObject( getUserByAccountName( arguments.accountName ) )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException" ).init( instance.ESAPI, "Account creation failed", "Duplicate user creation denied for " & arguments.accountName ) );
			}

			verifyAccountNameStrength( arguments.accountName );

			if(arguments.password1 == "") {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Invalid account name", "Attempt to create account " & arguments.accountName & " with a blank password" ) );
			}
			verifyPasswordStrength( newPassword=arguments.password1 );

			if(!arguments.password1.equals( arguments.password2 ))
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Passwords do not match", "Passwords for " & arguments.accountName & " do not match" ) );

			local.user = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultUser" ).init( instance.ESAPI, arguments.accountName );
			try {
				setHashedPassword( local.user, hashPassword( arguments.password1, arguments.accountName ) );
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException ee) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationException" ).init( instance.ESAPI, "Internal error", "Error hashing password for " & arguments.accountName, ee ) );
			}
			this.userMap.put( local.user.getAccountId(), local.user );
			instance.logger.info( getSecurity("SECURITY_SUCCESS"), true, "New user created: " & arguments.accountName );
			saveUsers();
			return local.user;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="exists" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			return isObject( getUserByAccountName( arguments.accountName ) );
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="_generateStrongPassword" output="false"
	            hint="Generate a strong password that is not similar to the specified old password.">
		<cfargument required="true" type="String" name="oldPassword" hint="the password to be compared to the new password for similarity"/>

		<cfscript>
			var local = {};

			local.r = instance.ESAPI.randomizer();
			local.letters = local.r.getRandomInteger( 4, 6 );// inclusive, exclusive
			local.digits = 7 - local.letters;
			local.passLetters = local.r.getRandomString( local.letters, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_PASSWORD_LETTERS );
			local.passDigits = local.r.getRandomString( local.digits, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_PASSWORD_DIGITS );
			local.passSpecial = local.r.getRandomString( 1, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_PASSWORD_SPECIALS );
			local.newPassword = local.passLetters & local.passSpecial & local.passDigits;
			return local.newPassword;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user"/>
		<cfargument required="true" type="String" name="currentPassword"/>
		<cfargument required="true" type="String" name="newPassword"/>
		<cfargument required="true" type="String" name="newPassword2"/>

		<cfscript>
			var local = {};

			local.accountName = arguments.user.getAccountName();
			try {
				local.currentHash = getHashedPassword( arguments.user );
				local.verifyHash = hashPassword( arguments.currentPassword, local.accountName );
				if(!local.currentHash.equals( local.verifyHash )) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Password change failed", "Authentication failed for password change on user: " & local.accountName ) );
				}
				if(arguments.newPassword == "" || arguments.newPassword2 == "" || !arguments.newPassword.equals( arguments.newPassword2 )) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Password change failed", "Passwords do not match for password change on user: " & local.accountName ) );
				}
				verifyPasswordStrength( arguments.currentPassword, arguments.newPassword );
				arguments.user.setLastPasswordChangeTime( getJava( "java.util.Date" ).init() );
				local.newHash = hashPassword( arguments.newPassword, local.accountName );
				if(cf8_arrayFind( getOldPasswordHashes( arguments.user ), local.newHash )) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Password change failed", "Password change matches a recent password for user: " & local.accountName ) );
				}
				setHashedPassword( arguments.user, local.newHash );
				instance.logger.info( getSecurity("SECURITY_SUCCESS"), true, "Password changed for user: " & local.accountName );
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException ee) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationException" ).init( instance.ESAPI, "Password change failed", "Encryption exception changing password for " & local.accountName, ee ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user"/>
		<cfargument required="true" type="String" name="password"/>

		<cfscript>
			var local = {};

			local.accountName = arguments.user.getAccountName();
			try {
				local.hash = hashPassword( arguments.password, local.accountName );
				local.currentHash = getHashedPassword( arguments.user );
				if(local.hash.equals( local.currentHash )) {
					arguments.user.setLastLoginTime( getJava( "java.util.Date" ).init() );
					arguments.user.setFailedLoginCount( 0 );
					instance.logger.info( getSecurity("SECURITY_SUCCESS"), true, "Password verified for " & local.accountName );
					return true;
				}
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
				instance.logger.fatal( getSecurity("SECURITY_FAILURE"), false, "Encryption error verifying password for " & local.accountName );
			}
			instance.logger.fatal( getSecurity("SECURITY_FAILURE"), false, "Password verification failed for " & local.accountName );
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="generateStrongPassword" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user"/>
		<cfargument type="String" name="oldPassword"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "user" ) && structKeyExists( arguments, "oldPassword" )) {
				local.newPassword = _generateStrongPassword( arguments.oldPassword );
				if(structKeyExists( local, "newPassword" ))
					instance.logger.info( getSecurity("SECURITY_SUCCESS"), true, "Generated strong password for " & arguments.user.getAccountName() );
				return local.newPassword;
			}
			else {
				return _generateStrongPassword( "" );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="getCurrentUser" output="false"
	            hint="Returns the currently logged user as set by the setCurrentUser() methods. Must not log in this method because the logger calls getCurrentUser() and this could cause a loop.">

		<cfscript>
			var local = {};

			local.user = instance.currentUser.get();
			if(!isObject( local.user )) {
				local.user = createObject( "component", "cfesapi.org.owasp.esapi.User$ANONYMOUS" ).init( instance.ESAPI );
			}
			return local.user;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserByAccountId" output="false">
		<cfargument required="true" type="numeric" name="accountId"/>

		<cfscript>
			var local = {};

			if(arguments.accountId == 0) {
				return createObject( "component", "cfesapi.org.owasp.esapi.User$ANONYMOUS" ).init( instance.ESAPI );
			}
			loadUsersIfNecessary();
			if(structKeyExists( this.userMap, arguments.accountId )) {
				return this.userMap.get( arguments.accountId );
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserByAccountName" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			var local = {};

			if(arguments.accountName == "") {
				return createObject( "component", "cfesapi.org.owasp.esapi.User$ANONYMOUS" ).init( instance.ESAPI );
			}
			loadUsersIfNecessary();
			for(local.u in this.userMap) {
				if(this.userMap[local.u].getAccountName().equalsIgnoreCase( arguments.accountName ))
					return this.userMap[local.u];
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserFromSession" output="false" hint="Gets the user from session.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" default="#instance.ESAPI.httpUtilities().getCurrentRequest()#"/>

		<cfscript>
			var local = {};

			local.session = arguments.request.getSession( false );
			if(!isObject( local.session ))
				return "";
			return local.session.getAttribute( instance.USER );
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserFromRememberToken" output="false" hint="Returns the user if a matching remember token is found, or null if the token is missing, token is corrupt, token is expired, account name does not match and existing account, or hashed password does not match user's hashed password.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" default="#instance.ESAPI.httpUtilities().getCurrentRequest()#"/>
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response" default="#instance.ESAPI.httpUtilities().getCurrentResponse()#"/>

		<cfscript>
			var local = {};

			local.token = instance.ESAPI.httpUtilities().getCookie( arguments.request, instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME );
			if(!isObject( local.token )) {
				return "";
			}

			local.data = "";
			try {
				local.data = instance.ESAPI.encryptor().unseal( local.token.getValue() ).split( ":" );
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Found corrupt or expired remember token" );
				instance.ESAPI.httpUtilities().killCookie( arguments.request, arguments.response, instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME );
				return "";
			}

			if(arrayLen( local.data ) != 3) {
				return "";
			}
			// data[1] is a random nonce, which can be ignored
			local.username = local.data[2];
			local.password = local.data[3];
			local.user = getUserByAccountName( local.username );
			if(!isObject( local.user )) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Found valid remember token but no user matching " & local.username );
				return "";
			}

			instance.logger.warning( getSecurity("SECURITY_SUCCESS"), true, "Logging in user with remember token: " & local.user.getAccountName() );
			try {
				local.user.loginWithPassword( local.password );
			}
			catch(cfesapi.org.owasp.esapi.errors.AuthenticationException ae) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Login via remember me cookie failed for user " & local.username, ae );
				instance.ESAPI.httpUtilities().killCookie( arguments.request, arguments.response, HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME );
				return "";
			}
			return local.user;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getUserNames" output="false">

		<cfscript>
			var local = {};

			loadUsersIfNecessary();
			local.results = [];
			for(local.u in this.userMap) {
				local.results.add( this.userMap[local.u].getAccountName() );
			}
			return local.results;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="hashPassword" output="false">
		<cfargument required="true" type="String" name="password"/>
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			var local = {};

			local.salt = arguments.accountName.toLowerCase();
			return instance.ESAPI.encryptor().hashString( arguments.password, local.salt );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="loadUsersIfNecessary" output="false"
	            hint="Load users if they haven't been loaded in a while.">

		<cfscript>
			var local = {};

			if(!isObject( instance.userDB )) {
				instance.userDB = getJava( "java.io.File" ).init( expandPath( instance.ESAPI.securityConfiguration().getResourceDirectory() ), "users.txt" );
			}

			// We only check at most every checkInterval milliseconds
			local.now = System.currentTimeMillis();
			if(local.now - instance.lastChecked < instance.checkInterval) {
				return;
			}
			instance.lastChecked = local.now;

			if(instance.lastModified == instance.userDB.lastModified()) {
				return;
			}
			loadUsersImmediately();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="loadUsersImmediately" output="false"
	            hint="file was touched so reload it">

		<cfscript>
			var local = {};

			instance.logger.trace( getSecurity("SECURITY_SUCCESS"), true, "Loading users from " & instance.userDB.getAbsolutePath() );

			local.reader = "";
			try {
				local.map = {};
				local.reader = getJava( "java.io.BufferedReader" ).init( getJava( "java.io.FileReader" ).init( instance.userDB ) );
				local.line = local.reader.readLine();
				while(structKeyExists( local, "line" )) {
					if(local.line.length() > 0 && local.line.charAt( 0 ) != chr( 35 )) {
						local.user = _createUser( local.line );
						if(local.map.containsKey( javaCast( "long", local.user.getAccountId() ) )) {
							instance.logger.fatal( getSecurity("SECURITY_FAILURE"), false, "Problem in user file. Skipping duplicate user: " & local.user );
						}
						local.map.put( local.user.getAccountId(), local.user );
					}
					local.line = local.reader.readLine();
				}
				this.userMap = local.map;
				instance.lastModified = System.currentTimeMillis();
				instance.logger.trace( getSecurity("SECURITY_SUCCESS"), true, "User file reloaded: " & local.map.size() );
			}
			catch(java.lang.Exception e) {
				instance.logger.fatal( getSecurity("SECURITY_FAILURE"), false, "Failure loading user file: " & instance.userDB.getAbsolutePath(), e );
			}
			try {
				if(isObject( local.reader )) {
					local.reader.close();
				}
			}
			catch(java.io.IOException e) {
				instance.logger.fatal( getSecurity("SECURITY_FAILURE"), false, "Failure closing user file: " & instance.userDB.getAbsolutePath(), e );
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="cfesapi.org.owasp.esapi.reference.DefaultUser" name="_createUser" output="false"
	            hint="Create a new user with all attributes from a String.  The format is: [ accountId | accountName | password | roles (comma separated) | unlocked | enabled | old password hashes (comma separated) | last host address | last password change time | last long time | last failed login time | expiration time | failed login count ] This method verifies the account name and password strength, creates a new CSRF token, then returns the newly created user.">
		<cfargument required="true" type="String" name="line" hint="parameters to set as attributes for the new User."/>

		<cfscript>
			var local = {};

			local.parts = line.split( " *\| *" );
			local.accountIdString = local.parts[1];
			local.accountId = javaCast( "long", local.accountIdString );
			local.accountName = local.parts[2];

			verifyAccountNameStrength( local.accountName );
			local.user = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultUser" ).init( instance.ESAPI, local.accountName );
			local.user.accountId = local.accountId;

			local.password = local.parts[3];
			verifyPasswordStrength( newPassword=local.password );
			setHashedPassword( local.user, local.password );

			local.roles = local.parts[4].toLowerCase().split( " *, *" );
			for(local.i = 1; local.i <= arrayLen( local.roles ); local.i++)
				if("" != local.roles[local.i])
					local.user.addRole( local.roles[local.i] );
			if("unlocked" != local.parts[5])
				local.user.lock();
			if("enabled" == local.parts[6]) {
				local.user.enable();
			}
			else {
				local.user.disable();
			}

			// generate a new csrf token
			local.user.resetCSRFToken();

			setOldPasswordHashes( local.user, local.parts[7].split( " *, *" ) );
			local.user.setLastHostAddress( iif( "local" == local.parts[8], de( '' ), de( local.parts[8] ) ) );
			local.user.setLastPasswordChangeTime( getJava( "java.util.Date" ).init( javaCast( "long", local.parts[9] ) ) );
			local.user.setLastLoginTime( getJava( "java.util.Date" ).init( javaCast( "long", local.parts[10] ) ) );
			local.user.setLastFailedLoginTime( getJava( "java.util.Date" ).init( javaCast( "long", local.parts[11] ) ) );
			local.user.setExpirationTime( getJava( "java.util.Date" ).init( javaCast( "long", local.parts[12] ) ) );
			local.user.setFailedLoginCount( int( local.parts[13] ) );
			return local.user;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="cfesapi.org.owasp.esapi.User" name="loginWithUsernameAndPassword" output="false"
	            hint="Utility method to extract credentials and verify them.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" hint="The current HTTP request"/>
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response" hint="The HTTP response being prepared"/>

		<cfscript>
			var local = {};

			local.username = arguments.request.getParameter( instance.ESAPI.securityConfiguration().getUsernameParameterName() );
			local.password = arguments.request.getParameter( instance.ESAPI.securityConfiguration().getPasswordParameterName() );

			// if a logged-in user is requesting to login, log them out first
			local.user = getCurrentUser();
			if(isObject( local.user ) && !local.user.isAnonymous()) {
				instance.logger.warning( getSecurity("SECURITY_SUCCESS"), true, "User requested relogin. Performing logout then authentication" );
				local.user.logout();
			}

			// now authenticate with username and password
			if(local.username == "" || local.password == "") {
				if(local.username == "") {
					local.username = "unspecified user";
				}
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Authentication failed", "Authentication failed for " & local.username & " because of blank username or password" ) );
			}
			local.user = getUserByAccountName( local.username );
			if(!isObject( local.user )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Authentication failed", "Authentication failed because user " & local.username & " doesn't exist" ) );
			}
			local.user.loginWithPassword( local.password );

			arguments.request.setAttribute( local.user.getCSRFToken(), "authenticated" );
			return local.user;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeUser" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			var local = {};

			loadUsersIfNecessary();
			local.user = getUserByAccountName( arguments.accountName );
			if(!isObject( local.user )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException" ).init( instance.ESAPI, "Remove user failed", "Can't remove invalid accountName " & arguments.accountName ) );
			}
			this.userMap.remove( getJava( "java.lang.Long" ).init( local.user.getAccountId() ) );
			System.out.println( "Removing user " & local.user.getAccountName() );
			instance.passwordMap.remove( local.user.getAccountId() );
			saveUsers();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="saveUsers" output="false"
	            hint="Save users.">
		<cfargument required="false" name="writer" hint="the print writer to use for saving"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "writer" )) {
				local.i = getUserNames().iterator();
				while(local.i.hasNext()) {
					local.accountName = local.i.next();
					local.u = getUserByAccountName( local.accountName );
					if(isObject( local.u ) && !local.u.isAnonymous()) {
						arguments.writer.println( save( local.u ) );
					}
					else {
						createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Problem saving user", "Skipping save of user " & local.accountName );
					}
				}
			}
			else {
				local.writer = "";
				try {
					local.writer = getJava( "java.io.PrintWriter" ).init( getJava( "java.io.FileWriter" ).init( instance.userDB ) );
					local.writer.println( "## This is the user file associated with the ESAPI library from http://www.owasp.org" );
					local.writer.println( "## accountId | accountName | hashedPassword | roles | locked | enabled | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount" );
					local.writer.println();
					saveUsers( local.writer );
					local.writer.flush();
					instance.logger.info( getSecurity("SECURITY_SUCCESS"), true, "User file written to disk" );
				}
				catch(java.io.IOException e) {
					instance.logger.fatal( getSecurity("SECURITY_FAILURE"), false, "Problem saving user file " & instance.userDB.getAbsolutePath(), e );
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationException" ).init( instance.ESAPI, "Internal Error", "Problem saving user file " & instance.userDB.getAbsolutePath(), e ) );
				}
				if(isObject( local.writer )) {
					local.writer.close();
					instance.lastModified = instance.userDB.lastModified();
					instance.lastChecked = instance.lastModified;
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="save" output="false"
	            hint="Save.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.reference.DefaultUser" name="user" hint="the User to save"/>

		<cfscript>
			var local = {};

			local.sb = getJava( "java.lang.StringBuffer" ).init();
			local.sb.append( arguments.user.getAccountId() );
			local.sb.append( " | " );
			local.sb.append( arguments.user.getAccountName() );
			local.sb.append( " | " );
			local.sb.append( getHashedPassword( arguments.user ) );
			local.sb.append( " | " );
			local.sb.append( arrayToList( arguments.user.getRoles() ) );
			local.sb.append( " | " );
			local.sb.append( iif( arguments.user.isLocked(), de( "locked" ), de( "unlocked" ) ) );
			local.sb.append( " | " );
			local.sb.append( iif( arguments.user.isEnabled(), de( "enabled" ), de( "disabled" ) ) );
			local.sb.append( " | " );
			local.sb.append( arrayToList( getOldPasswordHashes( arguments.user ) ) );
			local.sb.append( " | " );
			local.sb.append( arguments.user.getLastHostAddress() );
			local.sb.append( " | " );
			local.sb.append( arguments.user.getLastPasswordChangeTime().getTime() );
			local.sb.append( " | " );
			local.sb.append( arguments.user.getLastLoginTime().getTime() );
			local.sb.append( " | " );
			local.sb.append( arguments.user.getLastFailedLoginTime().getTime() );
			local.sb.append( " | " );
			local.sb.append( arguments.user.getExpirationTime().getTime() );
			local.sb.append( " | " );
			local.sb.append( arguments.user.getFailedLoginCount() );
			return local.sb.toString();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="login" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response"/>

		<cfscript>
			var local = {};

			if(!isObject( arguments.request ) || !isObject( arguments.response )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Invalid request", "Request or response objects were empty" ) );
			}

			// if there's a user in the session then use that
			local.user = getUserFromSession( arguments.request );

			// else if there's a remember token then use that
			if( !(structKeyExists(local, "user") && isObject( local.user )) ) {
				local.user = getUserFromRememberToken( arguments.request, arguments.response );
			}

			// else try to verify credentials - throws exception if login fails
			if( !(structKeyExists(local, "user") && isObject( local.user )) ) {
				local.user = loginWithUsernameAndPassword( arguments.request, arguments.response );

				// warn if this authentication request was not POST or non-SSL connection, exposing credentials or session id
				try {
					instance.ESAPI.httpUtilities().assertSecureRequest( arguments.request );
				}
				catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationException" ).init( instance.ESAPI, "Attempt to login with an insecure request", e.detail, e ) );
				}
			}

			// if we have a user, verify we are on SSL (POST not required)
			else {

				// warn if this authentication request was non-SSL connection, exposing session id
				try {
					instance.ESAPI.httpUtilities().isSecureChannel( arguments.request );
				}
				catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationException").init( instance.ESAPI, "Attempt to access secure content with an insecure request", e.detail, e ) );
				}
			}

			// set last host address
			local.user.setLastHostAddress( arguments.request.getRemoteHost() );

			// don't let anonymous user log in
			if(local.user.isAnonymous()) {
				local.user.logout();
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException" ).init( instance.ESAPI, "Login failed", "Anonymous user cannot be set to current user. User: " & local.user.getAccountName() ) );
			}

			// don't let disabled users log in
			if(!local.user.isEnabled()) {
				local.user.logout();
				local.user.incrementFailedLoginCount();
				local.user.setLastFailedLoginTime( getJava( "java.util.Date" ).init() );
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException" ).init( instance.ESAPI, "Login failed", "Disabled user cannot be set to current user. User: " & local.user.getAccountName() ) );
			}

			// don't let locked users log in
			if(local.user.isLocked()) {
				local.user.logout();
				local.user.incrementFailedLoginCount();
				local.user.setLastFailedLoginTime( getJava( "java.util.Date" ).init() );
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException" ).init( instance.ESAPI, "Login failed", "Locked user cannot be set to current user. User: " & local.user.getAccountName() ) );
			}

			// don't let expired users log in
			if(local.user.isExpired()) {
				local.user.logout();
				local.user.incrementFailedLoginCount();
				local.user.setLastFailedLoginTime( getJava( "java.util.Date" ).init() );
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException" ).init( instance.ESAPI, "Login failed", "Expired user cannot be set to current user. User: " & local.user.getAccountName() ) );
			}

			// check session inactivity timeout
			if(local.user.isSessionTimeout()) {
				local.user.logout();
				local.user.incrementFailedLoginCount();
				local.user.setLastFailedLoginTime( getJava( "java.util.Date" ).init() );
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException" ).init( instance.ESAPI, "Login failed", "Session inactivity timeout: " & local.user.getAccountName() ) );
			}

			// check session absolute timeout
			if(local.user.isSessionAbsoluteTimeout()) {
				local.user.logout();
				local.user.incrementFailedLoginCount();
				local.user.setLastFailedLoginTime( getJava( "java.util.Date" ).init() );
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException" ).init( instance.ESAPI, "Login failed", "Session absolute timeout: " & local.user.getAccountName() ) );
			}

			// create new session for this User
			local.session = arguments.request.getSession();
			local.user.addSession( local.session );
			local.session.setAttribute( instance.USER, local.user );
			setCurrentUser( local.user );
			return local.user;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="logout" output="false">

		<cfscript>
			var local = {};

			local.user = getCurrentUser();
			if(isObject( local.user ) && !local.user.isAnonymous()) {
				local.user.logout();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCurrentUser" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user"/>

		<cfscript>
			instance.currentUser.setUser( arguments.user );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="verifyAccountNameStrength" output="false"
	            hint="This implementation simply verifies that account names are at least 5 characters long. This helps to defeat a brute force attack, however the real strength comes from the name length and complexity.">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			if(arguments.accountName == "") {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Invalid account name", "Attempt to create account with a blank account name" ) );
			}
			if(!instance.ESAPI.validator().isValidInput( "verifyAccountNameStrength", arguments.accountName, "AccountName", instance.MAX_ACCOUNT_NAME_LENGTH, false )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Invalid account name", "New account name is not valid: " & arguments.accountName ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="verifyPasswordStrength" output="false"
	            hint="This implementation checks: - for any 3 character substrings of the old password - for use of a length character sets > 16 (where character sets are upper, lower, digit, and special">
		<cfargument type="String" name="oldPassword"/>
		<cfargument required="true" type="String" name="newPassword"/>

		<cfscript>
			var local = {};

			if(arguments.newPassword == "")
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Invalid password", "New password cannot be blank" ) );

			// can't change to a password that contains any 3 character substring of old password
			if(structKeyExists( arguments, "oldPassword" )) {
				local.length = arguments.oldPassword.length();
				for(local.i = 0; local.i < local.length - 2; local.i++) {
					local.sub = arguments.oldPassword.substring( local.i, local.i + 3 );
					if(arguments.newPassword.indexOf( local.sub ) > -1) {
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Invalid password", "New password cannot contain pieces of old password" ) );
					}
				}
			}

			// new password must have enough character sets and length
			local.charsets = 0;
			for(local.i = 0; local.i < arguments.newPassword.length(); local.i++)
				if(getJava( "java.util.Arrays" ).binarySearch( getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_LOWERS, arguments.newPassword.charAt( local.i ) ) > 0) {
					local.charsets++;
					break;
				}
			for(local.i = 0; local.i < arguments.newPassword.length(); local.i++)
				if(getJava( "java.util.Arrays" ).binarySearch( getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_UPPERS, arguments.newPassword.charAt( local.i ) ) > 0) {
					local.charsets++;
					break;
				}
			for(local.i = 0; local.i < arguments.newPassword.length(); local.i++)
				if(getJava( "java.util.Arrays" ).binarySearch( getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_DIGITS, arguments.newPassword.charAt( local.i ) ) > 0) {
					local.charsets++;
					break;
				}
			for(local.i = 0; local.i < arguments.newPassword.length(); local.i++)
				if(getJava( "java.util.Arrays" ).binarySearch( getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_SPECIALS, arguments.newPassword.charAt( local.i ) ) > 0) {
					local.charsets++;
					break;
				}

			// calculate and verify password strength
			local.strength = arguments.newPassword.length() * local.charsets;
			if(local.strength < 16) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException" ).init( instance.ESAPI, "Invalid password", "New password is not long and complex enough" ) );
			}
		</cfscript>

	</cffunction>

</cfcomponent>