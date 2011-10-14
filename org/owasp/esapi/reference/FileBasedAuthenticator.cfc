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
<cfcomponent extends="AbstractAuthenticator" output="false" hint="Reference implementation of the Authenticator interface. This reference implementation is backed by a simple text file that contains serialized information about users. Many organizations will want to create their own implementation of the methods provided in the Authenticator interface backed by their own user repository.">

	<cfscript>
		/* The logger. */
    	instance.logger = "";

		/* The file that contains the user db */
    	instance.userDB = "";

		/* How frequently to check the user db for external modifications */
    	instance.checkInterval = 60 * 1000;

    	/* The last modified time we saw on the user db. */
		instance.lastModified = 0;

    	/* The last time we checked if the user db had been modified externally */
		instance.lastChecked = 0;

		static.MAX_ACCOUNT_NAME_LENGTH = 250;


		/* The user map. */
	    instance.userMap = {};

	    // Map<User, List<String>>, where the strings are password hashes, with the current hash in entry 0
	    instance.passwordMap = {};
	</cfscript>
 
	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Authenticator" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			super.init(argumentCollection=arguments);

			instance.logger = instance.ESAPI.getLogger("Authenticator");

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="void" name="setHashedPassword" output="false" hint="Add a hash to a User's hashed password list.  This method is used to store a user's old password hashes to be sure that any new passwords are not too similar to old passwords.">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true" hint="the user to associate with the new hash">
		<cfargument type="String" name="hash" required="true" hint="the hash to store in the user's password hash list">
		<cfscript>
	        local.hashes = getAllHashedPasswords(arguments.user, true);
	        arrayPrepend(local.hashes, arguments.hash);
	        if (local.hashes.size() > instance.ESAPI.securityConfiguration().getMaxOldPasswordHashes()) {
	            local.hashes.remove(local.hashes.size() - 1);
	        }
	        instance.passwordMap.put(arguments.user.getAccountId(), local.hashes);
	        instance.logger.info(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "New hashed password stored for " & arguments.user.getAccountName());
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getHashedPassword" output="false" hint="Return the specified User's current hashed password.">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true" hint="this User's current hashed password will be returned">
		<cfscript>
	        local.hashes = getAllHashedPasswords(arguments.user, false);
	        if (arrayLen(local.hashes)) {
	        	return local.hashes[1];
	        }
	        return "";
    	</cfscript> 
	</cffunction>


	<cffunction access="package" returntype="void" name="setOldPasswordHashes" output="false" hint="Set the specified User's old password hashes.  This will not set the User's current password hash.">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true" hint="the User whose old password hashes will be set">
		<cfargument type="Array" name="oldHashes" required="true" hint="a list of the User's old password hashes">
		<cfscript>
	        local.hashes = getAllHashedPasswords(arguments.user, true);
	        if (local.hashes.size() > 1) {
	            local.hashes.removeAll(local.hashes.subList(1, local.hashes.size() - 1));
	        }
	        local.hashes.addAll(arguments.oldHashes);
	        instance.passwordMap.put(arguments.user.getAccountId(), local.hashes);
    	</cfscript> 
	</cffunction>


	<cffunction access="package" returntype="Array" name="getAllHashedPasswords" output="false" hint="Returns all of the specified User's hashed passwords.  If the User's list of passwords is null, and create is set to true, an empty password list will be associated with the specified User and then returned. If the User's password map is null and create is set to false, an exception will be thrown.">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true" hint="the User whose old hashes should be returned">
		<cfargument type="boolean" name="create" required="true" hint="true - if no password list is associated with this user, create one; false - if no password list is associated with this user, do not create one">
		<cfscript>
	        local.hashes = instance.passwordMap.get(arguments.user.getAccountId());
	        if (!isNull(local.hashes)) {
	            return local.hashes;
	        }
	        if (arguments.create) {
	            local.hashes = [];
	            instance.passwordMap.put(arguments.user.getAccountId(), local.hashes);
	            return local.hashes;
	        }
	        throw(object=createObject("java", "java.lang.RuntimeException").init("No hashes found for " & user.getAccountName() & ". Is User.hashcode() and equals() implemented correctly?"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getOldPasswordHashes" output="false" hint="Get a List of the specified User's old password hashes.  This will not return the User's current password hash.">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true" hint="the user whose old password hashes should be returned">
		<cfscript>
	        local.hashes = getAllHashedPasswords(arguments.user, false);
	        if (local.hashes.size() > 1) {
	            //return duplicate(local.hashes.subList(1, local.hashes.size() - 1));
	            return duplicate(listToArray(listRest(arrayToList(local.hashes))));
	        }
	        return [];
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="createUser" output="false">
		<cfargument type="String" name="accountName" required="true">
		<cfargument type="String" name="password1" required="true">
		<cfargument type="String" name="password2" required="true">
		<cfscript>
			loadUsersIfNecessary();
	        if (trim(arguments.accountName) == "") {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException").init(instance.ESAPI, "Account creation failed", "Attempt to create user with empty accountName");
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        if (isObject(getUserByAccountName(arguments.accountName))) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException").init(instance.ESAPI, "Account creation failed", "Duplicate user creation denied for " & arguments.accountName);
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }

	        verifyAccountNameStrength(arguments.accountName);

	        if (trim(arguments.password1) == "") {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid account name", "Attempt to create account " & arguments.accountName & " with an empty password");
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        
	        local.user = createObject("DefaultUser").init(instance.ESAPI, arguments.accountName);
	        
	        verifyPasswordStrength(newPassword=arguments.password1, user=local.user);

	        if (!arguments.password1.equals(arguments.password2)) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Passwords do not match", "Passwords for " & arguments.accountName & " do not match");
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }

	        try {
	            setHashedPassword(local.user, hashPassword(arguments.password1, arguments.accountName));
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException ee) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationException").init(instance.ESAPI, "Internal error", "Error hashing password for " & arguments.accountName, ee);
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        instance.userMap.put(local.user.getAccountId(), local.user);
	        instance.logger.info(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "New user created: " & arguments.accountName);
	        saveUsers();
	        return local.user;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="generateStrongPassword" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="false">
		<cfargument type="String" name="oldPassword" required="false">
		<cfscript>
			if (structKeyExists(arguments, "user") && structKeyExists(arguments, "oldPassword")) {
        		local.newPassword = _generateStrongPassword(arguments.oldPassword);
				if (!isNull(local.newPassword)) {
					instance.logger.info(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "Generated strong password for " & arguments.user.getAccountName());
				}
				return local.newPassword;
			}

			return _generateStrongPassword("");
        </cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="_generateStrongPassword" output="false" hint="Generate a strong password that is not similar to the specified old password.">
		<cfargument type="String" name="oldPassword" required="true" hint="the password to be compared to the new password for similarity">
		<cfscript>
			EncoderConstants = createObject("java", "org.owasp.esapi.EncoderConstants");

	        local.r = instance.ESAPI.randomizer();
	        local.letters = local.r.getRandomInteger(4, 6);  // inclusive, exclusive
	        local.digits = 7 - local.letters;
	        local.passLetters = local.r.getRandomString(local.letters, EncoderConstants.CHAR_PASSWORD_LETTERS);
	        local.passDigits = local.r.getRandomString(local.digits, EncoderConstants.CHAR_PASSWORD_DIGITS);
	        local.passSpecial = local.r.getRandomString(1, EncoderConstants.CHAR_PASSWORD_SPECIALS);
	        local.newPassword = local.passLetters & local.passSpecial & local.passDigits;
	        if (createObject("java", "org.owasp.esapi.StringUtilities").getLevenshteinDistance(arguments.oldPassword, local.newPassword) > 5) {
	            return local.newPassword;
	        }
	        return _generateStrongPassword(arguments.oldPassword);
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true">
		<cfargument type="String" name="currentPassword" required="true">
		<cfargument type="String" name="newPassword" required="true">
		<cfargument type="String" name="newPassword2" required="true">
		<cfscript>
	        local.accountName = arguments.user.getAccountName();
	        try {
	            local.currentHash = getHashedPassword(arguments.user);
	            local.verifyHash = hashPassword(arguments.currentPassword, local.accountName);
	            if (!local.currentHash.equals(local.verifyHash)) {
	                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Password change failed", "Authentication failed for password change on user: " & local.accountName);
					throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	            }
	            if (arguments.newPassword == "" || arguments.newPassword2 == "" || !arguments.newPassword.equals(arguments.newPassword2)) {
	                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Password change failed", "Passwords do not match for password change on user: " & local.accountName);
					throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	            }
	            verifyPasswordStrength(arguments.currentPassword, arguments.newPassword, arguments.user);
	            arguments.user.setLastPasswordChangeTime(createObject("java", "java.util.Date").init());
	            local.newHash = hashPassword(arguments.newPassword, local.accountName);
	            if (arrayFind(getOldPasswordHashes(arguments.user), local.newHash)) {
	                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Password change failed", "Password change matches a recent password for user: " & local.accountName);
					throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	            }
	            setHashedPassword(arguments.user, local.newHash);
	            instance.logger.info(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "Password changed for user: " & local.accountName);
	            // jtm - 11/2/2010 - added to resolve http://code.google.com/p/owasp-esapi-java/issues/detail?id=13
	            saveUsers();
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException ee) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationException").init(instance.ESAPI, "Password change failed", "Encryption exception changing password for " & local.accountName, ee);
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true">
		<cfargument type="String" name="password" required="true">
		<cfscript>
	        local.accountName = arguments.user.getAccountName();
	        try {
	            local.hash = hashPassword(arguments.password, local.accountName);
	            local.currentHash = getHashedPassword(arguments.user);
	            if (local.hash.equals(local.currentHash)) {
	                arguments.user.setLastLoginTime(now());
	                arguments.user.setFailedLoginCount(0);
	                instance.logger.info(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "Password verified for " & local.accountName);
	                return true;
	            }
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            instance.logger.fatal(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Encryption error verifying password for " & local.accountName);
	        }
	        instance.logger.fatal(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Password verification failed for " & local.accountName);
	        return false;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getUserByAccountId" output="false" hint="cfesapi.org.owasp.esapi.User: Returns the User matching the provided accountId.  If the accoundId is not found, an Anonymous User or null may be returned.">
		<cfargument type="numeric" name="accountId" required="true" hint="the account id">
		<cfscript>
			if (arguments.accountId == 0) {
	            return createObject("component", "cfesapi.org.owasp.esapi.User$ANONYMOUS").init(instance.ESAPI);
	        }
	        loadUsersIfNecessary();
	        local.u = instance.userMap.get(arguments.accountId);
	        return !isNull(local.u) ? local.u : "";
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getUserByAccountName" output="false" hint="cfesapi.org.owasp.esapi.User: Returns the User matching the provided accountName.  If the accoundId is not found, an Anonymous User or null may be returned.">
		<cfargument type="String" name="accountName" required="true">
		<cfscript>
	        if (arguments.accountName == "") {
	            return createObject("component", "cfesapi.org.owasp.esapi.User$ANONYMOUS").init(instance.ESAPI);
	        }
	        loadUsersIfNecessary();
	        for (local.u in instance.userMap) {
	            if (instance.userMap[local.u].getAccountName() == arguments.accountName) {
	                return instance.userMap[local.u];
	            }
	        }
	        return "";
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getUserNames" output="false">
		<cfscript>
	        loadUsersIfNecessary();
	        local.results = [];
	        for (local.u in instance.userMap) {
	            local.results.add(instance.userMap[local.u].getAccountName());
	        }
	        return local.results;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="hashPassword" output="false">
		<cfargument type="String" name="password" required="true">
		<cfargument type="String" name="accountName" required="true">
		<cfscript>
			local.salt = arguments.accountName.toLowerCase();
	        return instance.ESAPI.encryptor().hash(arguments.password, local.salt);
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="void" name="loadUsersIfNecessary" output="false" hint="Load users if they haven't been loaded in a while.">
		<cfscript>
	        if (!isObject(instance.userDB)) {
	            instance.userDB = instance.ESAPI.securityConfiguration().getResourceFile("users.txt");
	        }
	        if (isNull(instance.userDB)) {
	            instance.userDB = createObject("java", "java.io.File").init(expandPath(instance.ESAPI.securityConfiguration().getResourceDirectory()), "users.txt");
	            try {
	                if (!instance.userDB.createNewFile()) throw(object=createObject("java", "java.io.IOException").init("Unable to create the user file"));
	                instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "Created " & instance.userDB.getAbsolutePath());
	            } catch (java.io.IOException e) {
	                instance.logger.fatal(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Could not create " & instance.userDB.getAbsolutePath(), e);
	            }
	        }

	        // We only check at most every checkInterval milliseconds
	        local.now = getTickCount();
	        if (local.now - instance.lastChecked < instance.checkInterval) {
	            return;
	        }
	        instance.lastChecked = local.now;

	        if (instance.lastModified == instance.userDB.lastModified()) {
	            return;
	        }
	        loadUsersImmediately();
    	</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="void" name="loadUsersImmediately" output="false">
		<cfscript>
            instance.logger.trace(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "Loading users from " & instance.userDB.getAbsolutePath());

            local.reader = "";
            try {
                local.map = {};
                local.reader = createObject("java", "java.io.BufferedReader").init(createObject("java", "java.io.FileReader").init(instance.userDB));
                local.line = local.reader.readLine();
                while (!isNull(local.line)) {
                    if (local.line.length() > 0 && local.line.charAt(0) != chr(35)) {
                        local.user = _createUser(local.line);
                        if (local.map.containsKey(createObject("java", "java.lang.Long").init(local.user.getAccountId()))) {
                            instance.logger.fatal(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Problem in user file. Skipping duplicate user: " & local.user, "");
                        }
                        local.map.put(local.user.getAccountId(), local.user);
                    }
                    local.line = local.reader.readLine();
                }
                instance.userMap = local.map;
                instance.lastModified = getTickCount();
                instance.logger.trace(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "User file reloaded: " & local.map.size());
            } catch (Exception e) {
                instance.logger.fatal(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Failure loading user file: " & instance.userDB.getAbsolutePath(), e);
            } finally {
                try {
                    if (!isNull(local.reader) && isObject(local.reader)) {
                        local.reader.close();
                    }
                } catch (java.io.IOException e) {
                    instance.logger.fatal(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Failure closing user file: " & instance.userDB.getAbsolutePath(), e);
                }
            }
        </cfscript> 
	</cffunction>


	<cffunction access="private" returntype="cfesapi.org.owasp.esapi.reference.DefaultUser" name="_createUser" output="false" hint="Create a new user with all attributes from a String. This method verifies the account name and password strength, creates a new CSRF token, then returns the newly created user.">
		<cfargument type="String" name="line" required="true" hint="parameters to set as attributes for the new User.">
		<cfscript>
	        Long = createObject("java", "java.lang.Long");

			try {
		        local.parts = line.split(" *\| *");
		        local.accountIdString = local.parts[1];
		        local.accountId = Long.parseLong(local.accountIdString);
		        local.accountName = local.parts[2];

		        verifyAccountNameStrength(local.accountName);
		        local.user = createObject("component", "DefaultUser").init(instance.ESAPI, local.accountName);
		        local.user.accountId = local.accountId;

		        local.password = local.parts[3];
	       		verifyPasswordStrength(newPassword=local.password, user=local.user);
		        setHashedPassword(local.user, local.password);

		        local.roles = local.parts[4].toLowerCase().split(" *, *");
		        for (local.i = 1; local.i <= arrayLen(local.roles); local.i++) {
		        	local.role = local.roles[local.i];
		            if ("" != local.role) {
		                local.user.addRole(local.role);
		            }
		        }
		        if ("unlocked" != local.parts[5]) {
		            local.user.lock();
		        }
		        if ("enabled" == local.parts[6]) {
		            local.user.enable();
		        } else {
		            local.user.disable();
		        }

		        // generate a new csrf token
		        local.user.resetCSRFToken();

		        setOldPasswordHashes(local.user, Arrays.asList(local.parts[7].split(" *, *")));
		        local.user.setLastHostAddress("unknown" == local.parts[8] ? "" : local.parts[8]);
		        local.user.setLastPasswordChangeTime(createObject("java", "java.util.Date").init(Long.parseLong(local.parts[9])));
		        local.user.setLastLoginTime(createObject("java", "java.util.Date").init(Long.parseLong(local.parts[10])));
		        local.user.setLastFailedLoginTime(createObject("java", "java.util.Date").init(Long.parseLong(local.parts[11])));
		        local.user.setExpirationTime(createObject("java", "java.util.Date").init(Long.parseLong(local.parts[12])));
		        local.user.setFailedLoginCount(val(local.parts[13]));
		        return local.user;
			}
			catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				throw(message=e.message, type=e.type);
			}
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="removeUser" output="false">
		<cfargument type="String" name="accountName" required="true">
		<cfscript>
	        loadUsersIfNecessary();
	        local.user = getUserByAccountName(arguments.accountName);
	        if (!isObject(local.user)) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException").init(instance.ESAPI, "Remove user failed", "Can't remove invalid accountName " & arguments.accountName);
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        instance.userMap.remove(local.user.getAccountId());
	        instance.logger.info(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "Removing user " & local.user.getAccountName());
	        instance.passwordMap.remove(local.user);
	        saveUsers();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="saveUsers" output="false" hint="Saves the user database to the file system. In this implementation you must call save to commit any changes to the user file. Otherwise changes will be lost when the program ends.">
		<cfargument type="any" name="writer" required="false" hint="java.io.PrintWriter">
		<cfscript>
			if (structKeyExists(arguments, "writer")) {
				local.userNames = getUserNames();
		        for (local.i = 1; local.i <= arrayLen(local.userNames); local.i++) {
		        	local.accountName = local.userNames[local.i];
		            local.u = getUserByAccountName(local.accountName);
		            if (isObject(local.u) && !local.u.isAnonymous()) {
		                writer.println(save(local.u));
		            }
		            else {
		                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Problem saving user", "Skipping save of user " & local.accountName);
						throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
		            }
		        }
		        return;
		    }

	        local.writer = "";
	        try {
	            local.writer = createObject("java", "java.io.PrintWriter").init(createObject("java", "java.io.FileWriter").init(instance.userDB));
	            local.writer.println("## This is the user file associated with the ESAPI library from http://www.owasp.org");
	            local.writer.println("## accountId | accountName | hashedPassword | roles | locked | enabled | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount");
	            local.writer.println();
	            saveUsers(local.writer);
	            local.writer.flush();
	            instance.logger.info(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "User file written to disk");
	       	}
	       	catch (java.io.IOException e) {
	            instance.logger.fatal(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Problem saving user file " & instance.userDB.getAbsolutePath(), e);
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationException").init(instance.ESAPI, "Internal Error", "Problem saving user file " & instance.userDB.getAbsolutePath(), e);
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        finally {
	            if (isObject(local.writer)) {
	                local.writer.close();
	                instance.lastModified = instance.userDB.lastModified();
	                instance.lastChecked = instance.lastModified;
	            }
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="save" output="false" hint="Save.">
		<cfargument type="DefaultUser" name="user" required="true" hint="the User to save">
		<cfscript>
	        local.sb = createObject("java", "java.lang.StringBuilder").init();
	        local.sb.append(arguments.user.getAccountId());
	        local.sb.append(" | ");
	        local.sb.append(arguments.user.getAccountName());
	        local.sb.append(" | ");
	        local.sb.append(getHashedPassword(arguments.user));
	        local.sb.append(" | ");
	        local.sb.append(arrayToList(arguments.user.getRoles()));
	        local.sb.append(" | ");
	        local.sb.append(arguments.user.isLocked() ? "locked" : "unlocked");
	        local.sb.append(" | ");
	        local.sb.append(arguments.user.isEnabled() ? "enabled" : "disabled");
	        local.sb.append(" | ");
	        local.sb.append(arrayToList(getOldPasswordHashes(arguments.user)));
	        local.sb.append(" | ");
	        local.sb.append(arguments.user.getLastHostAddress());
	        local.sb.append(" | ");
	        local.sb.append(arguments.user.getLastPasswordChangeTime().getTime());
	        local.sb.append(" | ");
	        local.sb.append(arguments.user.getLastLoginTime().getTime());
	        local.sb.append(" | ");
	        local.sb.append(arguments.user.getLastFailedLoginTime().getTime());
	        local.sb.append(" | ");
	        local.sb.append(arguments.user.getExpirationTime().getTime());
	        local.sb.append(" | ");
	        local.sb.append(arguments.user.getFailedLoginCount());
	        return local.sb.toString();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="verifyAccountNameStrength" output="false" hint="This implementation simply verifies that account names are at least 5 characters long. This helps to defeat a brute force attack, however the real strength comes from the name length and complexity.">
		<cfargument type="String" name="accountName" required="true">
		<cfscript>
	        if (arguments.accountName == "") {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid account name", "Attempt to create account with a null account name");
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        if (!instance.ESAPI.validator().isValidInput("verifyAccountNameStrength", arguments.accountName, "AccountName", static.MAX_ACCOUNT_NAME_LENGTH, false)) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid account name", "New account name is not valid: " & arguments.accountName);
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="verifyPasswordStrength" output="false" hint="This implementation checks: - for any 3 character substrings of the old password - for use of a length character sets &gt; 16 (where character sets are upper, lower, digit, and special">
		<cfargument type="String" name="oldPassword" required="false">
		<cfargument type="String" name="newPassword" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true">
		<cfscript>
			Arrays = createObject("java", "java.util.Arrays");
			EncoderConstants = createObject("java", "org.owasp.esapi.EncoderConstants");

	        if (isNull(arguments.newPassword)) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid password", "New password cannot be null");
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }

	        // can't change to a password that contains any 3 character substring of old password
	        if (structKeyExists(arguments, "oldPassword")) {
	            local.length = arguments.oldPassword.length();
	            for (local.i = 0; local.i < local.length - 2; local.i++) {
	                local.sub = arguments.oldPassword.substring(local.i, local.i + 3);
	                if (arguments.newPassword.indexOf(local.sub) > -1) {
	                    cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid password", "New password cannot contain pieces of old password");
						throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	                }
	            }
	        }

	        // new password must have enough character sets and length
	        local.charsets = 0;
	        for (local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
	            if (Arrays.binarySearch(EncoderConstants.CHAR_LOWERS, arguments.newPassword.charAt(local.i)) >= 0) {
	                local.charsets++;
	                break;
	            }
	        }
	        for (local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
	            if (Arrays.binarySearch(EncoderConstants.CHAR_UPPERS, arguments.newPassword.charAt(local.i)) >= 0) {
	                local.charsets++;
	                break;
	            }
	        }
	        for (local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
	            if (Arrays.binarySearch(EncoderConstants.CHAR_DIGITS, arguments.newPassword.charAt(local.i)) >= 0) {
	                local.charsets++;
	                break;
	            }
	        }
	        for (local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
	            if (Arrays.binarySearch(EncoderConstants.CHAR_SPECIALS, arguments.newPassword.charAt(local.i)) >= 0) {
	                local.charsets++;
	                break;
	            }
	        }

	        // calculate and verify password strength
	        local.strength = arguments.newPassword.length() * local.charsets;
	        if (local.strength < 16) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid password", "New password is not long and complex enough");
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        
	        local.accountName = arguments.user.getAccountName();
	        
	        //jtm - 11/3/2010 - fix for bug http://code.google.com/p/owasp-esapi-java/issues/detail?id=108
	        if (local.accountName.equalsIgnoreCase(arguments.newPassword)) {
	        	//password can't be account name
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid password", "Password matches account name, irrespective of case");
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
    	</cfscript> 
	</cffunction>


</cfcomponent>
