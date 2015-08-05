/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
import "org.owasp.esapi.util.Utils";

component implements="org.owasp.esapi.Adapter" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";

    variables.logger = "";

	public org.owasp.esapi.Adapter function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;
		variables.logger = variables.ESAPI.getLogger(getMetaData(this).fullName);

		return this;
	}

/* *** USER METHODS *** */

    /**
     * The file that contains the user db
     */
    variables.userDB = "";

    /**
     * How frequently to check the user db for external modifications
     */
    variables.checkInterval = 60 * 1000;

    /**
     * The last modified time we saw on the user db.
     */
    variables.lastModified = 0;

    /**
     * The last time we checked if the user db had been modified externally
     */
    variables.lastChecked = 0;

    /**
     * The user map.
     */
    variables.userMap = {};

	public function getUserByAccountId(required accountId) {
        loadUsersIfNecessary();
        if (structKeyExists(variables.userMap, arguments.accountId)) {
        	return variables.userMap[arguments.accountId];
        }
    }

    public function getUserByAccountName(required string accountName) {
        loadUsersIfNecessary();
        for (var u in variables.userMap) {
            if (variables.userMap[u].getAccountName() == arguments.accountName) {
                return variables.userMap[u];
            }
        }
        return;
    }

    public array function getUserNames() {
        loadUsersIfNecessary();
        var results = [];
        for (var u in variables.userMap) {
            arrayAppend(results, variables.userMap[u].getAccountName());
        }
        return results;
    }

    public void function saveUser(required org.owasp.esapi.User user) {
		variables.userMap[arguments.user.getAccountId()] = arguments.user;
		// a password must exist before a file-based save
		if (!structKeyExists(variables.passwordMap, arguments.user.getAccountName())) {
			variables.passwordMap[arguments.user.getAccountName()] = [variables.ESAPI.authenticator().hashPassword(variables.ESAPI.authenticator().generateStrongPassword(), arguments.user.getAccountName())];
		}
        saveUsers();
    }

    public void function removeUser(required org.owasp.esapi.User user) {
        structDelete(variables.userMap, arguments.user.getAccountId());
        structDelete(variables.passwordMap, arguments.user.getAccountName());
        saveUsers();
    }

    /**
     * Load users if they haven't been loaded in a while.
     */
    private void function loadUsersIfNecessary() {
		if(isNull(variables.userDB) || !isObject(variables.userDB)) {
			variables.userDB = createObject("java", "java.io.File").init(expandPath("/org/owasp/esapi/conf/users.txt"));
		}

        // We only check at most every checkInterval milliseconds
        var timestamp = now().getTime();
        if (timestamp - variables.lastChecked < variables.checkInterval) {
            return;
        }
        variables.lastChecked = timestamp;

        if(variables.lastModified == variables.userDB.lastModified()) {
            return;
        }
        loadUsersImmediately();
    }

    // file was touched so reload it
    private void function loadUsersImmediately() {
		var msgParams = [variables.userDB.getAbsolutePath()];
		variables.logger.trace(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Authenticator_loadUsersImmediately_loading_message", msgParams));

		var reader = "";
		try {
			var map = {};
			reader = createObject("java", "java.io.BufferedReader").init(createObject("java", "java.io.FileReader").init(variables.userDB));
			var line = reader.readLine();
			while(isDefined("line") && !isNull(line)) {
				if(line.length() > 0 && line.charAt(0) != chr(35)) {
					var user = _toESAPIUser(line);
					if(map.containsKey(javaCast("long", user.getAccountId()))) {
						msgParams = [user];
						variables.logger.fatal(variables.Logger.SECURITY_FAILURE, new Utils().messageFormat("Authenticator_loadUsersImmediately_duplicateUser_message", msgParams));
					}
					map.put(user.getAccountId(), user);
				}
				line = reader.readLine();
			}
			variables.userMap = map;
			variables.lastModified = now().getTime();
			var msgParams = [map.size()];
			variables.logger.trace(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Authenticator_loadUsersImmediately_reloaded_message", msgParams));
		}
		catch(java.lang.Exception e) {
			var msgParams = [variables.userDB.getAbsolutePath()];
			variables.logger.fatal(variables.Logger.SECURITY_FAILURE, new Utils().messageFormat("Authenticator_loadUsersImmediately_loadingFailure_message", msgParams), e);
		}
		try {
			if(isObject(reader)) {
				reader.close();
			}
		}
		catch(java.io.IOException e) {
			var msgParams = [variables.userDB.getAbsolutePath()];
			variables.logger.fatal(variables.Logger.SECURITY_FAILURE, new Utils().messageFormat("Authenticator_loadUsersImmediately_closingFailure_message", msgParams), e);
		}
    }

    /**
     * Create a new user with all attributes from a String.  The format is:
     * accountId | accountName | password | roles (comma separated) | unlocked | enabled | old password hashes (comma separated) | last host address | last password change time | last long time | last failed login time | expiration time | failed login count
     * This method verifies the account name and password strength, creates a new CSRF token, then returns the newly created user.
     *
     * @param line parameters to set as attributes for the new User.
     * @return the newly created User
     * @throws AuthenticationException
     */
    private org.owasp.esapi.beans.AuthenticatedUser function _toESAPIUser(required string line) {
    	var authenticator = variables.ESAPI.authenticator();
        var parts = arguments.line.split(" *\| *");
        var accountIdString = parts[1];
        var accountId = javaCast("long", accountIdString);
        var accountName = parts[2];

        authenticator.verifyAccountNameStrength(accountName);
        var user = authenticator.getAuthenticatedUserInstance(accountName);
        user.accountId = accountId;

        var password = parts[3];
        authenticator.verifyPasswordStrength(newPassword=password, user=user);
        authenticator.setHashedPassword(user, password);

        var roles = parts[4].toLowerCase().split(" *, *");
        for (var role in roles) {
            if ("" != role) {
                user.addRole(role);
            }
        }
        if ("unlocked" != parts[5]) {
            user.lock();
        }
        if ("enabled" == parts[6]) {
            user.enable();
        } else {
            user.disable();
        }

        // generate a new csrf token
        user.resetCSRFToken();

        setOldPasswordHashes(user, listToArray(parts[7]));
        user.setLastHostAddress("null" == parts[8] ? javaCast("null", "") : parts[8]);
        user.setLastPasswordChangeTime(createObject("java", "java.util.Date").init(javaCast("long", parts[9])));
        user.setLastLoginTime(createObject("java", "java.util.Date").init(javaCast("long", parts[10])));
        user.setLastFailedLoginTime(createObject("java", "java.util.Date").init(javaCast("long", parts[11])));
        user.setExpirationTime(createObject("java", "java.util.Date").init(javaCast("long", parts[12])));
        user.setFailedLoginCount(javaCast("int", parts[13]));
        return user;
    }

    /**
     * Saves the user database to the file variables.System. In this implementation you must call save to commit any changes to
     * the user file. Otherwise changes will be lost when the program ends.
     *
     * @param printWriter the print writer to use for saving
     *
     * @throws AuthenticationException if the user file could not be written
     */
    private void function saveUsers(writer) {
		if(structKeyExists(arguments, "writer")) {
			var i = getUserNames().iterator();
			while(i.hasNext()) {
				var accountName = i.next();
				var u = getUserByAccountName(accountName);
				if(isObject(u) && !u.isAnonymous()) {
					arguments.writer.println(save(u));
				}
				else {
					new AuthenticationCredentialsException(variables.ESAPI, "Problem saving user", "Skipping save of user " & accountName);
				}
			}
		}
		else {
			var printWriter = "";
			try {
				printWriter = createObject("java", "java.io.PrintWriter").init(createObject("java", "java.io.FileWriter").init(variables.userDB));
				printWriter.println("## This is the user file associated with the ESAPI library from http://www.owasp.org");
				printWriter.println("## accountId | accountName | hashedPassword | roles | locked | enabled | oldPasswordHashes | lastHostAddress | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount");
				printWriter.println();
				saveUsers(printWriter);
				printWriter.flush();
				var msgParams = [];
				variables.logger.info(variables.Logger.SECURITY_SUCCESS, "User file written to disk");
			}
			catch(java.io.IOException e) {
				variables.logger.fatal(variables.Logger.SECURITY_FAILURE, "Problem saving user file " & variables.userDB.getAbsolutePath(), e);
				raiseException(new AuthenticationException(variables.ESAPI, "Internal Error", "Problem saving user file " & variables.userDB.getAbsolutePath(), e));
			}
			if(isObject(printWriter)) {
				printWriter.close();
				variables.lastModified = variables.userDB.lastModified();
				variables.lastChecked = variables.lastModified;
			}
		}
    }

    /**
     * Save.
     *
     * @param user the User to save
     * @return a line containing properly formatted information to save regarding the user
     */
    private string function save(required org.owasp.esapi.beans.AuthenticatedUser user) {
        var sb = createObject("java", "java.lang.StringBuilder").init();
        sb.append(arguments.user.getAccountId());
        sb.append(" | ");
        sb.append(arguments.user.getAccountName());
        sb.append(" | ");
        sb.append(variables.ESAPI.authenticator().getHashedPassword(arguments.user));
        sb.append(" | ");
        sb.append(arrayToList(arguments.user.getRoles()));
        sb.append(" | ");
        sb.append(arguments.user.isLocked() ? "locked" : "unlocked");
        sb.append(" | ");
        sb.append(arguments.user.isEnabled() ? "enabled" : "disabled");
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
    }

/* *** PASSWORD METHODS *** */

    // Map<User, List<String>>, where the strings are password hashes, with the current hash in entry 0
    variables.passwordMap = {};

    public void function savePasswordHashes(required org.owasp.esapi.User user, required array hashes) {
    	variables.passwordMap[arguments.user.getAccountName()] = arguments.hashes;
    	saveUsers();
    }

    /**
     * Returns all of the specified User's hashed passwords.  If the User's list of passwords is null,
     * and create is set to true, an empty password list will be associated with the specified User
     * and then returned. If the User's password map is null and create is set to false, an exception
     * will be thrown.
     *
     * @param user   the User whose old hashes should be returned
     * @param create true - if no password list is associated with this user, create one
     *               false - if no password list is associated with this user, do not create one
     * @return a List containing all of the specified User's password hashes
     */
    public array function getAllHashedPasswords(required org.owasp.esapi.User user) {
        if (structKeyExists(variables.passwordMap, arguments.user.getAccountName())) {
        	return variables.passwordMap[arguments.user.getAccountName()];
        }
        return [];
    }

    /**
     * Set the specified User's old password hashes.  This will not set the User's current password hash.
     *
     * @param user      the User whose old password hashes will be set
     * @param oldHashes a list of the User's old password hashes     *
     */
    private void function setOldPasswordHashes(required org.owasp.esapi.User user, array oldHashes) {
        var hashes = getAllHashedPasswords(arguments.user);
        variables.passwordMap[arguments.user.getAccountName()] = arguments.oldHashes;
        if (arrayLen(hashes)) {
        	arrayPrepend(variables.passwordMap[arguments.user.getAccountName()], hashes[1]);
        }
    }

    /**
     * Get a List of the specified User's old password hashes.  This will not return the User's current
     * password hash.
     *
     * @param user he user whose old password hashes should be returned
     * @return the specified User's old password hashes
     */
    public array function getOldPasswordHashes(required org.owasp.esapi.User user) {
        var hashes = getAllHashedPasswords(arguments.user);
        if (hashes.size() > 1) {
            return duplicate(hashes.subList(1, hashes.size() - 1));
        }
        return [];
    }

}