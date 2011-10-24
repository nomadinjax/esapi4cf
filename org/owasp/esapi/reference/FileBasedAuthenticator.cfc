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
/**
 * Reference implementation of the Authenticator interface. This reference implementation is backed by a simple text
 * file that contains serialized information about users. Many organizations will want to create their own
 * implementation of the methods provided in the Authenticator interface backed by their own user repository. This
 * reference implementation captures information about users in a simple text file format that contains user information
 * separated by the pipe "|" character. Here's an example of a single line from the users.txt file:
 * <p/>
 * <PRE>
 * <p/>
 * account id | account name | hashed password | roles | lockout | status | old password hashes | last
 * hostname | last change | last login | last failed | expiration | failed
 * ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 * 1203123710837 | mitch | 44k/NAzQUlrCq9musTGGkcMNmdzEGJ8w8qZTLzpxLuQ= | admin,user | unlocked | enabled |
 * u10dW4vTo3ZkoM5xP+blayWCz7KdPKyKUojOn9GJobg= | 192.168.1.255 | 1187201000926 | 1187200991568 | 1187200605330 |
 * 2187200605330 | 1
 * <p/>
 * </PRE>
 */
component FileBasedAuthenticator extends="AbstractAuthenticator" implements="cfesapi.org.owasp.esapi.Authenticator" {

	// imports
	EncoderConstants = createObject("java", "org.owasp.esapi.EncoderConstants");
	Logger = createObject("java", "org.owasp.esapi.Logger");

	/**
	 * The logger.
	 */
	instance.logger = "";

	/**
	 * The file that contains the user db
	 */
	instance.userDB = "";

	/**
	 * How frequently to check the user db for external modifications
	 */
	instance.checkInterval = 60 * 1000;

	/**
	 * The last modified time we saw on the user db.
	 */
	instance.lastModified = 0;

	/**
	 * The last time we checked if the user db had been modified externally
	 */
	instance.lastChecked = 0;

	instance.MAX_ACCOUNT_NAME_LENGTH = 250;

	public FileBasedAuthenticator function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI) {
		super.init(arguments.ESAPI);
		instance.logger = instance.ESAPI.getLogger("Authenticator");
		return this;
	}
	
	/**
	 * Add a hash to a User's hashed password list.  This method is used to store a user's old password hashes
	 * to be sure that any new passwords are not too similar to old passwords.
	 *
	 * @param user the user to associate with the new hash
	 * @param hash the hash to store in the user's password hash list
	 */
	
	private void function setHashedPassword(required cfesapi.org.owasp.esapi.User user, 
	                                        required String hash) {
		local.hashes = getAllHashedPasswords(arguments.user, true);
		arrayPrepend(local.hashes, arguments.hash);
		if(local.hashes.size() > instance.ESAPI.securityConfiguration().getMaxOldPasswordHashes()) {
			local.hashes.remove(local.hashes.size() - 1);
		}
		instance.passwordMap.put(arguments.user.getAccountId(), local.hashes);
		instance.logger.info(Logger.SECURITY_SUCCESS, "New hashed password stored for " & arguments.user.getAccountName());
	}
	
	/**
	 * Return the specified User's current hashed password.
	 *
	 * @param user this User's current hashed password will be returned
	 * @return the specified User's current hashed password
	 */
	
	public String function getHashedPassword(required cfesapi.org.owasp.esapi.User user) {
		local.hashes = getAllHashedPasswords(arguments.user, false);
		if (arrayLen(local.hashes)) {
			return local.hashes[1];
		}
		return "";
	}
	
	/**
	 * Set the specified User's old password hashes.  This will not set the User's current password hash.
	 *
	 * @param user      the User whose old password hashes will be set
	 * @param oldHashes a list of the User's old password hashes     *
	 */
	
	public void function setOldPasswordHashes(required cfesapi.org.owasp.esapi.User user, 
	                                          required Array oldHashes) {
		local.hashes = getAllHashedPasswords(arguments.user, true);
		if(local.hashes.size() > 1) {
			local.hashes.removeAll(local.hashes.subList(1, local.hashes.size() - 1));
		}
		for (local.i=1; local.i<=arrayLen(arguments.oldHashes); local.i++) {
			arrayAppend(local.hashes, arguments.oldHashes[local.i]);
		}
		instance.passwordMap.put(arguments.user.getAccountId(), local.hashes);
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
	
	public Array function getAllHashedPasswords(required cfesapi.org.owasp.esapi.User user, 
	                                            required boolean create) {
		local.hashes = instance.passwordMap.get(arguments.user.getAccountId());
		if(!isNull(local.hashes)) {
			return local.hashes;
		}
		if(arguments.create) {
			local.hashes = [];
			instance.passwordMap.put(arguments.user.getAccountId(), local.hashes);
			return local.hashes;
		}
		throwError(createObject("java", "java.lang.RuntimeException").init("No hashes found for " & arguments.user.getAccountName() & ". Is User.hashcode() and equals() implemented correctly?"));
	}
	
	/**
	 * Get a List of the specified User's old password hashes.  This will not return the User's current
	 * password hash.
	 *
	 * @param user he user whose old password hashes should be returned
	 * @return the specified User's old password hashes
	 */
	
	public Array function getOldPasswordHashes(required cfesapi.org.owasp.esapi.User user) {
		local.hashes = getAllHashedPasswords(arguments.user, false);
		if(local.hashes.size() > 1) {
			return duplicate(listToArray(listRest(arrayToList(local.hashes))));
		}
		return [];
	}
	
	/**
	 * The user map.
	 */
	instance.userMap = {};

	// Map<User, List<String>>, where the strings are password hashes, with the current hash in entry 0
	instance.passwordMap = {};

	/**
	 * {@inheritDoc}
	 */
	
	public cfesapi.org.owasp.esapi.User function createUser(required String accountName, 
	                                                        required String password1,
	                                                        required String password2) {
		loadUsersIfNecessary();
		if(trim(arguments.accountName) == "") {
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException(instance.ESAPI, "Account creation failed", "Attempt to create user with blank accountName"));
		}
		if(isObject(getUserByAccountName(arguments.accountName))) {
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException(instance.ESAPI, "Account creation failed", "Duplicate user creation denied for " & arguments.accountName));
		}
	
		verifyAccountNameStrength(arguments.accountName);
	
		if(trim(arguments.password1) == "") {
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Invalid account name", "Attempt to create account " & arguments.accountName & " with a blank password"));
		}
	
		local.user = new DefaultUser(instance.ESAPI, arguments.accountName);
	
		verifyPasswordStrength(newPassword=arguments.password1, user=local.user);
	
		if(!arguments.password1.equals(arguments.password2)) {
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Passwords do not match", "Passwords for " & arguments.accountName & " do not match"));
		}
	
		try {
			setHashedPassword(local.user, hashPassword(arguments.password1, arguments.accountName));
		}
		catch(cfesapi.org.owasp.esapi.errors.EncryptionException ee) {
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationException(instance.ESAPI, "Internal error", "Error hashing password for " & arguments.accountName, ee));
		}
		instance.userMap.put(local.user.getAccountId(), local.user);
		instance.logger.info(Logger.SECURITY_SUCCESS, "New user created: " & arguments.accountName);
		saveUsers();
		return local.user;
	}
	
	/**
	 * Generate a strong password that is not similar to the specified old password.
	 *
	 * @param oldPassword the password to be compared to the new password for similarity
	 * @return a new strong password that is dissimilar to the specified old password
	 */
	
	private String function _generateStrongPassword(required String oldPassword) {
		local.r = instance.ESAPI.randomizer();
		local.letters = local.r.getRandomInteger(4, 6);// inclusive, exclusive
		local.digits = 7 - local.letters;
		local.passLetters = local.r.getRandomString(local.letters, EncoderConstants.CHAR_PASSWORD_LETTERS);
		local.passDigits = local.r.getRandomString(local.digits, EncoderConstants.CHAR_PASSWORD_DIGITS);
		local.passSpecial = local.r.getRandomString(1, EncoderConstants.CHAR_PASSWORD_SPECIALS);
		local.newPassword = local.passLetters & local.passSpecial & local.passDigits;
		if(createObject("java", "org.owasp.esapi.StringUtilities").getLevenshteinDistance(arguments.oldPassword, local.newPassword) > 5) {
			return local.newPassword;
		}
		return _generateStrongPassword(arguments.oldPassword);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function changePassword(required cfesapi.org.owasp.esapi.User user, 
	                                    required String currentPassword,
	                                    required String newPassword,
	                                    required String newPassword2) {
		local.accountName = arguments.user.getAccountName();
		try {
			local.currentHash = getHashedPassword(arguments.user);
			local.verifyHash = hashPassword(arguments.currentPassword, local.accountName);
			if(!local.currentHash.equals(local.verifyHash)) {
				throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Password change failed", "Authentication failed for password change on user: " & local.accountName));
			}
			if(arguments.newPassword == "" || arguments.newPassword2 == "" || !arguments.newPassword.equals(arguments.newPassword2)) {
				throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Password change failed", "Passwords do not match for password change on user: " & local.accountName));
			}
			verifyPasswordStrength(arguments.currentPassword, arguments.newPassword, arguments.user);
			arguments.user.setLastPasswordChangeTime(now());
			local.newHash = hashPassword(arguments.newPassword, local.accountName);
			if(arrayFind(getOldPasswordHashes(arguments.user), local.newHash)) {
				throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Password change failed", "Password change matches a recent password for user: " & local.accountName));
			}
			setHashedPassword(arguments.user, local.newHash);
			instance.logger.info(Logger.SECURITY_SUCCESS, "Password changed for user: " & local.accountName);
			// jtm - 11/2/2010 - added to resolve http://code.google.com/p/owasp-esapi-java/issues/detail?id=13
			saveUsers();
		}
		catch(cfesapi.org.owasp.esapi.errors.EncryptionException ee) {
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationException(instance.ESAPI, "Password change failed", "Encryption exception changing password for " & local.accountName, ee));
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function verifyPassword(required cfesapi.org.owasp.esapi.User user, 
	                                       required String password) {
		local.accountName = arguments.user.getAccountName();
		try {
			local.hash = hashPassword(arguments.password, local.accountName);
			local.currentHash = getHashedPassword(arguments.user);
			if(local.hash.equals(local.currentHash)) {
				arguments.user.setLastLoginTime(now());
				arguments.user.setFailedLoginCount(0);
				instance.logger.info(Logger.SECURITY_SUCCESS, "Password verified for " & local.accountName);
				return true;
			}
		}
		catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
			instance.logger.fatal(Logger.SECURITY_FAILURE, "Encryption error verifying password for " & local.accountName);
		}
		instance.logger.fatal(Logger.SECURITY_FAILURE, "Password verification failed for " & local.accountName);
		return false;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function generateStrongPassword(cfesapi.org.owasp.esapi.User user, 
	                                              String oldPassword) {
		if (structKeyExists(arguments, "user") && structKeyExists(arguments, "oldPassword")) {
			local.newPassword = _generateStrongPassword(arguments.oldPassword);
			if(!isNull(local.newPassword)) {
				instance.logger.info(Logger.SECURITY_SUCCESS, "Generated strong password for " & arguments.user.getAccountName());
			}
			return local.newPassword;
		}
		else {
			return _generateStrongPassword("");
		}
	}
	
	/**
     * {@inheritDoc}
     */
     
    public function getUserByAccountId(required numeric accountId) {
        if (arguments.accountId == 0) {
            return new cfesapi.org.owasp.esapi.User$ANONYMOUS(instanceESAPI);
        }
        loadUsersIfNecessary();
        if (structKeyExists(instance.userMap, arguments.accountId)) {
	        return instance.userMap.get(arguments.accountId);
        }
        return "";
    }

    /**
     * {@inheritDoc}
     */
	 
    public function getUserByAccountName(required String accountName) {
        if (arguments.accountName == "") {
            return new cfesapi.org.owasp.esapi.User$ANONYMOUS(instanceESAPI);
        }
        loadUsersIfNecessary();
        for (local.u in instance.userMap) {
            if (instance.userMap[local.u].getAccountName().equalsIgnoreCase(arguments.accountName)) {
                return instance.userMap[local.u];
            }
        }
        return "";
    }
    
    /**
     * {@inheritDoc}
     */
     
    public Array function getUserNames() {
        loadUsersIfNecessary();
        local.results = [];
        for (local.u in instance.userMap) {
            local.results.add(instance.userMap[local.u].getAccountName());
        }
        return local.results;
    }
	
	/**
	 * {@inheritDoc}
	 *
	 * @throws EncryptionException
	 */
	
	public String function hashPassword(required String password, 
	                                    required String accountName) {
		local.salt = arguments.accountName.toLowerCase();
		return instance.ESAPI.encryptor().hash(arguments.password, local.salt);
	}
	
	/**
	 * Load users if they haven't been loaded in a while.
	 */
	
	private void function loadUsersIfNecessary() {
		if(!isObject(instance.userDB)) {
			instance.userDB = instance.ESAPI.securityConfiguration().getResourceFile("users.txt");
		}
		if(!isObject(instance.userDB)) {
			instance.userDB = createObject("java", "java.io.File").init(createObject("java", "java.lang.System").getProperty("user.home") & "/esapi", "users.txt");
			try {
				if(!instance.userDB.createNewFile()) {
					throwError(createObject("java", "java.io.IOException").init("Unable to create the user file"));
				}
				instance.logger.warning(Logger.SECURITY_SUCCESS, "Created " & instance.userDB.getAbsolutePath());
			}
			catch(java.io.IOException e) {
				instance.logger.fatal(Logger.SECURITY_FAILURE, "Could not create " & instance.userDB.getAbsolutePath(), e);
			}
		}
	
		// We only check at most every checkInterval milliseconds
		local.now = getTickCount();
		if(local.now - instance.lastChecked < instance.checkInterval) {
			return;
		}
		instance.lastChecked = local.now;
	
		if(instance.lastModified == instance.userDB.lastModified()) {
			return;
		}
		loadUsersImmediately();
	}
	
	// file was touched so reload it
	/**
	 *
	 */
	
	private void function loadUsersImmediately() {
		instance.logger.trace(Logger.SECURITY_SUCCESS, "Loading users from " & instance.userDB.getAbsolutePath());
	
		local.reader = "";
		try {
			local.map = {};
			local.reader = createObject("java", "java.io.BufferedReader").init(createObject("java", "java.io.FileReader").init(instance.userDB));
			local.line = local.reader.readLine();
			while(!isNull(local.line)) {
				if(local.line.length() > 0 && local.line.charAt(0) != chr(35)) {
					local.user = _createUser(local.line);
					if(local.map.containsKey(javaCast("long", local.user.getAccountId()))) {
						instance.logger.fatal(Logger.SECURITY_FAILURE, "Problem in user file. Skipping duplicate user: " & local.user);
					}
					local.map.put(local.user.getAccountId(), local.user);
				}
				local.line = local.reader.readLine();
			}
			instance.userMap = local.map;
			instance.lastModified = getTickCount();
			instance.logger.trace(Logger.SECURITY_SUCCESS, "User file reloaded: " & local.map.size());
		}
		catch(Exception e) {
			instance.logger.fatal(Logger.SECURITY_FAILURE, "Failure loading user file: " & instance.userDB.getAbsolutePath(), e);
		}
		finally
		{
			try {
				if(!isNull(local.reader) && isObject(local.reader)) {
					local.reader.close();
				}
			}
			catch(java.io.IOException e) {
				instance.logger.fatal(Logger.SECURITY_FAILURE, "Failure closing user file: " & instance.userDB.getAbsolutePath(), e);
			}
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
	
	private DefaultUser function _createUser(required String line) {
		JavaDate = createObject("java", "java.util.Date");
		
		local.parts = line.split(" *\| *");
		local.accountIdString = local.parts[1];
		local.accountId = javaCast("long", local.accountIdString);
		local.accountName = local.parts[2];
	
		verifyAccountNameStrength(local.accountName);
		local.user = new DefaultUser(instance.ESAPI, local.accountName);
		local.user.accountId = local.accountId;
	
		local.password = local.parts[3];
		verifyPasswordStrength(newPassword=local.password, user=local.user);
		setHashedPassword(local.user, local.password);
	
		local.roles = local.parts[4].toLowerCase().split(" *, *");
		for (local.i = 1; local.i <= arrayLen(local.roles); local.i++) {
		        local.role = local.roles[local.i];
			if("" != local.role) {
				local.user.addRole(local.role);
			}
		}
		if("unlocked" != local.parts[5]) {
			local.user.lock();
		}
		if("enabled" == local.parts[6]) {
			local.user.enable();
		}
		else {
			local.user.disable();
		}
	
		// generate a new csrf token
		local.user.resetCSRFToken();
	
		setOldPasswordHashes(local.user, local.parts[7].split(" *, *"));
		local.user.setLastHostAddress("unknown" == local.parts[8] ? "" : local.parts[8]);
		local.user.setLastPasswordChangeTime(JavaDate.init(javaCast("long", local.parts[9])));
		local.user.setLastLoginTime(JavaDate.init(javaCast("long", local.parts[10])));
		local.user.setLastFailedLoginTime(JavaDate.init(javaCast("long", local.parts[11])));
		local.user.setExpirationTime(JavaDate.init(javaCast("long", local.parts[12])));
		local.user.setFailedLoginCount(int(local.parts[13]));
		return local.user;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function removeUser(required String accountName) {
		loadUsersIfNecessary();
		local.user = getUserByAccountName(arguments.accountName);
		if(!isObject(local.user)) {
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException(instance.ESAPI, "Remove user failed", "Can't remove invalid accountName " & arguments.accountName));
		}
		instance.userMap.remove(local.user.getAccountId());
		instance.logger.info(Logger.SECURITY_SUCCESS, "Removing user " & local.user.getAccountName());
		instance.passwordMap.remove(local.user.getAccountId());
		saveUsers();
	}
	
	/**
	 * Saves the user database to the file system. In this implementation you must call save to commit any changes to
	 * the user file. Otherwise changes will be lost when the program ends.
	 *
	 * @throws AuthenticationException if the user file could not be written
	 */
	
	public void function saveUsers() {
		local.writer = "";
		try {
			local.writer = createObject("java", "java.io.PrintWriter").init(createObject("java", "java.io.FileWriter").init(instance.userDB));
			local.writer.println("## This is the user file associated with the ESAPI library from http://www.owasp.org");
			local.writer.println("## accountId | accountName | hashedPassword | roles | locked | enabled | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount");
			local.writer.println();
			_saveUsers(local.writer);
			local.writer.flush();
			instance.logger.info(Logger.SECURITY_SUCCESS, "User file written to disk");
		}
		catch(java.io.IOException e) {
			instance.logger.fatal(Logger.SECURITY_FAILURE, "Problem saving user file " & instance.userDB.getAbsolutePath(), e);
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationException(instance.ESAPI, "Internal Error", "Problem saving user file " & instance.userDB.getAbsolutePath(), e));
		}
		finally
		{
			if(isObject(local.writer)) {
				local.writer.close();
				instance.lastModified = instance.userDB.lastModified();
				instance.lastChecked = instance.lastModified;
			}
		}
	}
	
	/**
	 * Save users.
	 *
	 * @param writer the print writer to use for saving
	 */
	
	private void function _saveUsers(required writer) {
		for(local.o in getUserNames()) {
			local.accountName = local.o;
			local.u = getUserByAccountName(local.accountName);
			if(!isNull(local.u) && !local.u.isAnonymous()) {
				arguments.writer.println(save(local.u));
			}
			else {
				throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Problem saving user", "Skipping save of user " & local.accountName));
			}
		}
	}
	
	/**
	 * Save.
	 *
	 * @param user the User to save
	 * @return a line containing properly formatted information to save regarding the user
	 */
	
	private String function save(required DefaultUser user) {
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
	}
	
	/**
	 * {@inheritDoc}
	 * <p/>
	 * This implementation simply verifies that account names are at least 5 characters long. This helps to defeat a
	 * brute force attack, however the real strength comes from the name length and complexity.
	 *
	 * @param newAccountName
	 */
	
	public void function verifyAccountNameStrength(required String accountName) {
		if(arguments.accountName == "") {
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Invalid account name", "Attempt to create account with a null account name"));
		}
		if(!instance.ESAPI.validator().isValidInput("verifyAccountNameStrength", arguments.accountName, "AccountName", instance.MAX_ACCOUNT_NAME_LENGTH, false)) {
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Invalid account name", "New account name is not valid: " & arguments.accountName));
		}
	}
	
	/**
	 * {@inheritDoc}
	 * <p/>
	 * This implementation checks: - for any 3 character substrings of the old password - for use of a length *
	 * character sets > 16 (where character sets are upper, lower, digit, and special
	 * jtm - 11/16/2010 - added check to verify pw != username (fix for http://code.google.com/p/owasp-esapi-java/issues/detail?id=108)
	 */
	
	public void function verifyPasswordStrength(String oldPassword, 
	                                            required String newPassword,
	                                            required cfesapi.org.owasp.esapi.User user) {
		if(isNull(arguments.newPassword)) {
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Invalid password", "New password cannot be null"));
		}
	
		// can't change to a password that contains any 3 character substring of old password
		if(structKeyExists(arguments, "oldPassword")) {
			local.length = arguments.oldPassword.length();
			for(local.i = 0; local.i < local.length - 2; local.i++) {
				local.sub = arguments.oldPassword.substring(local.i, local.i + 3);
				if(arguments.newPassword.indexOf(local.sub) > -1) {
					throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Invalid password", "New password cannot contain pieces of old password"));
				}
			}
		}
		
		Arrays = createObject("java", "java.util.Arrays");
	
		// new password must have enough character sets and length
		local.charsets = 0;
		for(local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
			if(Arrays.binarySearch(EncoderConstants.CHAR_LOWERS, arguments.newPassword.charAt(local.i)) >= 0) {
				local.charsets++;
				break;
			}
		}
		for(local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
			if(Arrays.binarySearch(EncoderConstants.CHAR_UPPERS, arguments.newPassword.charAt(local.i)) >= 0) {
				local.charsets++;
				break;
			}
		}
		for(local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
			if(Arrays.binarySearch(EncoderConstants.CHAR_DIGITS, arguments.newPassword.charAt(local.i)) >= 0) {
				local.charsets++;
				break;
			}
		}
		for(local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
			if(Arrays.binarySearch(EncoderConstants.CHAR_SPECIALS, arguments.newPassword.charAt(local.i)) >= 0) {
				local.charsets++;
				break;
			}
		}
	
		// calculate and verify password strength
		local.strength = arguments.newPassword.length() * local.charsets;
		if(local.strength < 16) {
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Invalid password", "New password is not long and complex enough"));
		}
	
		local.accountName = arguments.user.getAccountName();
	
		//jtm - 11/3/2010 - fix for bug http://code.google.com/p/owasp-esapi-java/issues/detail?id=108
		if(local.accountName.equalsIgnoreCase(arguments.newPassword)) {
			//password can't be account name
			throwError(new cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException(instance.ESAPI, "Invalid password", "Password matches account name, irrespective of case"));
		}
	}
	
}