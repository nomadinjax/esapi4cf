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
import "org.owasp.esapi.errors.AuthenticationException";
import "org.owasp.esapi.errors.AuthenticationAccountsException";
import "org.owasp.esapi.errors.AuthenticationCredentialsException";
import "org.owasp.esapi.errors.AuthenticationLoginException";
import "org.owasp.esapi.beans.ThreadLocalUser";

/**
 * A partial implementation of the Authenticator interface.
 * This class should not implement any methods that would be meant
 * to modify a User object, since that's probably implementation specific.
 */
component implements="org.owasp.esapi.Authenticator" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";

    variables.logger = "";

    /**
     * The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an
     * application. Otherwise, each thread would have to pass the User object through the calltree to any methods that
     * need it. Because we want exceptions and log calls to contain user data, that could be almost anywhere. Therefore,
     * the ThreadLocal approach simplifies things greatly. <P> As a possible extension, one could create a delegation
     * framework by adding another ThreadLocal to hold the delegating user identity.
     */
    variables.currentUser = "";

	// constructor

	public org.owasp.esapi.Authenticator function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;
		variables.logger = variables.ESAPI.getLogger(getMetaData(this).fullName);

		variables.currentUser = new ThreadLocalUser(variables.ESAPI);

		return this;
	}

	public org.owasp.esapi.beans.AnonymousUser function getAnonymousUserInstance() {
		return new org.owasp.esapi.beans.AnonymousUser(variables.ESAPI);
	}

	public org.owasp.esapi.beans.AuthenticatedUser function getAuthenticatedUserInstance(required string accountName) {
		return new org.owasp.esapi.beans.AuthenticatedUser(variables.ESAPI, arguments.accountName);
	}


    public void function clearCurrent() {
        // variables.logger.logWarning(variables.logger.SECURITY, "************Clearing threadlocals. Thread" + Thread.currentThread().getName() );
        variables.currentUser.remove();
    }

    public boolean function exists(required string accountName) {
        return !isNull(getUserByAccountName(arguments.accountName));
    }

    /**
     * <p/>
     * Returns the currently logged user as set by the setCurrentUser() methods. Must not log in this method because the
     * logger calls getCurrentUser() and this could cause a loop.
     */
    public org.owasp.esapi.User function getCurrentUser() {
        var user = variables.currentUser.get();
        if (!isObject(user)) {
            user = getAnonymousUserInstance();
        }
        return user;
    }

    /**
     * Gets the user from session.
     *
     * @return the user from session or null if no user is found in the session
     */
    public function getUserFromSession(httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest()) {
        var httpSession = arguments.httpRequest.getSession(false);
        if (isNull(httpSession) || !isObject(httpSession)) return;
        var user = variables.ESAPI.httpUtilities().getSessionAttribute(variables.ESAPI.securityConfiguration().getUserSessionKey(), httpSession);
        if (!isNull(user) && isObject(user)) return user;
    }

    /**
     * Returns the user if a matching remember token is found, or null if the token
     * is missing, token is corrupt, token is expired, account name does not match
     * and existing account, or hashed password does not match user's hashed password.
     *
     * @return the user if a matching remember token is found, or null if the token
     *         is missing, token is corrupt, token is expired, account name does not match
     *         and existing account, or hashed password does not match user's hashed password.
     */
    private function getUserFromRememberToken(httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest(), httpResponse=variables.ESAPI.httpUtilities().getCurrentResponse()) {
    	var HTTPUtilities = variables.ESAPI.httpUtilities();
        try {
            var token = HTTPUtilities.getRememberToken(arguments.httpRequest);
            if (isNull(token)) return;

            // See Google Issue 144 regarding first URLDecode the token and THEN unsealing.
            // Note that this Google Issue was marked as "WontFix".

            var data = listToArray(variables.ESAPI.encryptor().unseal(token), "|");
            if (arrayLen(data) != 2) {
                variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Found corrupt or expired remember token");
                HTTPUtilities.invalidateRememberToken(arguments.httpRequest, arguments.httpResponse);
                return;
            }

            var username = data[1];
            var password = data[2];
            var user = getUserByAccountName(username);
            if (isNull(user)) {
                variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Found valid remember token but no user matching " & username);
                return;
            }

            variables.logger.info(variables.Logger.SECURITY_SUCCESS, "Logging in user with remember token: " & user.getAccountName());
            user.loginWithPassword(password, arguments.httpRequest, arguments.httpResponse);
            return user;
        }
        catch (org.owasp.esapi.errors.AuthenticationException ae) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Login via remember me cookie failed", ae);
        }
        catch (org.owasp.esapi.errors.EncryptionException ex) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Remember token was missing, corrupt, or expired");
        }
        catch (org.owasp.esapi.errors.EnterpriseSecurityException ex) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Remember token was missing, corrupt, or expired");
        }
        HTTPUtilities.invalidateRememberToken(arguments.httpRequest, arguments.httpResponse);
        return;
    }

    /**
     * Utility method to extract credentials and verify them.
     *
     * @param request The current HTTP request
     * @return The user that successfully authenticated
     * @throws AuthenticationException if the submitted credentials are invalid.
     */
    private org.owasp.esapi.User function loginWithUsernameAndPassword(httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest(), httpResponse=variables.ESAPI.httpUtilities().getCurrentResponse()) {
        var httpUsername = arguments.httpRequest.getParameter(variables.ESAPI.securityConfiguration().getUsernameParameterName());
        var httpPassword = arguments.httpRequest.getParameter(variables.ESAPI.securityConfiguration().getPasswordParameterName());

        // if a logged-in user is requesting to login, log them out first
        var user = getCurrentUser();
        if (!isNull(user) && isObject(user) && !user.isAnonymous()) {
            variables.logger.warning(variables.Logger.SECURITY_SUCCESS, "User requested relogin. Performing logout then authentication");
            user.logout(arguments.httpRequest, arguments.httpResponse);
        }

        // now authenticate with username and password
        if (isNull(httpUsername) || isNull(httpPassword)) {
            if (isNull(httpUsername)) {
                httpUsername = "unspecified user";
            }
            raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Authentication failed", "Authentication failed for " & httpUsername & " because of null username or password"));
        }
        user = getUserByAccountName(httpUsername);
        if (isNull(user)) {
            raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Authentication failed", "Authentication failed because user " & httpUsername & " doesn't exist"));
        }
        user.loginWithPassword(httpPassword, arguments.httpRequest, arguments.httpResponse);

        arguments.httpRequest.setAttribute(user.getCSRFToken(), "authenticated");
        return user;
    }

    public org.owasp.esapi.User function login(httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest(), httpResponse=variables.ESAPI.httpUtilities().getCurrentResponse()) {
        if (isNull(arguments.httpRequest) || isNull(arguments.httpResponse)) {
            raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Invalid request", "Request or response objects were null"));
        }

        // if there's a user in the session then use that
        var user = getUserFromSession(arguments.httpRequest);

        // else if there's a remember token then use that
        if (!structKeyExists(local, "user") || (isNull(user) && isObject(user))) {
            user = getUserFromRememberToken(arguments.httpRequest, arguments.httpResponse);
        }

        // else try to verify credentials - throws exception if login fails
        if (!structKeyExists(local, "user") || (isNull(user) && isObject(user))) {
            user = loginWithUsernameAndPassword(arguments.httpRequest, arguments.httpResponse);

            // warn if this authentication request was not POST or non-SSL connection, exposing credentials or session id
	        try {
	            variables.ESAPI.httpUtilities().assertSecureRequest(arguments.httpRequest);
	        }
	        catch (org.owasp.esapi.errors.AccessControlException ex) {
	            raiseException(new AuthenticationException(variables.ESAPI, "Attempt to login with an insecure request", ex.detail, ex));
	        }
        }
        else {
			// warn if this authentication request was non-SSL connection, exposing session id
			try {
				variables.ESAPI.httpUtilities().assertSecureChannel(arguments.httpRequest);
			}
			catch (org.owasp.esapi.errors.AccessControlException ex) {
				raiseException(new AuthenticationException(variables.ESAPI, "Attempt to access secure content with an insecure request", ex.detail, ex));
			}
        }

        // set last host address
        user.setLastHostAddress(arguments.httpRequest.getRemoteHost());

        // don't let anonymous user log in
        if (user.isAnonymous()) {
            user.logout(arguments.httpRequest, arguments.httpResponse);
            raiseException(new AuthenticationLoginException(variables.ESAPI, "Login failed", "Anonymous user cannot be set to current user. User: " & user.getAccountName()));
        }

        // don't let disabled users log in
        if (!user.isEnabled()) {
            user.logout(arguments.httpRequest, arguments.httpResponse);
            user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(now());
            variables.ESAPI.getAdapter().saveUser(user);
            raiseException(new AuthenticationLoginException(variables.ESAPI, "Login failed", "Disabled user cannot be set to current user. User: " & user.getAccountName()));
        }

        // don't let locked users log in
        if (user.isLocked()) {
            user.logout(arguments.httpRequest, arguments.httpResponse);
            user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(now());
            variables.ESAPI.getAdapter().saveUser(user);
            raiseException(new AuthenticationLoginException(variables.ESAPI, "Login failed", "Locked user cannot be set to current user. User: " & user.getAccountName()));
        }

        // don't let expired users log in
        if (user.isExpired()) {
            user.logout(arguments.httpRequest, arguments.httpResponse);
            user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(now());
            variables.ESAPI.getAdapter().saveUser(user);
            raiseException(new AuthenticationLoginException(variables.ESAPI, "Login failed", "Expired user cannot be set to current user. User: " & user.getAccountName()));
        }

        // check session inactivity timeout
        if (user.isSessionTimeout(arguments.httpRequest)) {
            user.logout(arguments.httpRequest, arguments.httpResponse);
            user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(now());
            variables.ESAPI.getAdapter().saveUser(user);
            raiseException(new AuthenticationLoginException(variables.ESAPI, "Login failed", "Session inactivity timeout: " & user.getAccountName()));
        }

        // check session absolute timeout
        if (user.isSessionAbsoluteTimeout(arguments.httpRequest)) {
            user.logout(arguments.httpRequest, arguments.httpResponse);
            user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(now());
            variables.ESAPI.getAdapter().saveUser(user);
            raiseException(new AuthenticationLoginException(variables.ESAPI, "Login failed", "Session absolute timeout: " & user.getAccountName()));
        }

        //set Locale to the user object in the session from request
        var locale = arguments.httpRequest.getLocale();
        if (!isNull(locale) && isObject(locale)) {
        	user.setLocale(locale);
		}

        // create new session for this User
        var httpSession = arguments.httpRequest.getSession();
        user.addSession(httpSession);
        httpSession.setAttribute(variables.ESAPI.securityConfiguration().getUserSessionKey(), user);
        setCurrentUser(user);
        return user;
    }

    public void function logout(httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest(), httpResponse=variables.ESAPI.httpUtilities().getCurrentResponse()) {
        var user = getCurrentUser();
        if (!isNull(user) && isObject(user) && !user.isAnonymous()) {
            user.logout(arguments.httpRequest, arguments.httpResponse);
        }
    }

    public void function setCurrentUser(required user) {
    	if (isInstanceOf(arguments.user, "org.owasp.esapi.User")) {
        	variables.currentUser.setUser(arguments.user);
        }
        else {
        	variables.currentUser.remove();
        }
    }

    public org.owasp.esapi.User function createUser(required string accountName, required string password1, required string password2) {
        if (isNull(arguments.accountName)) {
            raiseException(new AuthenticationAccountsException(variables.ESAPI, "Account creation failed", "Attempt to create user with null accountName"));
        }
        if (!isNull(getUserByAccountName(arguments.accountName))) {
            raiseException(new AuthenticationAccountsException(variables.ESAPI, "Account creation failed", "Duplicate user creation denied for " & arguments.accountName));
        }

        verifyAccountNameStrength(arguments.accountName);

        if (isNull(arguments.password1)) {
            raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Invalid account name", "Attempt to create account " & arguments.accountName & " with a null password"));
        }

        var user = getAuthenticatedUserInstance(arguments.accountName);

        verifyPasswordStrength(user, arguments.password1);

        if (!arguments.password1.equals(arguments.password2)) {
            raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Passwords do not match", "Passwords for " & arguments.accountName & " do not match"));
        }

        variables.ESAPI.getAdapter().saveUser(user);
        variables.logger.info(variables.Logger.SECURITY_SUCCESS, "New user created: " & arguments.accountName);

        try {
            setHashedPassword(user, hashPassword(arguments.password1, arguments.accountName));
        } catch (org.owasp.esapi.errors.EncryptionException ee) {
            raiseException(new AuthenticationException(variables.ESAPI, "Internal error", "Error hashing password for " & arguments.accountName, ee));
        }
        return user;
    }

    public void function changePassword(required org.owasp.esapi.User user, required string currentPassword, required string newPassword, required string newPassword2) {
        var accountName = arguments.user.getAccountName();
        try {
            var currentHash = getHashedPassword(arguments.user);
            var verifyHash = hashPassword(arguments.currentPassword, accountName);
            if (!currentHash.equals(verifyHash)) {
                raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Password change failed", "Authentication failed for password change on user: " & accountName));
            }
            if (isNull(arguments.newPassword) || isNull(arguments.newPassword2) || arguments.newPassword != arguments.newPassword2) {
                raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Password change failed", "Passwords do not match for password change on user: " & accountName));
            }
            verifyPasswordStrength(arguments.user, arguments.newPassword, arguments.currentPassword);
            arguments.user.setLastPasswordChangeTime(now());
            var newHash = hashPassword(arguments.newPassword, accountName);
            if (arrayFind(variables.ESAPI.getAdapter().getOldPasswordHashes(arguments.user), newHash)) {
                raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Password change failed", "Password change matches a recent password for user: " & accountName));
            }
            setHashedPassword(arguments.user, newHash);
            variables.logger.info(variables.Logger.SECURITY_SUCCESS, "Password changed for user: " & accountName);
            variables.ESAPI.getAdapter().saveUser(arguments.user);
        } catch (EncryptionException ee) {
            raiseException(new AuthenticationException(variables.ESAPI, "Password change failed", "Encryption exception changing password for " & accountName, ee));
        }
    }

    public boolean function verifyPassword(required org.owasp.esapi.User user, required string password) {
        var accountName = arguments.user.getAccountName();
        try {
            var hash = hashPassword(arguments.password, accountName);
            var currentHash = getHashedPassword(arguments.user);
            if (hash.equals(currentHash)) {
                arguments.user.setLastLoginTime(now());
                arguments.user.setFailedLoginCount(0);
                variables.logger.info(variables.Logger.SECURITY_SUCCESS, "Password verified for " & accountName);
                return true;
            }
        } catch (EncryptionException e) {
            variables.logger.fatal(variables.Logger.SECURITY_FAILURE, "Encryption error verifying password for " & accountName);
        }
        variables.logger.fatal(variables.Logger.SECURITY_FAILURE, "Password verification failed for " & accountName);
        return false;
    }

    public string function generateStrongPassword(org.owasp.esapi.User user, string oldPassword) {
        if (structKeyExists(arguments, "user") && structKeyExists(arguments, "oldPassword")) {
	        var newPassword = _generateStrongPassword(arguments.oldPassword);
	        if (!isNull(newPassword)) {
	            variables.logger.info(variables.Logger.SECURITY_SUCCESS, "Generated strong password for " & arguments.user.getAccountName());
	        }
	        return newPassword;
		}
		else {
			return _generateStrongPassword("");
		}
    }

    /**
     * Generate a strong password that is not similar to the specified old password.
     *
     * @param oldPassword the password to be compared to the new password for similarity
     * @return a new strong password that is dissimilar to the specified old password
     */
    private string function _generateStrongPassword(required string oldPassword) {
    	var StringUtilities = createObject("java", "org.owasp.esapi.StringUtilities");
        var r = variables.ESAPI.randomizer();
        var letters = r.getRandomInteger(4, 6);  // inclusive, exclusive
        var digits = 7 - letters;
        var passLetters = r.getRandomString(letters, variables.ESAPI.encoder().CHAR_PASSWORD_LETTERS);
        var passDigits = r.getRandomString(digits, variables.ESAPI.encoder().CHAR_PASSWORD_DIGITS);
        var passSpecial = r.getRandomString(1, variables.ESAPI.encoder().CHAR_PASSWORD_SPECIALS);
        var newPassword = passLetters & passSpecial & passDigits;
        if (StringUtilities.getLevenshteinDistance(arguments.oldPassword, newPassword) > 5) {
            return newPassword;
        }
        return _generateStrongPassword(arguments.oldPassword);
    }

    public function getUserByAccountId(required numeric accountId) {
        if (arguments.accountId == 0) {
            return getAnonymousUserInstance();
        }
        return variables.ESAPI.getAdapter().getUserByAccountId(arguments.accountId);
    }

    public function getUserByAccountName(required string accountName) {
        if (isNull(arguments.accountName)) {
            return getAnonymousUserInstance();
        }
        return variables.ESAPI.getAdapter().getUserByAccountName(arguments.accountName);
    }

    public array function getUserNames() {
        return variables.ESAPI.getAdapter().getUserNames();
    }

    /**
     * @throws EncryptionException
     */
    public string function hashPassword(required string password, required string accountName) {
        var salt = arguments.accountName.toLowerCase();
        return variables.ESAPI.encryptor().hash(arguments.password, salt);
    }

    public void function removeUser(required string accountName) {
        var user = getUserByAccountName(arguments.accountName);
        if (isNull(user)) {
			raiseException(new AuthenticationAccountsException(variables.ESAPI, "Remove user failed", "Can't remove invalid accountName " & accountName));
        }
        variables.ESAPI.getAdapter().removeUser(user);
        variables.logger.info(variables.Logger.SECURITY_SUCCESS, "Removing user " & user.getAccountName());
    }

    /**
     * <p/>
     * This implementation simply verifies that account names are at least 5 characters long. This helps to defeat a
     * brute force attack, however the real strength comes from the name length and complexity.
     *
     * @param accountName
     */
    public void function verifyAccountNameStrength(required string accountName) {
        if (isNull(arguments.accountName)) {
            raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Invalid account name", "Attempt to create account with a null account name"));
        }
        if (!variables.ESAPI.validator().isValidInput("verifyAccountNameStrength", arguments.accountName, "AccountName", variables.ESAPI.securityConfiguration().getAccountNameLengthMax(), false)) {
            raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Invalid account name", "New account name is not valid: " & arguments.accountName));
        }
    }

    /**
     * <p/>
     * This implementation checks: - for any 3 character substrings of the old password - for use of a length *
     * character sets > 16 (where character sets are upper, lower, digit, and special
     * jtm - 11/16/2010 - added check to verify pw != username (fix for http://code.google.com/p/owasp-esapi-java/issues/detail?id=108)
     */
    public void function verifyPasswordStrength(required org.owasp.esapi.User user, required string newPassword, string oldPassword) {
        if (isNull(arguments.newPassword)) {
            raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Invalid password", "New password cannot be null"));
        }

        // can't change to a password that contains any 3 character substring of old password
        if (structKeyExists(arguments, "oldPassword") && !isNull(arguments.oldPassword)) {
            var length = len(arguments.oldPassword);
            for (var i = 0; i < length - 2; i++) {
                var sub = arguments.oldPassword.substring(i, i + 3);
                if (arguments.newPassword.indexOf(sub) > -1) {
                    raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Invalid password", "New password cannot contain pieces of old password"));
                }
            }
        }

        // new password must have enough character sets and length
        var Arrays = createObject("java", "java.util.Arrays");
        var charsets = 0;
        for (var i = 0; i < arguments.newPassword.length(); i++) {
            if (Arrays.binarySearch(variables.ESAPI.encoder().CHAR_LOWERS, arguments.newPassword.charAt(i)) >= 0) {
                charsets++;
                break;
            }
        }
        for (var i = 0; i < arguments.newPassword.length(); i++) {
            if (Arrays.binarySearch(variables.ESAPI.encoder().CHAR_UPPERS, arguments.newPassword.charAt(i)) >= 0) {
                charsets++;
                break;
            }
        }
        for (var i = 0; i < arguments.newPassword.length(); i++) {
            if (Arrays.binarySearch(variables.ESAPI.encoder().CHAR_DIGITS, arguments.newPassword.charAt(i)) >= 0) {
                charsets++;
                break;
            }
        }
        for (var i = 0; i < arguments.newPassword.length(); i++) {
            if (Arrays.binarySearch(variables.ESAPI.encoder().CHAR_SPECIALS, arguments.newPassword.charAt(i)) >= 0) {
                charsets++;
                break;
            }
        }

        // calculate and verify password strength
        var strength = arguments.newPassword.length() * charsets;
        if (strength < variables.ESAPI.securityConfiguration().getPasswordStrengthComplexity()) {
            raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Invalid password", "New password is not long and complex enough"));
        }

        var accountName = arguments.user.getAccountName();

        //jtm - 11/3/2010 - fix for bug http://code.google.com/p/owasp-esapi-java/issues/detail?id=108
        if (accountName.equalsIgnoreCase(arguments.newPassword)) {
        	//password can't be account name
        	raiseException(new AuthenticationCredentialsException(variables.ESAPI, "Invalid password", "Password matches account name, irrespective of case"));
        }
    }

    /**
     * Return the specified User's current hashed password.
     *
     * @param user this User's current hashed password will be returned
     * @return the specified User's current hashed password
     */
    public function getHashedPassword(required org.owasp.esapi.User user) {
        var hashes = variables.ESAPI.getAdapter().getAllHashedPasswords(arguments.user);
        if (arrayLen(hashes)) {
        	return hashes[1];
        }
        return "";
    }

    /**
     * Add a hash to a User's hashed password list.  This method is used to store a user's old password hashes
     * to be sure that any new passwords are not too similar to old passwords.
     *
     * @param user the user to associate with the new hash
     * @param hash the hash to store in the user's password hash list
     */
    public void function setHashedPassword(required org.owasp.esapi.User user, required string hash) {
        var hashes = variables.ESAPI.getAdapter().getAllHashedPasswords(arguments.user);
        arrayPrepend(hashes, arguments.hash);
        if (arrayLen(hashes) > variables.ESAPI.securityConfiguration().getMaxOldPasswordHashes()) {
            arrayDeleteAt(hashes, arrayLen(hashes));
        }
        variables.ESAPI.getAdapter().savePasswordHashes(arguments.user, hashes);
        variables.logger.info(variables.Logger.SECURITY_SUCCESS, "New hashed password stored for " & arguments.user.getAccountName());
    }

}