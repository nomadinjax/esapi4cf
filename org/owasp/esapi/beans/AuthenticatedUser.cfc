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
import "org.owasp.esapi.errors.AuthenticationHostException";
import "org.owasp.esapi.errors.AuthenticationLoginException";
import "org.owasp.esapi.util.Utils";

/**
 * Reference implementation of the User interface. This implementation is serialized into a flat file in a simple format.
 */
component implements="org.owasp.esapi.User" extends="org.owasp.esapi.util.Object" {

	property type="numeric" name="accountId";
	property type="string" name="accountName";

	variables.ESAPI = "";

	/** The idle timeout length specified in the ESAPI config file. */
	this.IDLE_TIMEOUT_LENGTH = 1000 * 60 * 20;

	/** The absolute timeout length specified in the ESAPI config file. */
	this.ABSOLUTE_TIMEOUT_LENGTH = 1000 * 60 * 120;

	/** The logger used by the class. */
	variables.logger = "";

	/** This user's account id. */
	variables.accountId = 0;

	/** This user's account name. */
	variables.accountName = "";

	/** This user's screen name (account name alias). */
	variables.screenName = "";

	/** This user's CSRF token. */
	variables.csrfToken = "";

	/** This user's assigned roles. */
	variables.roles = [];

	/** Whether this user's account is locked. */
	variables.locked = false;

	/** Whether this user is logged in. */
	variables.loggedIn = true;

	/** Whether this user's account is enabled. */
	variables.enabled = false;

	/** The last host address used by this user. */
	variables.lastHostAddress = "";

	/** The last password change time for this user. */
	variables.lastPasswordChangeTime = createObject("java", "java.util.Date").init(javaCast("long", 0));

	/** The last login time for this user. */
	variables.lastLoginTime = createObject("java", "java.util.Date").init(javaCast("long", 0));

	/** The last failed login time for this user. */
	variables.lastFailedLoginTime = createObject("java", "java.util.Date").init(javaCast("long", 0));

	/** The expiration date/time for this user's account. */
	variables.expirationTime = createObject("java", "java.util.Date").init(javaCast("long", createObject("java", "java.lang.Long").MAX_VALUE));

	/** The sessions this user is associated with */
	variables.sessions = [];

	/** The event map for this User */
	variables.eventMap = {};

	/* A flag to indicate that the password must be changed before the account can be used. */
	variables.requiresPasswordChange = true;

	/** The failed login count for this user's account. */
	variables.failedLoginCount = 0;

	/** This user's Locale. */
	variables.Locale = "";

	variables.MAX_ROLE_LENGTH = 250;

	/**
	 * Instantiates a new user.
	 *
	 * @param accountName
	 * 		The name of this user's account.
	 */
	public AuthenticatedUser function init(required org.owasp.esapi.ESAPI ESAPI, required string accountName) {
		variables.ESAPI = arguments.ESAPI;
		variables.logger = variables.ESAPI.getLogger(getMetaData(this).fullName);

		variables.csrfToken = resetCSRFToken();

		this.IDLE_TIMEOUT_LENGTH = variables.ESAPI.securityConfiguration().getSessionIdleTimeoutLength();
		this.ABSOLUTE_TIMEOUT_LENGTH = variables.ESAPI.securityConfiguration().getSessionAbsoluteTimeoutLength();

		variables.accountName = lCase(arguments.accountName);
		var id = javaCast("long", abs(variables.ESAPI.randomizer().getRandomLong()));
		variables.accountId = id;

		return this;
	}

	public void function addRole(required string role) {
		var roleName = arguments.role.toLowerCase();
		if ( variables.ESAPI.validator().isValidInput("addRole", roleName, "RoleName", variables.MAX_ROLE_LENGTH, false) ) {
			variables.roles.add(roleName);
			variables.logger.info(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Role {0} added to {1}", [roleName, getAccountName()]) );
		} else {
			raiseException(new AuthenticationAccountsException( "Add role failed", new Utils().messageFormat("Attempt to add invalid role {0} to {1}", [roleName, getAccountName()]) ));
		}
	}

	public void function addRoles(required array newRoles) {
		for(var newRole in arguments.newRoles) {
			addRole(newRole);
		}
	}

	public void function changePassword(required string oldPassword, required string newPassword1, required string newPassword2) {
		variables.ESAPI.authenticator().changePassword(this, arguments.oldPassword, arguments.newPassword1, arguments.newPassword2);
	}

	public void function disable() {
		variables.enabled = false;
		variables.logger.info(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Account disabled: {0}", [getAccountName()]));
	}

	public void function enable() {
		variables.enabled = true;
		variables.logger.info(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Account enabled: {0}", [getAccountName()]));
	}

	public numeric function getAccountId() {
		return variables.accountId;
	}

	public string function getAccountName() {
		return variables.accountName;
	}

	public string function getCSRFToken() {
		return variables.csrfToken;
	}

	public date function getExpirationTime() {
		return duplicate(variables.expirationTime);
	}

	public numeric function getFailedLoginCount() {
		return variables.failedLoginCount;
	}

	/**
	 * Set the failed login count
	 *
	 * @param count
	 * 			the number of failed logins
	 */
	public void function setFailedLoginCount(required numeric count) {
		variables.failedLoginCount = arguments.count;
	}

	public date function getLastFailedLoginTime() {
		return duplicate(variables.lastFailedLoginTime);
	}

	public string function getLastHostAddress() {
		if (isNull(variables.lastHostAddress) || !len(trim(variables.lastHostAddress))) {
			return "";
		}
		return variables.lastHostAddress;
	}

	public date function getLastLoginTime() {
		return duplicate(variables.lastLoginTime);
	}

	public date function getLastPasswordChangeTime() {
		return duplicate(variables.lastPasswordChangeTime);
	}

	public array function getRoles() {
		return duplicate(variables.roles);
	}

	public string function getScreenName() {
		return variables.screenName;
	}

	public void function addSession(required s) {
		variables.sessions.add(arguments.s);
	}

	public void function removeSession(required s) {
		variables.sessions.remove(arguments.s);
	}

	public array function getSessions() {
		return variables.sessions;
	}

	public void function incrementFailedLoginCount() {
		variables.failedLoginCount++;
	}

	public boolean function isAnonymous() {
		// User cannot be anonymous, since we have a special User.ANONYMOUS instance
		// for the anonymous user
		return false;
	}

	public boolean function isEnabled() {
		return variables.enabled;
	}

	public boolean function isExpired() {
		return getExpirationTime().before(now());
	}

	public boolean function isInRole(required string role) {
		return variables.roles.contains(arguments.role.toLowerCase());
	}

	public boolean function isLocked() {
		return variables.locked;
	}

	public boolean function isLoggedIn() {
		return variables.loggedIn;
	}

	public boolean function isSessionAbsoluteTimeout(httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest()) {
		var httpSession = arguments.httpRequest.getSession(false);
		if (isNull(httpSession)) return true;
		var deadline = createObject("java", "java.util.Date").init(javaCast("long", httpSession.getCreationTime() + this.ABSOLUTE_TIMEOUT_LENGTH));
		var timestamp = now();
		return timestamp.after(deadline);
	}

	public boolean function isSessionTimeout(httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest()) {
		var httpSession = arguments.httpRequest.getSession(false);
		if (isNull(httpSession)) {
			return true;
		}
		var deadline = createObject("java", "java.util.Date").init(javaCast("long", httpSession.getLastAccessedTime() + this.IDLE_TIMEOUT_LENGTH));
		var timestamp = now();
		return timestamp.after(deadline);
	}

	public void function lock() {
		variables.locked = true;
		variables.logger.info(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Account locked: {0}", [getAccountName()]));
	}

	public void function loginWithPassword(required string password, httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest(), httpResponse=variables.ESAPI.httpUtilities().getCurrentResponse()) {
		if (isNull(arguments.password) || arguments.password.equals("")) {
			setLastFailedLoginTime(now());
			incrementFailedLoginCount();
			variables.ESAPI.getAdapter().saveUser(this);
			raiseException(new AuthenticationLoginException(variables.ESAPI, variables.ESAPI.getResource().getString("Authenticator.loginFailed"), new Utils().messageFormat("Missing password: {0}", [variables.accountName])));
		}

		// don't let disabled users log in
		if ( !isEnabled() ) {
			setLastFailedLoginTime(now());
			incrementFailedLoginCount();
			variables.ESAPI.getAdapter().saveUser(this);
			raiseException(new AuthenticationLoginException(variables.ESAPI, variables.ESAPI.getResource().getString("Authenticator.loginFailed"), new Utils().messageFormat("Disabled user attempt to login: {0}", [variables.accountName])));
		}

		// don't let locked users log in
		if ( isLocked() ) {
			setLastFailedLoginTime(now());
			incrementFailedLoginCount();
			variables.ESAPI.getAdapter().saveUser(this);
			raiseException(new AuthenticationLoginException(variables.ESAPI, variables.ESAPI.getResource().getString("Authenticator.loginFailed"), new Utils().messageFormat("Locked user attempt to login: {0}", [variables.accountName])));
		}

		// don't let expired users log in
		if ( isExpired() ) {
			setLastFailedLoginTime(now());
			incrementFailedLoginCount();
			variables.ESAPI.getAdapter().saveUser(this);
			raiseException(new AuthenticationLoginException(variables.ESAPI, variables.ESAPI.getResource().getString("Authenticator.loginFailed"), new Utils().messageFormat("Expired user attempt to login: {0}", [variables.accountName])));
		}

		logout(arguments.httpRequest, arguments.httpResponse);

		if ( verifyPassword(arguments.password) ) {
			variables.loggedIn = true;
			variables.ESAPI.httpUtilities().changeSessionIdentifier(arguments.httpRequest);
			variables.ESAPI.authenticator().setCurrentUser(this);
			variables.failedLoginCount = 0;
			setLastLoginTime(now());
			setLastHostAddress(arguments.httpRequest.getRemoteAddr());
			variables.ESAPI.getAdapter().saveUser(this);
			variables.logger.trace(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("User logged in: {0}", [variables.accountName]));
		}
		else {
			variables.loggedIn = false;
			setLastFailedLoginTime(now());
			incrementFailedLoginCount();
			if (getFailedLoginCount() >= variables.ESAPI.securityConfiguration().getAllowedLoginAttempts()) {
				this.lock();
			}
			variables.ESAPI.getAdapter().saveUser(this);
			raiseException(new AuthenticationLoginException(variables.ESAPI, variables.ESAPI.getResource().getString("Authenticator.loginFailed"), new Utils().messageFormat("Incorrect password provided for {0}", [variables.accountName])));
		}
	}

	public void function logout(httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest(), httpResponse=variables.ESAPI.httpUtilities().getCurrentResponse()) {
		variables.ESAPI.httpUtilities().killCookie(variables.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME, arguments.httpRequest, arguments.httpResponse);
		var httpSession = arguments.httpRequest.getSession(false);
		if (!isNull(httpSession)) {
			removeSession(httpSession);
			httpSession.invalidate();
		}
		//variables.ESAPI.httpUtilities().killCookie(variables.ESAPI.securityConfiguration().getHttpSessionIdName(), arguments.httpRequest, arguments.httpResponse);
		variables.loggedIn = false;
		variables.logger.info(variables.Logger.SECURITY_SUCCESS, "Logout successful");
		variables.ESAPI.authenticator().setCurrentUser("");
	}

	public void function removeRole(required string role) {
		variables.roles.remove(arguments.role.toLowerCase());
		variables.logger.trace(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Role {0} removed from {1}", [arguments.role, getAccountName()]));
	}

	/**
	 * In this implementation, we have chosen to use a random token that is
	 * stored in the User object. Note that it is possible to avoid the use of
	 * server side state by using either the hash of the users's session id or
	 * an encrypted token that includes a timestamp and the user's IP address.
	 * user's IP address. A relatively short 8 character string has been chosen
	 * because this token will appear in all links and forms.
	 *
	 * @return the string
	 */
	public string function resetCSRFToken() {
		variables.csrfToken = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		return variables.csrfToken;
	}

	public void function setAccountId(required numeric accountId) {
		variables.accountId = arguments.accountId;
	}

	public void function setAccountName(required string accountName) {
		var old = getAccountName();
		variables.accountName = arguments.accountName.toLowerCase();
		if (!isNull(old)) {
			if ( old == "" ) {
				old = "[nothing]";
			}
			variables.logger.info(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Account name changed from {0} to {1}", [old, getAccountName()]));
		}
	}

	public void function setExpirationTime(required date expirationTime) {
		variables.expirationTime = createObject("java", "java.util.Date").init(javaCast("long", arguments.expirationTime.getTime()));
		variables.logger.info(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Account expiration time set to {0} for {1}", [arguments.expirationTime, getAccountName()]));
	}

	public void function setLastFailedLoginTime(required date lastFailedLoginTime) {
		variables.lastFailedLoginTime = arguments.lastFailedLoginTime;
		variables.logger.info(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Set last failed login time to {0} for {1}", [arguments.lastFailedLoginTime, getAccountName()]));
	}

	public void function setLastHostAddress(required string remoteHost) {
		if(!isNull(variables.lastHostAddress) && len(trim(variables.lastHostAddress)) && variables.lastHostAddress != arguments.remoteHost) {
			// returning remote address not remote hostname to prevent DNS lookup
			raiseException(new AuthenticationHostException(variables.ESAPI, variables.ESAPI.getResource().getString("User.hostAddressMismatch"), new Utils().messageFormat("User session just jumped from {0} to {1}", [variables.lastHostAddress, arguments.remoteHost])));
		}
		variables.lastHostAddress = arguments.remoteHost;
	}

	public void function setLastLoginTime(required date lastLoginTime) {
		variables.lastLoginTime = arguments.lastLoginTime;
		variables.logger.info(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Set last successful login time to {0} for {1}", [arguments.lastLoginTime, getAccountName()]));
	}

	public void function setLastPasswordChangeTime(required date lastPasswordChangeTime) {
		variables.lastPasswordChangeTime = arguments.lastPasswordChangeTime;
		variables.logger.info(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Set last password change time to {0} for {1}", [arguments.lastPasswordChangeTime, getAccountName()]));
	}

	public void function setRoles(required array roles) {
		variables.roles = [];
		addRoles(arguments.roles);
		variables.logger.info(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Adding roles {0} to {1}", [arrayToList(arguments.roles), getAccountName()]));
	}

	public void function setScreenName(required string screenName) {
		variables.screenName = arguments.screenName;
		variables.logger.info(variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("ScreenName changed to {0} for {1}", [arguments.screenName, getAccountName()] ));
	}

	public void function unlock() {
		variables.locked = false;
		variables.failedLoginCount = 0;
		variables.logger.info( variables.Logger.SECURITY_SUCCESS, new Utils().messageFormat("Account unlocked: {0}", [getAccountName()]));
	}

	public boolean function verifyPassword(required string password) {
		return variables.ESAPI.authenticator().verifyPassword(this, arguments.password);
	}

	/**
	 * @return the locale
	 */
	public function getLocale() {
		return variables.Locale;
	}

	/**
	 * @param locale the locale to set
	 */
	public void function setLocale(required Locale) {
		variables.Locale = arguments.Locale;
	}

	public struct function getEventMap() {
		return variables.eventMap;
	}

}