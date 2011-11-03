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
 * Reference implementation of the User interface. This implementation is serialized into a flat file in a simple format.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Chris Schmidt (chrisisbeef .at. gmail.com) <a href="http://www.digital-ritual.com">Digital Ritual Software</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.User
 */
component DefaultUser extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.User" {

	instance.ESAPI = "";

	/** The idle timeout length specified in the ESAPI config file. */
	this.IDLE_TIMEOUT_LENGTH = 20;

	/** The absolute timeout length specified in the ESAPI config file. */
	this.ABSOLUTE_TIMEOUT_LENGTH = 120;

	/** The logger used by the class. */
	instance.logger = "";

	/** This user's account id. */
	instance.accountId = 0;

	/** This user's account name. */
	instance.acountName = "";

	/** This user's screen name (account name alias). */
	instance.screenName = "";

	/** This user's CSRF token. */
	instance.csrfToken = "";

	/** This user's assigned roles. */
	instance.roles = [];

	/** Whether this user's account is locked. */
	instance.locked = false;

	/** Whether this user is logged in. */
	instance.loggedIn = true;

	/** Whether this user's account is enabled. */
	instance.enabled = false;

	/** The last host address used by this user. */
	instance.lastHostAddress = "";

	/** The last password change time for this user. */
	instance.lastPasswordChangeTime = newJava("java.util.Date").init(javaCast("long", 0));

	/** The last login time for this user. */
	instance.lastLoginTime = newJava("java.util.Date").init(javaCast("long", 0));

	/** The last failed login time for this user. */
	instance.lastFailedLoginTime = newJava("java.util.Date").init(javaCast("long", 0));

	/** The expiration date/time for this user's account. */
	instance.expirationTime = newJava("java.util.Date").init(javaCast("long", newJava("java.lang.Long").MAX_VALUE));

	/** The sessions this user is associated with */
	instance.sessions = [];

	/** The event map for this User */
	instance.eventMap = {};

	/* A flag to indicate that the password must be changed before the account can be used. */
	// instance.requiresPasswordChange = true;
	/** The failed login count for this user's account. */
	instance.failedLoginCount = 0;

	/** This user's Locale. */
	instance.locale = "";

	instance.MAX_ROLE_LENGTH = 250;

	/**
	 * Instantiates a new user.
	 *
	 * @param accountName
	 *         The name of this user's account.
	 */
	
	public DefaultUser function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI, required String accountName) {
		instance.ESAPI = arguments.ESAPI;
		this.IDLE_TIMEOUT_LENGTH = instance.ESAPI.securityConfiguration().getSessionIdleTimeoutLength();
		this.ABSOLUTE_TIMEOUT_LENGTH = instance.ESAPI.securityConfiguration().getSessionAbsoluteTimeoutLength();
		instance.logger = instance.ESAPI.getLogger("DefaultUser");
		instance.csrfToken = resetCSRFToken();
	
		instance.accountName = arguments.accountName.toLowerCase();
		while(true) {
			local.id = javaCast("long", abs(instance.ESAPI.randomizer().getRandomLong()));
			if(!isObject(instance.ESAPI.authenticator().getUserByAccountId(local.id)) && local.id != 0) {
				instance.accountId = local.id;
				break;
			}
		}
		
		return this;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function addRole(required String role) {
		local.roleName = arguments.role.toLowerCase();
		if(instance.ESAPI.validator().isValidInput("addRole", local.roleName, "RoleName", instance.MAX_ROLE_LENGTH, false)) {
			instance.roles.add(local.roleName);
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Role " & local.roleName & " added to " & getAccountName());
		}
		else {
			local.exception = new cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException(instance.ESAPI, "Add role failed", "Attempt to add invalid role " & local.roleName & " to " & getAccountName());
			throwError(local.exception);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function addRoles(required Array newRoles) {
		for(local.i = 1; local.i <= arrayLen(arguments.newRoles); local.i++) {
			addRole(arguments.newRoles[local.i]);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function changePassword(required String oldPassword, required String newPassword1, required String newPassword2) {
		instance.ESAPI.authenticator().changePassword(this, arguments.oldPassword, arguments.newPassword1, arguments.newPassword2);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function disable() {
		instance.enabled = false;
		instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account disabled: " & getAccountName());
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function enable() {
		instance.enabled = true;
		instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account enabled: " & getAccountName());
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getAccountId() {
		return duplicate(instance.accountId);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getAccountName() {
		return duplicate(instance.accountName);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getCSRFToken() {
		return duplicate(instance.csrfToken);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public function getExpirationTime() {
		return instance.expirationTime.clone();
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getFailedLoginCount() {
		return duplicate(instance.failedLoginCount);
	}
	
	/**
	 * Set the failed login count
	 * 
	 * @param count
	 *             the number of failed logins
	 */
	
	void function setFailedLoginCount(required numeric count) {
		instance.failedLoginCount = arguments.count;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public function getLastFailedLoginTime() {
		return instance.lastFailedLoginTime.clone();
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getLastHostAddress() {
		if(instance.lastHostAddress == "") {
			return "unknown";
		}
		return duplicate(instance.lastHostAddress);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public function getLastLoginTime() {
		return instance.lastLoginTime.clone();
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public function getLastPasswordChangeTime() {
		return instance.lastPasswordChangeTime.clone();
	}
	
	/**
	 * {@inheritDoc}
	 *
	 * @return
	 */
	
	public String function getName() {
		return this.getAccountName();
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public Array function getRoles() {
		return duplicate(instance.roles);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getScreenName() {
		return duplicate(instance.screenName);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function addSession(required s) {
		if(isInstanceOf(arguments.s, "cfesapi.org.owasp.esapi.HttpSession")) {
			instance.sessions.add(arguments.s);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function removeSession(required s) {
		if(isInstanceOf(arguments.s, "cfesapi.org.owasp.esapi.HttpSession")) {
			instance.sessions.remove(arguments.s);
		}
	}
	
	/**
	 * {@inheritDoc}
	 *
	 * @return
	 */
	
	public Array function getSessions() {
		return duplicate(instance.sessions);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function incrementFailedLoginCount() {
		instance.failedLoginCount++;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function isAnonymous() {
		// User cannot be anonymous, since we have a special User.ANONYMOUS instance
		// for the anonymous user
		return false;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function isEnabled() {
		return instance.enabled;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function isExpired() {
		return getExpirationTime().before(newJava("java.util.Date").init());
	
		// If expiration should happen automatically or based on lastPasswordChangeTime?
		//long from = lastPasswordChangeTime.getTime();
		//long to = newJava("java.util.Date").init().getTime();
		//double difference = to - from;
		//long days = Math.round((difference / (1000 * 60 * 60 * 24)));
		//return days > 60;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function isInRole(required String role) {
		return instance.roles.contains(arguments.role.toLowerCase());
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function isLocked() {
		return instance.locked;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function isLoggedIn() {
		return instance.loggedIn;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function isSessionAbsoluteTimeout() {
		local.session = instance.ESAPI.httpUtilities().getCurrentRequest().getSession(false);
		if(!isObject(local.session)) {
			return true;
		}
		local.deadline = newJava("java.util.Date").init(javaCast("long", local.session.getCreationTime() + this.ABSOLUTE_TIMEOUT_LENGTH));
		local.now = newJava("java.util.Date").init();
		return local.now.after(local.deadline);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function isSessionTimeout() {
		local.session = instance.ESAPI.httpUtilities().getCurrentRequest().getSession(false);
		if(!isObject(local.session)) {
			return true;
		}
		local.deadline = newJava("java.util.Date").init(javaCast("long", local.session.getLastAccessedTime() + this.IDLE_TIMEOUT_LENGTH));
		local.now = newJava("java.util.Date").init();
		return local.now.after(local.deadline);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function lock() {
		instance.locked = true;
		instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account locked: " & getAccountName());
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function loginWithPassword(cfesapi.org.owasp.esapi.HttpServletRequest request=instance.ESAPI.currentRequest(), required String password) {
		if(arguments.password == "") {
			setLastFailedLoginTime(newJava("java.util.Date").init());
			incrementFailedLoginCount();
			local.exception = new cfesapi.org.owasp.esapi.errors.AuthenticationLoginException(instance.ESAPI, "Login failed", "Missing password: " & getAccountName());
			throwError(local.exception);
		}
	
		// don't let disabled users log in
		if(!isEnabled()) {
			setLastFailedLoginTime(newJava("java.util.Date").init());
			incrementFailedLoginCount();
			local.exception = new cfesapi.org.owasp.esapi.errors.AuthenticationLoginException(instance.ESAPI, "Login failed", "Disabled user attempt to login: " & getAccountName());
			throwError(local.exception);
		}
	
		// don't let locked users log in
		if(isLocked()) {
			setLastFailedLoginTime(newJava("java.util.Date").init());
			incrementFailedLoginCount();
			local.exception = new cfesapi.org.owasp.esapi.errors.AuthenticationLoginException(instance.ESAPI, "Login failed", "Locked user attempt to login: " & getAccountName());
			throwError(local.exception);
		}
	
		// don't let expired users log in
		if(isExpired()) {
			setLastFailedLoginTime(newJava("java.util.Date").init());
			incrementFailedLoginCount();
			local.exception = new cfesapi.org.owasp.esapi.errors.AuthenticationLoginException(instance.ESAPI, "Login failed", "Expired user attempt to login: " & getAccountName());
			throwError(local.exception);
		}
	
		logout();
	
		if(verifyPassword(arguments.password)) {
			instance.loggedIn = true;
			instance.ESAPI.httpUtilities().changeSessionIdentifier(arguments.request);
			instance.ESAPI.authenticator().setCurrentUser(this);
			setLastLoginTime(newJava("java.util.Date").init());
			setLastHostAddress(arguments.request.getRemoteAddr());
			instance.logger.trace(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "User logged in: " & getAccountName());
		}
		else {
			instance.loggedIn = false;
			setLastFailedLoginTime(newJava("java.util.Date").init());
			incrementFailedLoginCount();
			if(getFailedLoginCount() >= instance.ESAPI.securityConfiguration().getAllowedLoginAttempts()) {
				this.lock();
			}
			local.exception = new cfesapi.org.owasp.esapi.errors.AuthenticationLoginException(instance.ESAPI, "Login failed", "Incorrect password provided for " & getAccountName());
			throwError(local.exception);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function logout() {
		instance.ESAPI.httpUtilities().killCookie(instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse(), instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);
	
		local.session = instance.ESAPI.currentRequest().getSession(false);
		if(structKeyExists(local, "session") && isObject(local.session)) {
			removeSession(local.session);
			local.session.invalidate();
		}
		// FIXME
		// I do not believe destroying the JSESSIONID cookie is currently working
		instance.ESAPI.httpUtilities().killCookie(instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse(), instance.ESAPI.securityConfiguration().getHttpSessionIdName());
		instance.loggedIn = false;
		instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Logout successful");
		local.anonymous = new cfesapi.org.owasp.esapi.User$ANONYMOUS(instance.ESAPI);
		instance.ESAPI.authenticator().setCurrentUser(local.anonymous);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function removeRole(required String role) {
		instance.roles.remove(arguments.role.toLowerCase());
		instance.logger.trace(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Role " & arguments.role & " removed from " & getAccountName());
	}
	
	/**
	 * {@inheritDoc}
	 * 
	 * In this implementation, we have chosen to use a random token that is
	 * stored in the User object. Note that it is possible to avoid the use of
	 * server side state by using either the hash of the users's session id or
	 * an encrypted token that includes a timestamp and the user's IP address.
	 * user's IP address. A relatively short 8 character string has been chosen
	 * because this token will appear in all links and forms.
	 * 
	 * @return the string
	 */
	
	public String function resetCSRFToken() {
		// user.csrfToken = instance.ESAPI.encryptor().hash( session.getId(),user.name );
		// user.csrfToken = instance.ESAPI.encryptor().encrypt( address & ":" & instance.ESAPI.encryptor().getTimeStamp();
		instance.csrfToken = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		return instance.csrfToken;
	}
	
	/**
	 * Sets the account id for this user's account.
	 */
	
	private void function setAccountId(required numeric accountId) {
		instance.accountId = arguments.accountId;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setAccountName(required String accountName) {
		local.old = getAccountName();
		instance.accountName = arguments.accountName.toLowerCase();
		if(!isNull(local.old)) {
			if(local.old.equals("")) {
				local.old = "[nothing]";
			}
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account name changed from " & local.old & " to " & getAccountName());
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setExpirationTime(required Date expirationTime) {
		instance.expirationTime = newJava("java.util.Date").init(javaCast("long", arguments.expirationTime.getTime()));
		instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account expiration time set to " & arguments.expirationTime & " for " & getAccountName());
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setLastFailedLoginTime(required Date lastFailedLoginTime) {
		instance.lastFailedLoginTime = arguments.lastFailedLoginTime;
		instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Set last failed login time to " & arguments.lastFailedLoginTime & " for " & getAccountName());
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setLastHostAddress(required String remoteHost) {
		if(instance.lastHostAddress != "" && !instance.lastHostAddress.equals(arguments.remoteHost)) {
			// returning remote address not remote hostname to prevent DNS lookup
			local.exception = new cfesapi.org.owasp.esapi.errors.AuthenticationHostException(instance.ESAPI, "Host change", "User session just jumped from " & instance.lastHostAddress & " to " & arguments.remoteHost);
			throwError(local.exception);
		}
		instance.lastHostAddress = arguments.remoteHost;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setLastLoginTime(required Date lastLoginTime) {
		instance.lastLoginTime = arguments.lastLoginTime;
		instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Set last successful login time to " & arguments.lastLoginTime & " for " & getAccountName());
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setLastPasswordChangeTime(required Date lastPasswordChangeTime) {
		instance.lastPasswordChangeTime = arguments.lastPasswordChangeTime;
		instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Set last password change time to " & arguments.lastPasswordChangeTime & " for " & getAccountName());
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setRoles(required Array roles) {
		instance.roles = [];
		addRoles(arguments.roles);
		instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Adding roles " & arrayToList(arguments.roles) & " to " & getAccountName());
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setScreenName(required String screenName) {
		instance.screenName = arguments.screenName;
		instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "ScreenName changed to " & arguments.screenName & " for " & getAccountName());
	}
	
	/**
	 * {@inheritDoc}
	 *
	 * @return
	 */
	
	public String function toString() {
		return "USER:" & getAccountName();
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function unlock() {
		instance.locked = false;
		instance.failedLoginCount = 0;
		instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account unlocked: " & getAccountName());
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function verifyPassword(required String password) {
		return instance.ESAPI.authenticator().verifyPassword(this, arguments.password);
	}
	
	/**
	 * Override clone and make final to prevent duplicate user objects.
	 * @return 
	 * @throws java.lang.CloneNotSupportedException
	 */
	
	public function clone() {
		throwError(newJava("java.lang.CloneNotSupportedException"));
	}
	
	/**
	 * @return the locale
	 */
	
	public function getLocale() {
		return instance.locale;
	}
	
	/**
	 * @param locale the locale to set
	 */
	
	public void function setLocale(required locale) {
		if(isInstanceOf(arguments.locale, "java.util.Locale")) {
			instance.locale = arguments.locale;
		}
		else {
			instance.locale = "";
		}
	}
	
	public Struct function getEventMap() {
		// do not wrap with duplicate(); needs to be modifiable
		return instance.eventMap;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function isEquals(required another) {
		// TODO
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function hashCode() {
		// TODO
	}
	
}