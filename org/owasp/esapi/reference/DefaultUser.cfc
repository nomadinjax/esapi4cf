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
<cfcomponent implements="org.owasp.esapi.User" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the User interface. This implementation is serialized into a flat file in a simple format.">

	<cfscript>
		variables.ESAPI = "";

		/** The idle timeout length specified in the ESAPI config file. */
		variables.IDLE_TIMEOUT_LENGTH = 20;

		/** The absolute timeout length specified in the ESAPI config file. */
		variables.ABSOLUTE_TIMEOUT_LENGTH = 120;

		/** The logger used by the class. */
		variables.logger = "";

		/** This user's account id. */
		this.accountId = 0;

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
		variables.lastPasswordChangeTime = newJava("java.util.Date").init(javaCast("long", 0));

		/** The last login time for this user. */
		variables.lastLoginTime = newJava("java.util.Date").init(javaCast("long", 0));

		/** The last failed login time for this user. */
		variables.lastFailedLoginTime = newJava("java.util.Date").init(javaCast("long", 0));

		/** The expiration date/time for this user's account. */
		variables.expirationTime = newJava("java.util.Date").init(javaCast("long", newJava("java.lang.Long").MAX_VALUE));

		/** The session's this user is associated with */
		variables.sessions = [];

		/* A flag to indicate that the password must be changed before the account can be used. */
		// variables.requiresPasswordChange = true;
		/** The failed login count for this user's account. */
		variables.failedLoginCount = 0;

		variables.MAX_ROLE_LENGTH = 250;
	</cfscript>

	<cffunction access="public" returntype="DefaultUser" name="init" output="false"
	            hint="Instantiates a new user.">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="String" name="accountName" hint="The name of this user's account."/>

		<cfscript>
			// CF8 requires 'var' at the top
			var id = "";

			variables.ESAPI = arguments.ESAPI;
			variables.IDLE_TIMEOUT_LENGTH = variables.ESAPI.securityConfiguration().getSessionIdleTimeoutLength();
			variables.ABSOLUTE_TIMEOUT_LENGTH = variables.ESAPI.securityConfiguration().getSessionAbsoluteTimeoutLength();
			variables.logger = variables.ESAPI.getLogger("DefaultUser");

			setAccountName(arguments.accountName);
			while(true) {
				id = javaCast("long", abs(variables.ESAPI.randomizer().getRandomLong()));
				if(!isObject(variables.ESAPI.authenticator().getUserByAccountId(id)) && id != 0) {
					setAccountId(id);
					break;
				}
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			var roleName = arguments.role.toLowerCase();
			if(variables.ESAPI.validator().isValidInput("addRole", roleName, "RoleName", variables.MAX_ROLE_LENGTH, false)) {
				variables.roles.add(roleName);
				variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Role " & roleName & " added to " & getAccountName());
			}
			else {
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationAccountsException").init(variables.ESAPI, "Add role failed", "Attempt to add invalid role " & roleName & " to " & getAccountName()));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addRoles" output="false">
		<cfargument required="true" type="Array" name="newRoles"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";

			for(i = 1; i <= arrayLen(arguments.newRoles); i++) {
				addRole(arguments.newRoles[i]);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfargument required="true" type="String" name="oldPassword"/>
		<cfargument required="true" type="String" name="newPassword1"/>
		<cfargument required="true" type="String" name="newPassword2"/>

		<cfscript>
			variables.ESAPI.authenticator().changePassword(this, arguments.oldPassword, arguments.newPassword1, arguments.newPassword2);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="disable" output="false">

		<cfscript>
			variables.enabled = false;
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Account disabled: " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="enable" output="false">

		<cfscript>
			variables.enabled = true;
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Account enabled: " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getAccountId" output="false">

		<cfscript>
			return duplicate(this.accountId);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getAccountName" output="false">

		<cfscript>
			return duplicate(variables.accountName);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCSRFToken" output="false">

		<cfscript>
			return duplicate(variables.csrfToken);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getExpirationTime" output="false">

		<cfscript>
			return duplicate(variables.expirationTime);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getFailedLoginCount" output="false">

		<cfscript>
			return duplicate(variables.failedLoginCount);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setFailedLoginCount" output="false"
	            hint="Set the failed login count">
		<cfargument required="true" type="numeric" name="count" hint="the number of failed logins"/>

		<cfscript>
			variables.failedLoginCount = arguments.count;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getLastFailedLoginTime" output="false">

		<cfscript>
			return duplicate(variables.lastFailedLoginTime);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLastHostAddress" output="false">

		<cfscript>
			if(variables.lastHostAddress == "") {
				return "local";
			}
			return duplicate(variables.lastHostAddress);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getLastLoginTime" output="false">

		<cfscript>
			return duplicate(variables.lastLoginTime);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getLastPasswordChangeTime" output="false">

		<cfscript>
			return duplicate(variables.lastPasswordChangeTime);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getName" output="false">

		<cfscript>
			return getAccountName();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getRoles" output="false">

		<cfscript>
			return duplicate(variables.roles);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getScreenName" output="false">

		<cfscript>
			return duplicate(variables.screenName);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addSession" output="false">
		<cfargument required="true" name="s"/>

		<cfscript>
			if(isInstanceOf(arguments.s, "org.owasp.esapi.util.HttpSession")) {
				variables.sessions.add(arguments.s);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeSession" output="false">
		<cfargument required="true" name="s"/>

		<cfscript>
			if(isInstanceOf(arguments.s, "org.owasp.esapi.util.HttpSession")) {
				variables.sessions.remove(arguments.s);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getSessions" output="false">

		<cfscript>
			return duplicate(variables.sessions);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="incrementFailedLoginCount" output="false">

		<cfscript>
			variables.failedLoginCount++;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAnonymous" output="false">

		<cfscript>
			// User cannot be anonymous, since we have a special User.ANONYMOUS instance for the anonymous user
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isEnabled" output="false">

		<cfscript>
			return variables.enabled;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isExpired" output="false">

		<cfscript>
			return getExpirationTime().before(newJava("java.util.Date").init());

			// If expiration should happen automatically or based on lastPasswordChangeTime?
			//long from = lastPasswordChangeTime.getTime();
			//long to = newJava("java.util.Date").init().getTime();
			//double difference = to - from;
			//long days = Math.round((difference / (1000 * 60 * 60 * 24)));
			//return days > 60;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isInRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			return variables.roles.contains(arguments.role.toLowerCase());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isLocked" output="false">

		<cfscript>
			return variables.locked;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isLoggedIn" output="false">

		<cfscript>
			return variables.loggedIn;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isSessionAbsoluteTimeout" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var httpSession = "";
			var deadline = "";
			var timestamp = "";

			httpSession = variables.ESAPI.httpUtilities().getCurrentRequest().getSession(false);
			if(!isObject(httpSession))
				return true;
			deadline = newJava("java.util.Date").init(javaCast("long", httpSession.getCreationTime() + variables.ABSOLUTE_TIMEOUT_LENGTH));
			timestamp = newJava("java.util.Date").init();
			return timestamp.after(deadline);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isSessionTimeout" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var httpSession = "";
			var deadline = "";
			var timestamp = "";

			httpSession = variables.ESAPI.httpUtilities().getCurrentRequest().getSession(false);
			if(!isObject(httpSession))
				return true;
			deadline = newJava("java.util.Date").init(javaCast("long", httpSession.getLastAccessedTime() + variables.IDLE_TIMEOUT_LENGTH));
			timestamp = newJava("java.util.Date").init();
			return timestamp.after(deadline);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="lock" output="false">

		<cfscript>
			variables.locked = true;
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Account locked: " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="loginWithPassword" output="false">
		<cfargument required="true" type="String" name="password"/>

		<cfscript>
			if(arguments.password == "" || arguments.password.equals("")) {
				setLastFailedLoginTime(newJava("java.util.Date").init());
				incrementFailedLoginCount();
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, "Login failed", "Missing password: " & variables.accountName));
			}

			// don't let disabled users log in
			if(!isEnabled()) {
				setLastFailedLoginTime(newJava("java.util.Date").init());
				incrementFailedLoginCount();
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, "Login failed", "Disabled user attempt to login: " & variables.accountName));
			}

			// don't let locked users log in
			if(isLocked()) {
				setLastFailedLoginTime(newJava("java.util.Date").init());
				incrementFailedLoginCount();
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, "Login failed", "Locked user attempt to login: " & variables.accountName));
			}

			// don't let expired users log in
			if(isExpired()) {
				setLastFailedLoginTime(newJava("java.util.Date").init());
				incrementFailedLoginCount();
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, "Login failed", "Expired user attempt to login: " & variables.accountName));
			}

			logout();

			if(verifyPassword(arguments.password)) {
				variables.loggedIn = true;
				variables.ESAPI.httpUtilities().changeSessionIdentifier(variables.ESAPI.currentRequest());
				variables.ESAPI.authenticator().setCurrentUser(this);
				setLastLoginTime(newJava("java.util.Date").init());
				setLastHostAddress(variables.ESAPI.httpUtilities().getCurrentRequest().getRemoteHost());
				variables.logger.trace(getSecurityType("SECURITY_SUCCESS"), true, "User logged in: " & variables.accountName);
			}
			else {
				variables.loggedIn = false;
				setLastFailedLoginTime(newJava("java.util.Date").init());
				incrementFailedLoginCount();
				if(getFailedLoginCount() >= variables.ESAPI.securityConfiguration().getAllowedLoginAttempts()) {
					this.lock();
				}
				throwException(createObject("component", "org.owasp.esapi.errors.AuthenticationLoginException").init(variables.ESAPI, "Login failed", "Incorrect password provided for " & getAccountName()));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="logout" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var httpSession = "";

			variables.ESAPI.httpUtilities().killCookie(variables.ESAPI.currentRequest(), variables.ESAPI.currentResponse(), variables.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);

			httpSession = variables.ESAPI.currentRequest().getSession(false);
			if(isObject(httpSession)) {
				removeSession(httpSession);
				httpSession.invalidate();
			}
			variables.ESAPI.httpUtilities().killCookie(variables.ESAPI.currentRequest(), variables.ESAPI.currentResponse(), "JSESSIONID");
			variables.loggedIn = false;
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Logout successful");
			variables.ESAPI.authenticator().setCurrentUser(createObject("component", "org.owasp.esapi.User$ANONYMOUS").init(variables.ESAPI));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			variables.roles.remove(arguments.role.toLowerCase());
			variables.logger.trace(getSecurityType("SECURITY_SUCCESS"), true, "Role " & arguments.role & " removed from " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="resetCSRFToken" output="false"
	            hint="In this implementation, we have chosen to use a random token that is stored in the User object. Note that it is possible to avoid the use of server side state by using either the hash of the users's session id or an encrypted token that includes a timestamp and the user's IP address. user's IP address. A relatively short 8 character string has been chosen because this token will appear in all links and forms.">

		<cfscript>
			// user.csrfToken = variables.ESAPI.encryptor().hash( session.getId(),user.name );
			// user.csrfToken = variables.ESAPI.encryptor().encrypt( address & ":" & variables.ESAPI.encryptor().getTimeStamp();
			variables.csrfToken = variables.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			return variables.csrfToken;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="setAccountId" output="false">
		<cfargument required="true" type="numeric" name="accountId"/>

		<cfscript>
			this.accountId = arguments.accountId;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAccountName" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			var old = getAccountName();
			variables.accountName = arguments.accountName.toLowerCase();
			if(old != "")
				variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Account name changed from " & old & " to " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setExpirationTime" output="false">
		<cfargument required="true" type="Date" name="expirationTime"/>

		<cfscript>
			variables.expirationTime = newJava("java.util.Date").init(javaCast("long", arguments.expirationTime.getTime()));
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Account expiration time set to " & arguments.expirationTime & " for " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastFailedLoginTime" output="false">
		<cfargument required="true" type="Date" name="lastFailedLoginTime"/>

		<cfscript>
			variables.lastFailedLoginTime = arguments.lastFailedLoginTime;
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Set last failed login time to " & arguments.lastFailedLoginTime & " for " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastHostAddress" output="false">
		<cfargument required="true" type="String" name="remoteHost"/>

		<cfscript>
			if(variables.lastHostAddress != "" && !variables.lastHostAddress.equals(arguments.remoteHost)) {
				// returning remote address not remote hostname to prevent DNS lookup
				createObject("component", "org.owasp.esapi.errors.AuthenticationHostException").init(variables.ESAPI, "Host change", "User session just jumped from " & variables.lastHostAddress & " to " & arguments.remoteHost);
			}
			variables.lastHostAddress = arguments.remoteHost;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastLoginTime" output="false">
		<cfargument required="true" type="Date" name="lastLoginTime"/>

		<cfscript>
			variables.lastLoginTime = arguments.lastLoginTime;
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Set last successful login time to " & arguments.lastLoginTime & " for " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastPasswordChangeTime" output="false">
		<cfargument required="true" type="Date" name="lastPasswordChangeTime"/>

		<cfscript>
			variables.lastPasswordChangeTime = arguments.lastPasswordChangeTime;
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Set last password change time to " & arguments.lastPasswordChangeTime & " for " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setRoles" output="false">
		<cfargument required="true" type="Array" name="roles"/>

		<cfscript>
			variables.roles = [];
			addRoles(arguments.roles);
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Adding roles " & arrayToList(arguments.roles) & " to " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setScreenName" output="false">
		<cfargument required="true" type="String" name="screenName"/>

		<cfscript>
			variables.screenName = arguments.screenName;
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "ScreenName changed to " & arguments.screenName & " for " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toStringData" output="false">

		<cfscript>
			return "USER:" & variables.accountName;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="unlock" output="false">

		<cfscript>
			variables.locked = false;
			variables.failedLoginCount = 0;
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Account unlocked: " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false">
		<cfargument required="true" type="String" name="password"/>

		<cfscript>
			return variables.ESAPI.authenticator().verifyPassword(this, arguments.password);
		</cfscript>

	</cffunction>

	<cffunction access="public" name="clone" output="false" hint="Override clone and make final to prevent duplicate user objects.">

		<cfscript>
			throw(object=newJava("java.lang.CloneNotSupportedException").init());
		</cfscript>

	</cffunction>

</cfcomponent>