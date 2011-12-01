<!--- /**
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
 */ --->
<cfcomponent displayname="DefaultUser" extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.User" output="false"
             hint="Reference implementation of the User interface. This implementation is serialized into a flat file in a simple format.">

	<cfscript>
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
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="init" output="false"
	            hint="Instantiates a new user.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="String" name="accountName" hint="The name of this user's account."/>

		<cfset var local = {}/>

		<cfscript>
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
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfset var local = {}/>

		<cfscript>
			local.roleName = arguments.role.toLowerCase();
			if(instance.ESAPI.validator().isValidInput("addRole", local.roleName, "RoleName", instance.MAX_ROLE_LENGTH, false)) {
				instance.roles.add(local.roleName);
				instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Role " & local.roleName & " added to " & getAccountName());
			}
			else {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException").init(instance.ESAPI, "Add role failed", "Attempt to add invalid role " & local.roleName & " to " & getAccountName());
				throwError(local.exception);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addRoles" output="false">
		<cfargument required="true" type="Array" name="newRoles"/>

		<cfset var local = {}/>

		<cfscript>
			for(local.i = 1; local.i <= arrayLen(arguments.newRoles); local.i++) {
				addRole(arguments.newRoles[local.i]);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfargument required="true" type="String" name="oldPassword"/>
		<cfargument required="true" type="String" name="newPassword1"/>
		<cfargument required="true" type="String" name="newPassword2"/>

		<cfscript>
			instance.ESAPI.authenticator().changePassword(this, arguments.oldPassword, arguments.newPassword1, arguments.newPassword2);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="disable" output="false">

		<cfscript>
			instance.enabled = false;
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account disabled: " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="enable" output="false">

		<cfscript>
			instance.enabled = true;
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account enabled: " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getAccountId" output="false">

		<cfscript>
			return duplicate(instance.accountId);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getAccountName" output="false">

		<cfscript>
			return duplicate(instance.accountName);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCSRFToken" output="false">

		<cfscript>
			return duplicate(instance.csrfToken);
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getExpirationTime" output="false">

		<cfscript>
			return instance.expirationTime.clone();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getFailedLoginCount" output="false">

		<cfscript>
			return duplicate(instance.failedLoginCount);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setFailedLoginCount" output="false"
	            hint="Set the failed login count">
		<cfargument required="true" type="numeric" name="count" hint="the number of failed logins"/>

		<cfscript>
			instance.failedLoginCount = arguments.count;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLastFailedLoginTime" output="false">

		<cfscript>
			return instance.lastFailedLoginTime.clone();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLastHostAddress" output="false">

		<cfscript>
			if(instance.lastHostAddress == "") {
				return "unknown";
			}
			return duplicate(instance.lastHostAddress);
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLastLoginTime" output="false">

		<cfscript>
			return instance.lastLoginTime.clone();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLastPasswordChangeTime" output="false">

		<cfscript>
			return instance.lastPasswordChangeTime.clone();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getName" output="false">

		<cfscript>
			return this.getAccountName();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getRoles" output="false">

		<cfscript>
			return duplicate(instance.roles);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getScreenName" output="false">

		<cfscript>
			return duplicate(instance.screenName);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addSession" output="false">
		<cfargument required="true" name="s"/>

		<cfscript>
			if(isInstanceOf(arguments.s, "cfesapi.org.owasp.esapi.HttpSession")) {
				instance.sessions.add(arguments.s);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeSession" output="false">
		<cfargument required="true" name="s"/>

		<cfscript>
			if(isInstanceOf(arguments.s, "cfesapi.org.owasp.esapi.HttpSession")) {
				instance.sessions.remove(arguments.s);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getSessions" output="false">

		<cfscript>
			return duplicate(instance.sessions);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="incrementFailedLoginCount" output="false">

		<cfscript>
			instance.failedLoginCount++;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAnonymous" output="false">

		<cfscript>
			// User cannot be anonymous, since we have a special User.ANONYMOUS instance
			// for the anonymous user
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isEnabled" output="false">

		<cfscript>
			return instance.enabled;
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
			return instance.roles.contains(arguments.role.toLowerCase());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isLocked" output="false">

		<cfscript>
			return instance.locked;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isLoggedIn" output="false">

		<cfscript>
			return instance.loggedIn;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isSessionAbsoluteTimeout" output="false">
		<cfargument name="request" default="#instance.ESAPI.currentRequest()#"/>
		<cfset var local = {}/>

		<cfscript>
			if (isObject(arguments.request)) {
				local.session = arguments.request.getSession(false);
			}
			if(!isObject(local.session)) {
				return true;
			}
			local.deadline = newJava("java.util.Date").init(javaCast("long", local.session.getCreationTime() + this.ABSOLUTE_TIMEOUT_LENGTH));
			local.now = newJava("java.util.Date").init();
			return local.now.after(local.deadline);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isSessionTimeout" output="false">
		<cfargument name="request" default="#instance.ESAPI.currentRequest()#"/>
		<cfset var local = {}/>

		<cfscript>
			if (isObject(arguments.request)) {
				local.session = arguments.request.getSession(false);
			}
			if(!structKeyExists(local, "session")) {
				return true;
			}
			local.deadline = newJava("java.util.Date").init(javaCast("long", local.session.getLastAccessedTime() + this.IDLE_TIMEOUT_LENGTH));
			local.now = newJava("java.util.Date").init();
			return local.now.after(local.deadline);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="lock" output="false">

		<cfscript>
			instance.locked = true;
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account locked: " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="loginWithPassword" output="false">
		<cfargument name="request" default="#instance.ESAPI.currentRequest()#"/>
		<cfargument required="true" type="String" name="password"/>

		<cfset var local = {}/>

		<cfscript>
			if(arguments.password == "") {
				setLastFailedLoginTime(newJava("java.util.Date").init());
				incrementFailedLoginCount();
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Missing password: " & getAccountName());
				throwError(local.exception);
			}

			// don't let disabled users log in
			if(!isEnabled()) {
				setLastFailedLoginTime(newJava("java.util.Date").init());
				incrementFailedLoginCount();
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Disabled user attempt to login: " & getAccountName());
				throwError(local.exception);
			}

			// don't let locked users log in
			if(isLocked()) {
				setLastFailedLoginTime(newJava("java.util.Date").init());
				incrementFailedLoginCount();
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Locked user attempt to login: " & getAccountName());
				throwError(local.exception);
			}

			// don't let expired users log in
			if(isExpired()) {
				setLastFailedLoginTime(newJava("java.util.Date").init());
				incrementFailedLoginCount();
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Expired user attempt to login: " & getAccountName());
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
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Incorrect password provided for " & getAccountName());
				throwError(local.exception);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="logout" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.request = instance.ESAPI.currentRequest();

			instance.ESAPI.httpUtilities().killCookie(local.request, instance.ESAPI.currentResponse(), instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);

			if(isObject(local.request)) {
				local.session = local.request.getSession(false);
			}
			if(structKeyExists(local, "session") && isObject(local.session)) {
				removeSession(local.session);
				local.session.invalidate();
			}
			// FIXME
			// I do not believe destroying the JSESSIONID cookie is currently working
			instance.ESAPI.httpUtilities().killCookie(local.request, instance.ESAPI.currentResponse(), instance.ESAPI.securityConfiguration().getHttpSessionIdName());
			instance.loggedIn = false;
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Logout successful");
			local.anonymous = newComponent("cfesapi.org.owasp.esapi.User$ANONYMOUS").init(instance.ESAPI);
			instance.ESAPI.authenticator().setCurrentUser(local.anonymous);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			instance.roles.remove(arguments.role.toLowerCase());
			instance.logger.trace(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Role " & arguments.role & " removed from " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="resetCSRFToken" output="false"
	            hint="In this implementation, we have chosen to use a random token that is stored in the User object. Note that it is possible to avoid the use of server side state by using either the hash of the users's session id or an encrypted token that includes a timestamp and the user's IP address. user's IP address. A relatively short 8 character string has been chosen because this token will appear in all links and forms.">

		<cfscript>
			// user.csrfToken = instance.ESAPI.encryptor().hash( session.getId(),user.name );
			// user.csrfToken = instance.ESAPI.encryptor().encrypt( address & ":" & instance.ESAPI.encryptor().getTimeStamp();
			instance.csrfToken = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			return instance.csrfToken;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="setAccountId" output="false"
	            hint="Sets the account id for this user's account.">
		<cfargument required="true" type="numeric" name="accountId"/>

		<cfscript>
			instance.accountId = arguments.accountId;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAccountName" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfset var local = {}/>

		<cfscript>
			local.old = getAccountName();
			instance.accountName = arguments.accountName.toLowerCase();
			if(structKeyExists(local, "old")) {
				if(local.old.equals("")) {
					local.old = "[nothing]";
				}
				instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account name changed from " & local.old & " to " & getAccountName());
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setExpirationTime" output="false">
		<cfargument required="true" type="Date" name="expirationTime"/>

		<cfscript>
			instance.expirationTime = newJava("java.util.Date").init(javaCast("long", arguments.expirationTime.getTime()));
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account expiration time set to " & arguments.expirationTime & " for " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastFailedLoginTime" output="false">
		<cfargument required="true" type="Date" name="lastFailedLoginTime"/>

		<cfscript>
			instance.lastFailedLoginTime = arguments.lastFailedLoginTime;
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Set last failed login time to " & arguments.lastFailedLoginTime & " for " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastHostAddress" output="false">
		<cfargument required="true" type="String" name="remoteHost"/>

		<cfset var local = {}/>

		<cfscript>
			if(instance.lastHostAddress != "" && !instance.lastHostAddress.equals(arguments.remoteHost)) {
				// returning remote address not remote hostname to prevent DNS lookup
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationHostException").init(instance.ESAPI, "Host change", "User session just jumped from " & instance.lastHostAddress & " to " & arguments.remoteHost);
				throwError(local.exception);
			}
			instance.lastHostAddress = arguments.remoteHost;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastLoginTime" output="false">
		<cfargument required="true" type="Date" name="lastLoginTime"/>

		<cfscript>
			instance.lastLoginTime = arguments.lastLoginTime;
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Set last successful login time to " & arguments.lastLoginTime & " for " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastPasswordChangeTime" output="false">
		<cfargument required="true" type="Date" name="lastPasswordChangeTime"/>

		<cfscript>
			instance.lastPasswordChangeTime = arguments.lastPasswordChangeTime;
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Set last password change time to " & arguments.lastPasswordChangeTime & " for " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setRoles" output="false">
		<cfargument required="true" type="Array" name="roles"/>

		<cfscript>
			instance.roles = [];
			addRoles(arguments.roles);
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Adding roles " & arrayToList(arguments.roles) & " to " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setScreenName" output="false">
		<cfargument required="true" type="String" name="screenName"/>

		<cfscript>
			instance.screenName = arguments.screenName;
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "ScreenName changed to " & arguments.screenName & " for " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toStringESAPI" output="false">

		<cfscript>
			return "USER:" & getAccountName();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="unlock" output="false">

		<cfscript>
			instance.locked = false;
			instance.failedLoginCount = 0;
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Account unlocked: " & getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false">
		<cfargument required="true" type="String" name="password"/>

		<cfscript>
			return instance.ESAPI.authenticator().verifyPassword(this, arguments.password);
		</cfscript>

	</cffunction>

	<cffunction access="public" name="clone" output="false" hint="Override clone and make final to prevent duplicate user objects.">

		<cfscript>
			throwError(newJava("java.lang.CloneNotSupportedException"));
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLocaleESAPI" output="false" hint="the locale">

		<cfscript>
			return instance.locale;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLocaleESAPI" output="false">
		<cfargument required="true" name="locale" hint="the locale to set"/>

		<cfscript>
			if(isInstanceOf(arguments.locale, "java.util.Locale")) {
				instance.locale = arguments.locale;
			}
			else {
				instance.locale = "";
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="getEventMap" output="false">

		<cfscript>
			// do not wrap with duplicate(); needs to be modifiable
			return instance.eventMap;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="equalsESAPI" output="false">
		<cfargument required="true" name="another"/>

		<cfscript>
			// TODO
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="hashCodeESAPI" output="false">

		<cfscript>
			// TODO
		</cfscript>

	</cffunction>

</cfcomponent>