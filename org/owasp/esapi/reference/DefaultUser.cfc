<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.User" output="false">

	<cfscript>
		Logger = createObject("java", "org.owasp.esapi.Logger");

		instance.ESAPI = "";

		/* The idle timeout length specified in the ESAPI config file. */
		this.IDLE_TIMEOUT_LENGTH = 20;

		/* The absolute timeout length specified in the ESAPI config file. */
		this.ABSOLUTE_TIMEOUT_LENGTH = 120;

		/* The logger used by the class. */
		instance.logger = "";

		/* This user's account id. */
		instance.accountId = 0;

		/* This user's account name. */
		instance.accountName = "";

		/* This user's screen name (account name alias). */
		instance.screenName = "";

		/* This user's CSRF token. */
		instance.csrfToken = "";

		/* This user's assigned roles. */
		instance.roles = [];

		/* Whether this user's account is locked. */
		instance.locked = false;

		/* Whether this user is logged in. */
		instance.loggedIn = true;

	    /* Whether this user's account is enabled. */
		instance.enabled = false;

	    /* The last host address used by this user. */
	    instance.lastHostAddress = "";

		/* The last password change time for this user. */
		instance.lastPasswordChangeTime = createObject("java", "java.util.Date").init(javaCast("long", 0));

		/* The last login time for this user. */
		instance.lastLoginTime = createObject("java", "java.util.Date").init(javaCast("long", 0));

		/* The last failed login time for this user. */
		instance.lastFailedLoginTime = createObject("java", "java.util.Date").init(javaCast("long", 0));

		/* The expiration date/time for this user's account. */
		instance.expirationTime = createObject("java", "java.util.Date").init(createObject("java", "java.lang.Long").MAX_VALUE);

		/* The sessions this user is associated with */
		instance.sessions = [];

		/* The event map for this User */
		instance.eventMap = {};

		/* A flag to indicate that the password must be changed before the account can be used. */
		// instance.requiresPasswordChange = true;

		/* The failed login count for this user's account. */
		instance.failedLoginCount = 0;

		/* This user's Locale. */
		instance.locale = "";

	    static.MAX_ROLE_LENGTH = 250;
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="accountName" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("DefaultUser");
			this.IDLE_TIMEOUT_LENGTH = instance.ESAPI.securityConfiguration().getSessionIdleTimeoutLength();
			this.ABSOLUTE_TIMEOUT_LENGTH = instance.ESAPI.securityConfiguration().getSessionAbsoluteTimeoutLength();

			resetCSRFToken();

			instance.accountName = lCase(arguments.accountName);

			while( true ) {
				local.id = newLong(abs( instance.ESAPI.randomizer().getRandomLong() ));
				if ( !isObject(instance.ESAPI.authenticator().getUserByAccountId( local.id )) && local.id != 0 ) {
					instance.accountId = local.id;
					break;
				}
			}

	        return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="addRole" output="false">
		<cfargument type="String" name="role" required="true">
		<cfscript>
			local.roleName = arguments.role.toLowerCase();
			if ( instance.ESAPI.validator().isValidInput("addRole", local.roleName, "RoleName", static.MAX_ROLE_LENGTH, false) ) {
				instance.roles.add(local.roleName);
				instance.logger.info(Logger.SECURITY_SUCCESS, "Role " & local.roleName & " added to " & getAccountName() );
			} else {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException").init(instance.ESAPI, "Add role failed", "Attempt to add invalid role " & local.roleName & " to " & getAccountName() );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="addRoles" output="false">
		<cfargument type="Array" name="newRoles" required="true">
		<cfscript>
	        for (local.i=1; local.i<=arrayLen(arguments.newRoles); local.i++) {
	            this.addRole(arguments.newRoles[local.i]);
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfargument type="String" name="oldPassword" required="true">
		<cfargument type="String" name="newPassword1" required="true">
		<cfargument type="String" name="newPassword2" required="true">
		<cfscript>
			instance.ESAPI.authenticator().changePassword(this, arguments.oldPassword, arguments.newPassword1, arguments.newPassword2);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="disable" output="false">
		<cfscript>
			instance.enabled = false;
			instance.logger.info( Logger.SECURITY_SUCCESS, "Account disabled: " & getAccountName() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="enable" output="false">
		<cfscript>
			instance.enabled = true;
			instance.logger.info( Logger.SECURITY_SUCCESS, "Account enabled: " & getAccountName() );
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


	<cffunction access="public" returntype="any" name="getExpirationTime" output="false" hint="Date">
		<cfscript>
			return instance.expirationTime.clone();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getFailedLoginCount" output="false">
		<cfscript>
			return duplicate(instance.failedLoginCount);
		</cfscript>
	</cffunction>


	<cffunction access="package" returntype="void" name="setFailedLoginCount" output="false">
		<cfargument type="numeric" name="count" required="true">
		<cfscript>
			instance.failedLoginCount = arguments.count;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getLastFailedLoginTime" output="false" hint="Date">
		<cfscript>
			return instance.lastFailedLoginTime.clone();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getLastHostAddress" output="false">
		<cfscript>
		if ( instance.lastHostAddress == "" ) {
			return "unknown";
		}
        return duplicate(instance.lastHostAddress);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getLastLoginTime" output="false" hint="Date">
		<cfscript>
			return instance.lastLoginTime.clone();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getLastPasswordChangeTime" output="false" hint="Date">
		<cfscript>
			return instance.lastPasswordChangeTime.clone();
		</cfscript>
	</cffunction>

	<!--- getName --->

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
		<cfargument type="cfesapi.org.owasp.esapi.HttpSession" name="s" required="true">
		<cfscript>
        	instance.sessions.add( arguments.s );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="removeSession" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpSession" name="s" required="true">
		<cfscript>
			instance.sessions.remove( arguments.s );
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
			// User cannot be anonymous, since we have a special User.ANONYMOUS instance for the anonymous user
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
			return getExpirationTime().before( createObject("java", "java.util.Date").init() );

			// If expiration should happen automatically or based on lastPasswordChangeTime?
			//		long from = lastPasswordChangeTime.getTime();
			//		long to = new Date().getTime();
			//		double difference = to - from;
			//		long days = Math.round((difference / (1000 * 60 * 60 * 24)));
			//		return days > 60;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isInRole" output="false">
		<cfargument type="String" name="role" required="true">
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
		<cfscript>
			local.session = instance.ESAPI.httpUtilities().getCurrentRequest().getSession(false);
			if ( !isObject(local.session) ) return true;
			local.deadline = createObject("java", "java.util.Date").init( local.session.getCreationTime() + this.ABSOLUTE_TIMEOUT_LENGTH);
			local.now = createObject("java", "java.util.Date").init();
			return local.now.after(local.deadline);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isSessionTimeout" output="false">
		<cfscript>
			local.session = instance.ESAPI.httpUtilities().getCurrentRequest().getSession(false);
			if ( !isObject(local.session) ) return true;
			local.deadline = createObject("java", "java.util.Date").init( local.session.getLastAccessedTime() + this.IDLE_TIMEOUT_LENGTH);
			local.now = createObject("java", "java.util.Date").init();
			return local.now.after(local.deadline);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="lock" output="false">
		<cfscript>
			instance.locked = true;
			instance.logger.info(Logger.SECURITY_SUCCESS, "Account locked: " & getAccountName() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="loginWithPassword" output="false">
		<cfargument type="String" name="password" required="true">
		<cfscript>
			if ( arguments.password == "" ) {
				setLastFailedLoginTime(createObject("java", "java.util.Date").init());
				incrementFailedLoginCount();
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Missing password: " & getAccountName()  );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}

			// don't let disabled users log in
			if ( !isEnabled() ) {
				setLastFailedLoginTime(createObject("java", "java.util.Date").init());
				incrementFailedLoginCount();
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Disabled user attempt to login: " & getAccountName() );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}

			// don't let locked users log in
			if ( isLocked() ) {
				setLastFailedLoginTime(createObject("java", "java.util.Date").init());
				incrementFailedLoginCount();
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Locked user attempt to login: " & getAccountName() );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}

			// don't let expired users log in
			if ( isExpired() ) {
				setLastFailedLoginTime(createObject("java", "java.util.Date").init());
				incrementFailedLoginCount();
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Expired user attempt to login: " & getAccountName() );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}

			logout();

			if ( verifyPassword( arguments.password ) ) {
				instance.loggedIn = true;
				instance.ESAPI.httpUtilities().changeSessionIdentifier( instance.ESAPI.currentRequest() );
				instance.ESAPI.authenticator().setCurrentUser(this);
				setLastLoginTime(createObject("java", "java.util.Date").init());
	            setLastHostAddress( instance.ESAPI.httpUtilities().getCurrentRequest().getRemoteAddr() );
				instance.logger.trace(Logger.SECURITY_SUCCESS, "User logged in: " & getAccountName() );
			} else {
				instance.loggedIn = false;
				setLastFailedLoginTime(createObject("java", "java.util.Date").init());
				incrementFailedLoginCount();
				if (getFailedLoginCount() >= instance.ESAPI.securityConfiguration().getAllowedLoginAttempts()) {
					lock();
				}
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Incorrect password provided for " & getAccountName() );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="logout" output="false">
		<cfscript>
			instance.ESAPI.httpUtilities().killCookie( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse(), instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME );

			local.session = instance.ESAPI.currentRequest().getSession(false);
			if (isObject(local.session)) {
	            removeSession(local.session);
				local.session.invalidate();
			}
			instance.ESAPI.httpUtilities().killCookie(instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse(), "JSESSIONID");
			instance.loggedIn = false;
			instance.logger.info(Logger.SECURITY_SUCCESS, "Logout successful" );
			instance.ESAPI.authenticator().setCurrentUser( createObject("component", "cfesapi.org.owasp.esapi.reference.AnonymousUser") );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="removeRole" output="false">
		<cfargument type="String" name="role" required="true">
		<cfscript>
			instance.roles.remove(arguments.role.toLowerCase());
			instance.logger.trace(Logger.SECURITY_SUCCESS, "Role " & role & " removed from " & getAccountName() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="resetCSRFToken" output="false" hint="In this implementation, we have chosen to use a random token that is stored in the User object. Note that it is possible to avoid the use of server side state by using either the hash of the users's session id or an encrypted token that includes a timestamp and the user's IP address. A relatively short 8 character string has been chosen because this token will appear in all links and forms.">
		<cfscript>
			// user.csrfToken = instance.ESAPI.encryptor().hash( session.getId(),user.name );
			// user.csrfToken = instance.ESAPI.encryptor().encrypt( address + ":" + ESAPI.encryptor().getTimeStamp();
			instance.csrfToken = instance.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			return instance.csrfToken;
		</cfscript>
	</cffunction>

	<!--- setAccountId --->

	<cffunction access="public" returntype="void" name="setAccountName" output="false">
		<cfargument type="String" name="accountName" required="true">
		<cfscript>
			local.old = getAccountName();
			instance.accountName = arguments.accountName.toLowerCase();
			if ( local.old.equals( "" ) ) {
				local.old = "[nothing]";
			}
			instance.logger.info(Logger.SECURITY_SUCCESS, "Account name changed from " & local.old & " to " & getAccountName() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setExpirationTime" output="false">
		<cfargument type="Date" name="expirationTime" required="true">
		<cfscript>
			instance.expirationTime = createObject("java", "java.util.Date").init( javaCast("long", arguments.expirationTime.getTime()) );
			instance.logger.info(Logger.SECURITY_SUCCESS, "Account expiration time set to " & instance.expirationTime & " for " & getAccountName() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setLastFailedLoginTime" output="false">
		<cfargument type="Date" name="lastFailedLoginTime" required="true">
		<cfscript>
			instance.lastFailedLoginTime = arguments.lastFailedLoginTime;
			instance.logger.info(Logger.SECURITY_SUCCESS, "Set last failed login time to " & instance.lastFailedLoginTime & " for " & getAccountName() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setLastHostAddress" output="false">
		<cfargument type="String" name="remoteHost" required="true">
		<cfscript>
			if ( instance.lastHostAddress != "" && !instance.lastHostAddress.equals(arguments.remoteHost)) {
	        	// returning remote address not remote hostname to prevent DNS lookup
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationHostException").init(instance.ESAPI, "Host change", "User session just jumped from " & instance.lastHostAddress & " to " & arguments.remoteHost );
				throw(type=cfex.getType(), message=cfex.getMessage());
			}
			instance.lastHostAddress = arguments.remoteHost;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setLastLoginTime" output="false">
		<cfargument type="Date" name="lastLoginTime" required="true">
		<cfscript>
			instance.lastLoginTime = arguments.lastLoginTime;
			instance.logger.info(Logger.SECURITY_SUCCESS, "Set last successful login time to " & instance.lastLoginTime & " for " & getAccountName() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setLastPasswordChangeTime" output="false">
		<cfargument type="Date" name="lastPasswordChangeTime" required="true">
		<cfscript>
			instance.lastPasswordChangeTime = arguments.lastPasswordChangeTime;
			instance.logger.info(Logger.SECURITY_SUCCESS, "Set last password change time to " & instance.lastPasswordChangeTime & " for " & getAccountName() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setRoles" output="false">
		<cfargument type="Array" name="roles" required="true">
		<cfscript>
			instance.roles = [];
			this.addRoles(arguments.roles);
			instance.logger.info(Logger.SECURITY_SUCCESS, "Adding roles " & arrayToList(arguments.roles) & " to " & getAccountName() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setScreenName" output="false">
		<cfargument type="String" name="screenName" required="true">
		<cfscript>
			instance.screenName = arguments.screenName;
			instance.logger.info(Logger.SECURITY_SUCCESS, "ScreenName changed to " & arguments.screenName & " for " & getAccountName() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="toString" output="false">
		<cfscript>
			return "USER:" & instance.accountName;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="unlock" output="false">
		<cfscript>
			instance.locked = false;
			instance.failedLoginCount = 0;
			instance.logger.info( Logger.SECURITY_SUCCESS, "Account unlocked: " & getAccountName() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false">
		<cfargument type="String" name="password" required="true">
		<cfscript>
			return instance.ESAPI.authenticator().verifyPassword(this, arguments.password);
		</cfscript>
	</cffunction>

	<!--- clone --->

	<cffunction access="public" returntype="any" name="getLocale" output="false" hint="java.util.Locale">
		<cfscript>
			return instance.locale;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setLocale" output="false">
		<cfargument type="any" name="locale" required="true" hint="java.util.Locale: the locale to set">
		<cfscript>
			instance.locale = arguments.locale;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Struct" name="getEventMap" output="false">
		<cfscript>
			// do not wrap with duplicate(); needs to be modifiable
    		return instance.eventMap;
    	</cfscript>
	</cffunction>


</cfcomponent>
