<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.Authenticator" output="false" hint="A partial implementation of the Authenticator interface. This class should not implement any methods that would be meant to modify a User object, since that's probably implementation specific.">

	<cfscript>
		/* Key for user in session */
    	this.USER = "ESAPIUserSessionKey";

		instance.ESAPI = "";

		instance.logger = "";
		instance.currentUser = "";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Authenticator" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			instance.logger = instance.ESAPI.getLogger("Authenticator");
			instance.currentUser = createObject('component', 'ThreadLocalUser').init(instance.ESAPI);

	        return this;
		</cfscript>
	</cffunction>

	<!--- TODO

		<cffunction name="clearCurrent">
		</cffunction>

		--->
	<!--- TODO

		<cffunction name="exists">
		</cffunction>

		--->

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="getCurrentUser" output="false" hint="Returns the currently logged user as set by the setCurrentUser() methods. Must not log in this method because the logger calls getCurrentUser() and this could cause a loop.">
		<cfscript>
	        return instance.currentUser.getUser();
    	</cfscript>
	</cffunction>


	<cffunction access="package" returntype="any" name="getUserFromSession" output="false" hint="cfesapi.org.owasp.esapi.User: the user from session or null if no user is found in the session">
		<cfscript>
	        local.session = instance.ESAPI.httpUtilities().getCurrentRequest().getSession(false);
	        if (!isObject(local.session)) return "";
	        return instance.ESAPI.httpUtilities().getSessionAttribute(this.USER);
    	</cfscript>
	</cffunction>

    <cffunction access="package" returntype="any" name="getUserFromRememberToken" output="false" hint="cfesapi.org.owasp.esapi.reference.DefaultUser: Returns the user if a matching remember token is found, or null if the token is missing, token is corrupt, token is expired, account name does not match and existing account, or hashed password does not match user's hashed password.">
		<cfscript>
	        try {
	            local.token = instance.ESAPI.httpUtilities().getCookie(instance.ESAPI.currentRequest(), instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);
	            if (local.token == "") return "";

	            // TODO - kww - URLDecode token first, and THEN unseal. See Google Issue 144.

	            local.data = instance.ESAPI.encryptor().unseal(local.token).split("\\|");
	            if (local.data.length != 2) {
	                instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Found corrupt or expired remember token");
	                instance.ESAPI.httpUtilities().killCookie(instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse(), instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);
	                return "";
	            }

	            local.username = local.data[1];
	            local.password = local.data[2];
	            System.out.println("DATA0: " & local.username);
	            System.out.println("DATA1: " & local.password);
	            local.user = getUser(local.username);
	            if (local.user == "") {
	                instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Found valid remember token but no user matching " & local.username);
	                return "";
	            }

	            instance.logger.info(javaLoader().create("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Logging in user with remember token: " & local.user.getAccountName());
	            local.user.loginWithPassword(local.password);
	            return local.user;
	        } catch (cfesapi.org.owasp.esapi.errors.AuthenticationException ae) {
	            instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Login via remember me cookie failed", ae);
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Remember token was missing, corrupt, or expired");
	        }
	        instance.ESAPI.httpUtilities().killCookie(instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse(), instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);
	        return "";
    	</cfscript>
	</cffunction>

	<!--- TODO

		<cffunction name="loginWithUsernameAndPassword">
		</cffunction>

		--->

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="login" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#instance.ESAPI.currentRequest()#">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response" required="true" default="#instance.ESAPI.currentResponse()#">
		<cfscript>
	        if (isNull(arguments.request) || isNull(arguments.response)) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid request", "Request or response objects were null");
				throw(message=cfex.getMessage(), type=cfex.getType());
	        }

	        // if there's a user in the session then use that
	        local.user = this.getUserFromSession();

	        // else if there's a remember token then use that
	        if (local.user == "") {
	            local.user = this.getUserFromRememberToken();
	        }

	        // else try to verify credentials - throws exception if login fails
	        if (local.user == "") {
	            local.user = this.loginWithUsernameAndPassword(arguments.request);
	        }

	        // set last host address
	        local.user.setLastHostAddress(arguments.request.getRemoteHost());

	        // warn if this authentication request was not POST or non-SSL connection, exposing credentials or session id
	        try {
	            instance.ESAPI.httpUtilities().assertSecureRequest(arguments.request);
	        } catch (cfesapi.org.owasp.esapi.errors.AccessControlException e) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationException").init(instance.ESAPI, "Attempt to login with an insecure request", e.getLogMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
	        }

	        // don't let anonymous user log in
	        if (local.user.isAnonymous()) {
	            local.user.logout();
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Anonymous user cannot be set to current user. User: " & local.user.getAccountName());
				throw(message=cfex.getMessage(), type=cfex.getType());
	        }

	        // don't let disabled users log in
	        if (!local.user.isEnabled()) {
	            local.user.logout();
	            local.user.incrementFailedLoginCount();
	            local.user.setLastFailedLoginTime(new Date());
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Disabled user cannot be set to current user. User: " & local.user.getAccountName());
				throw(message=cfex.getMessage(), type=cfex.getType());
	        }

	        // don't let locked users log in
	        if (local.user.isLocked()) {
	            local.user.logout();
	            local.user.incrementFailedLoginCount();
	            local.user.setLastFailedLoginTime(new Date());
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Locked user cannot be set to current user. User: " & local.user.getAccountName());
				throw(message=cfex.getMessage(), type=cfex.getType());
	        }

	        // don't let expired users log in
	        if (local.user.isExpired()) {
	            local.user.logout();
	            local.user.incrementFailedLoginCount();
	            local.user.setLastFailedLoginTime(new Date());
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Expired user cannot be set to current user. User: " & local.user.getAccountName());
				throw(message=cfex.getMessage(), type=cfex.getType());
	        }

	        // check session inactivity timeout
	        if (local.user.isSessionTimeout()) {
	            local.user.logout();
	            local.user.incrementFailedLoginCount();
	            local.user.setLastFailedLoginTime(new Date());
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Session inactivity timeout: " & local.user.getAccountName());
				throw(message=cfex.getMessage(), type=cfex.getType());
	        }

	        // check session absolute timeout
	        if (local.user.isSessionAbsoluteTimeout()) {
	            local.user.logout();
	            local.user.incrementFailedLoginCount();
	            local.user.setLastFailedLoginTime(new Date());
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Session absolute timeout: " & local.user.getAccountName());
				throw(message=cfex.getMessage(), type=cfex.getType());
	        }

	        //set Locale to the user object in the session from request
	        local.user.setLocale(arguments.request.getLocale());

	        // create new session for this User
	        local.session = arguments.request.getSession();
	        local.user.addSession(local.session);
	        local.session.setAttribute(this.USER, local.user);
	        setCurrentUser(local.user);
	        return local.user;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="logout" output="false">
		<cfscript>
	        local.user = getCurrentUser();
	        if (isObject(local.user) && !local.user.isAnonymous()) {
	            local.user.logout();
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setCurrentUser" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true">
		<cfscript>
        	instance.currentUser.setUser(arguments.user);
    	</cfscript>
	</cffunction>


</cfcomponent>
