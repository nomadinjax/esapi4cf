<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.Authenticator" output="false" hint="A partial implementation of the Authenticator interface. This class should not implement any methods that would be meant to modify a User object, since that's probably implementation specific.">

	<cfscript>
		Logger = createObject("java", "org.owasp.esapi.Logger");

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
			instance.currentUser = createObject("component", "ThreadLocalUser").init(instance.ESAPI);

	        return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="clearCurrent" output="false">
		<cfscript>
	        // instance.logger.logWarning(Logger.SECURITY, "************Clearing threadlocals. Thread" + Thread.currentThread().getName() );
	        instance.currentUser.set("");
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="exists" output="false">
		<cfargument type="String" name="accountName" required="true">
		<cfscript>
        	return isObject(getUserByAccountName(arguments.accountName));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="getCurrentUser" output="false" hint="Returns the currently logged user as set by the setCurrentUser() methods. Must not log in this method because the logger calls getCurrentUser() and this could cause a loop.">
		<cfscript>
	        local.user = instance.currentUser.getUser();
	        if (isNull(local.user) || !isObject(local.user)) {
	            local.user = createObject("component", "AnonymousUser").init(instance.ESAPI);
	        }
	        return local.user;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getUserFromSession" output="false" hint="cfesapi.org.owasp.esapi.User: the user from session or null if no user is found in the session">
		<cfscript>
	        local.session = instance.ESAPI.httpUtilities().getCurrentRequest().getSession(false);
	        if (isNull(local.session) || !isObject(local.session)) return "";
	        return instance.ESAPI.httpUtilities().getSessionAttribute(key=this.USER);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getUserFromRememberToken" output="false" hint="cfesapi.org.owasp.esapi.reference.DefaultUser: Returns the user if a matching remember token is found, or null if the token is missing, token is corrupt, token is expired, account name does not match and existing account, or hashed password does not match user's hashed password.">
		<cfscript>
	        try {
	            local.token = instance.ESAPI.httpUtilities().getCookie(instance.ESAPI.currentRequest(), instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);
	            if (local.token == "") return "";

	            // TODO - kww - URLDecode token first, and THEN unseal. See Google Issue 144.

	            local.data = instance.ESAPI.encryptor().unseal(local.token).split("\|");
	            if (arrayLen(local.data) != 2) {
	                instance.logger.warning(Logger.SECURITY_FAILURE, "Found corrupt or expired remember token");
	                instance.ESAPI.httpUtilities().killCookie(instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse(), instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);
	                return "";
	            }

	            local.username = local.data[1];
	            local.password = local.data[2];
	            System.out.println("DATA0: " & local.username);
	            System.out.println("DATA1: " & local.password);
	            local.user = getUserByAccountName(local.username);
	            if (!isObject(local.user)) {
	                instance.logger.warning(Logger.SECURITY_FAILURE, "Found valid remember token but no user matching " & local.username);
	                return "";
	            }

	            instance.logger.info(Logger.SECURITY_SUCCESS, "Logging in user with remember token: " & local.user.getAccountName());
	            local.user.loginWithPassword(local.password);
	            return local.user;
	        } catch (cfesapi.org.owasp.esapi.errors.AuthenticationException ae) {
	            instance.logger.warning(Logger.SECURITY_FAILURE, "Login via remember me cookie failed", ae);
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            instance.logger.warning(Logger.SECURITY_FAILURE, "Remember token was missing, corrupt, or expired");
	        }
	        instance.ESAPI.httpUtilities().killCookie(instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse(), instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME);
	        return "";
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="cfesapi.org.owasp.esapi.User" name="loginWithUsernameAndPassword" output="false" hint="Utility method to extract credentials and verify them.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="true" hint="The current HTTP request">
		<cfscript>
			//writedump(var=instance.ESAPI.securityConfiguration().getUsernameParameterName(),abort=true);
	        local.username = arguments.request.getParameter(instance.ESAPI.securityConfiguration().getUsernameParameterName());
	        local.password = arguments.request.getParameter(instance.ESAPI.securityConfiguration().getPasswordParameterName());

	        // if a logged-in user is requesting to login, log them out first
	        local.user = getCurrentUser();
	        if (isObject(local.user) && !local.user.isAnonymous()) {
	            instance.logger.warning(Logger.SECURITY_SUCCESS, "User requested relogin. Performing logout then authentication");
	            local.user.logout();
	        }

	        // now authenticate with username and password
	        if (local.username == "" || local.password == "") {
	            if (local.username == "") {
	                local.username = "unspecified user";
	            }
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Authentication failed", "Authentication failed for " & local.username & " because of blank username or password");
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        local.user = getUserByAccountName(local.username);
	        if (!isObject(local.user)) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Authentication failed", "Authentication failed because user " & local.username & " doesn't exist");
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        local.user.loginWithPassword(local.password);

	        arguments.request.setAttribute(local.user.getCSRFToken(), "authenticated");
	        return local.user;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="login" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#instance.ESAPI.httpUtilities().getCurrentRequest()#">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response" required="false" default="#instance.ESAPI.httpUtilities().getCurrentResponse()#">
		<cfscript>
	        if (isNull(arguments.request) || isNull(arguments.response)) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid request", "Request or response objects were null");
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }

	        // if there's a user in the session then use that
	        local.user = getUserFromSession();

	        // else if there's a remember token then use that
	        if (isNull(local.user) || !isInstanceOf(local.user, "cfesapi.org.owasp.esapi.User")) {
	            local.user = getUserFromRememberToken();
	        }

	        // else try to verify credentials - throws exception if login fails
	        if (isNull(local.user) || !isInstanceOf(local.user, "cfesapi.org.owasp.esapi.reference.DefaultUser")) {
	            local.user = loginWithUsernameAndPassword(arguments.request);
	        }

	        // set last host address
	        local.user.setLastHostAddress(arguments.request.getRemoteHost());

	        // warn if this authentication request was not POST or non-SSL connection, exposing credentials or session id
	        try {
	            instance.ESAPI.httpUtilities().assertSecureRequest(arguments.request);
	        } catch (cfesapi.org.owasp.esapi.errors.AccessControlException e) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationException").init(instance.ESAPI, "Attempt to login with an insecure request", e.detail, e);
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }

	        // don't let anonymous user log in
	        if (local.user.isAnonymous()) {
	            local.user.logout();
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Anonymous user cannot be set to current user. User: " & local.user.getAccountName());
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }

	        // don't let disabled users log in
	        if (!local.user.isEnabled()) {
	            local.user.logout();
	            local.user.incrementFailedLoginCount();
	            local.user.setLastFailedLoginTime(createObject("java", "java.util.Date").init());
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Disabled user cannot be set to current user. User: " & local.user.getAccountName());
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }

	        // don't let locked users log in
	        if (local.user.isLocked()) {
	            local.user.logout();
	            local.user.incrementFailedLoginCount();
	            local.user.setLastFailedLoginTime(createObject("java", "java.util.Date").init());
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Locked user cannot be set to current user. User: " & local.user.getAccountName());
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }

	        // don't let expired users log in
	        if (local.user.isExpired()) {
	            local.user.logout();
	            local.user.incrementFailedLoginCount();
	            local.user.setLastFailedLoginTime(createObject("java", "java.util.Date").init());
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Expired user cannot be set to current user. User: " & local.user.getAccountName());
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }

	        // check session inactivity timeout
	        if (local.user.isSessionTimeout()) {
	            local.user.logout();
	            local.user.incrementFailedLoginCount();
	            local.user.setLastFailedLoginTime(createObject("java", "java.util.Date").init());
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Session inactivity timeout: " & local.user.getAccountName());
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }

	        // check session absolute timeout
	        if (local.user.isSessionAbsoluteTimeout()) {
	            local.user.logout();
	            local.user.incrementFailedLoginCount();
	            local.user.setLastFailedLoginTime(createObject("java", "java.util.Date").init());
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AuthenticationLoginException").init(instance.ESAPI, "Login failed", "Session absolute timeout: " & local.user.getAccountName());
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
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

	<!---
		<cfinterface> is broken in CF
		It forces the immediate implementor to contain all functions from <cfinterface> even if an extended class contains the functions.
		Below functions are in the extended class but only reside here to make the <cfinterface> not throw errors.
		* override all of these *
		--->

	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false" hint="Verify that the supplied password matches the password for this user. Password should be stored as a hash. It is recommended you use the hashPassword(password, accountName) method in this class. This method is typically used for 'reauthentication' for the most sensitive functions, such as transactions, changing email address, and changing other account information.">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true" hint="the user who requires verification">
		<cfargument type="String" name="password" required="true" hint="the hashed user-supplied password">
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="createUser" output="false" hint="Creates a new User with the information provided. Implementations should check accountName and password for proper format and strength against brute force attacks ( verifyAccountNameStrength(String), verifyPasswordStrength(String, String)  ). Two copies of the new password are required to encourage user interface designers to include a 're-type password' field in their forms. Implementations should verify that both are the same.">
		<cfargument type="String" name="accountName" required="true" hint="the account name of the new user">
		<cfargument type="String" name="password1" required="true" hint="the password of the new user">
		<cfargument type="String" name="password2" required="true" hint="the password of the new user.  This field is to encourage user interface designers to include two password fields in their forms.">
	</cffunction>


	<cffunction access="public" returntype="String" name="generateStrongPassword" output="false" hint="Generate strong password that takes into account the user's information and old password. Implementations should verify that the new password does not include information such as the username, fragments of the old password, and other information that could be used to weaken the strength of the password.">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="false" hint="the user whose information to use when generating password">
		<cfargument type="String" name="oldPassword" required="false" hint="the old password to use when verifying strength of new password.  The new password may be checked for fragments of oldPassword.">
	</cffunction>


	<cffunction access="public" returntype="void" name="changePassword" output="false" hint="Changes the password for the specified user. This requires the current password, as well as the password to replace it with. The new password should be checked against old hashes to be sure the new password does not closely resemble or equal any recent passwords for that User. Password strength should also be verified.  This new password must be repeated to ensure that the user has typed it in correctly.">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true" hint="the user to change the password for">
		<cfargument type="String" name="currentPassword" required="true" hint="the current password for the specified user">
		<cfargument type="String" name="newPassword" required="true" hint="the new password to use">
		<cfargument type="String" name="newPassword2" required="true" hint="a verification copy of the new password">
	</cffunction>


	<cffunction access="public" returntype="any" name="getUserByAccountId" output="false" hint="cfesapi.org.owasp.esapi.User: Returns the User matching the provided accountId.  If the accoundId is not found, an Anonymous User or null may be returned.">
		<cfargument type="numeric" name="accountId" required="true" hint="the account id">
	</cffunction>


	<cffunction access="public" returntype="any" name="getUserByAccountName" output="false" hint="cfesapi.org.owasp.esapi.User: Returns the User matching the provided accountName.  If the accoundId is not found, an Anonymous User or null may be returned.">
		<cfargument type="String" name="accountName" required="true" hint="the account name">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getUserNames" output="false" hint="Gets a collection containing all the existing user names.">
	</cffunction>


	<cffunction access="public" returntype="String" name="hashPassword" output="false" hint="Returns a string representation of the hashed password, using the accountName as the salt. The salt helps to prevent against 'rainbow' table attacks where the attacker pre-calculates hashes for known strings. This method specifies the use of the user's account name as the 'salt' value. The Encryptor.hash method can be used if a different salt is required.">
		<cfargument type="String" name="password" required="true" hint="the password to hash">
		<cfargument type="String" name="accountName" required="true" hint="the account name to use as the salt">
	</cffunction>


	<cffunction access="public" returntype="void" name="removeUser" output="false" hint="Removes the account of the specified accountName.">
		<cfargument type="String" name="accountName" required="true" hint="the account name to remove">
	</cffunction>


	<cffunction access="public" returntype="void" name="verifyAccountNameStrength" output="false" hint="Ensures that the account name passes site-specific complexity requirements, like minimum length.">
		<cfargument type="String" name="accountName" required="true" hint="the account name">
	</cffunction>


	<cffunction access="public" returntype="void" name="verifyPasswordStrength" output="false" hint="Ensures that the password meets site-specific complexity requirements, like length or number of character sets. This method takes the old password so that the algorithm can analyze the new password to see if it is too similar to the old password. Note that this has to be invoked when the user has entered the old password, as the list of old credentials stored by ESAPI is all hashed.">
		<cfargument type="String" name="oldPassword" required="true" hint="the old password">
		<cfargument type="String" name="newPassword" required="true" hint="the new password">
	</cffunction>


</cfcomponent>
