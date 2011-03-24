<cfcomponent implements="cfesapi.org.owasp.esapi.User" output="false" hint="The ANONYMOUS user is used to represent an unidentified user. Since there is always a real user, the ANONYMOUS user is better than using null to represent this.">

	<cfscript>
		instance.csrfToken = "";
    	instance.sessions = [];
		instance.locale = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="addRole" output="false">
		<cfargument type="String" name="role" required="true">
		<cfscript>
       		throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
       	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="addRoles" output="false">
		<cfargument type="Array" name="newRoles" required="true">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfargument type="String" name="oldPassword" required="true">
		<cfargument type="String" name="newPassword1" required="true">
		<cfargument type="String" name="newPassword2" required="true">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="disable" output="false">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="enable" output="false">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getAccountId" output="false">
		<cfscript>
        	return 0;
       	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getAccountName" output="false">
		<cfscript>
	        return "Anonymous";
		</cfscript>
	</cffunction>

	<!--- getName --->

	<cffunction access="public" returntype="String" name="getCSRFToken" output="false">
		<cfscript>
        	instance.csrfToken;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getExpirationTime" output="false">
		<cfscript>
			return "";
       	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getFailedLoginCount" output="false">
		<cfscript>
	        return 0;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getLastFailedLoginTime" output="false">
		<cfscript>
	        return "";
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getLastHostAddress" output="false">
		<cfscript>
	        return "unknown";
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getLastLoginTime" output="false">
		<cfscript>
	        return "";
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getLastPasswordChangeTime" output="false">
		<cfscript>
	        return "";
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getRoles" output="false">
		<cfscript>
        	return [];
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getScreenName" output="false">
		<cfscript>
	        return "Anonymous";
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="addSession" output="false" hint="Adds a session for this User.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpSession" name="s" required="true" hint="The session to associate with this user.">
		<cfscript>
			// do nothing
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="removeSession" output="false" hint="Removes a session for this User.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpSession" name="s" required="true" hint="The session to remove from being associated with this user.">
		<cfscript>
			// do nothing
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getSessions" output="false">
		<cfscript>
            return instance.sessions;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="incrementFailedLoginCount" output="false">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAnonymous" output="false">
		<cfscript>
        	return true;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isEnabled" output="false">
		<cfscript>
	        return false;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isExpired" output="false">
		<cfscript>
	        return false;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isInRole" output="false">
		<cfargument type="String" name="role" required="true">
		<cfscript>
	        return false;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isLocked" output="false">
		<cfscript>
			return false;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isLoggedIn" output="false">
		<cfscript>
			return false;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isSessionAbsoluteTimeout" output="false">
		<cfscript>
			return false;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isSessionTimeout" output="false">
		<cfscript>
			return false;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="lock" output="false">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="loginWithPassword" output="false">
		<cfargument type="String" name="password" required="true">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="logout" output="false">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="removeRole" output="false">
		<cfargument type="String" name="role" required="true">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="resetCSRFToken" output="false">
		<cfscript>
			instance.csrfToken = instance.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			return instance.csrfToken;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setAccountName" output="false">
		<cfargument type="String" name="accountName" required="true">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setExpirationTime" output="false">
		<cfargument type="Date" name="expirationTime" required="true">
		<cfscript>
    		throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setRoles" output="false">
		<cfargument type="Array" name="roles" required="true">
		<cfscript>
    		throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setScreenName" output="false">
		<cfargument type="String" name="screenName" required="true">
		<cfscript>
    		throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="unlock" output="false">
		<cfscript>
    		throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false">
		<cfargument type="String" name="password" required="true">
		<cfscript>
    		throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setLastFailedLoginTime" output="false">
		<cfargument type="Date" name="lastFailedLoginTime" required="true">
		<cfscript>
    		throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setLastLoginTime" output="false">
		<cfargument type="Date" name="lastLoginTime" required="true">
		<cfscript>
    		throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setLastHostAddress" output="false">
		<cfargument type="String" name="remoteHost" required="true">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setLastPasswordChangeTime" output="false">
		<cfargument type="Date" name="lastPasswordChangeTime" required="true">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="Struct" name="getEventMap" output="false">
		<cfscript>
			throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getLocale" output="false" hint="java.util.Locale">
		<cfscript>
   			return instance.locale;
   		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setLocale" output="false">
		<cfargument type="any" name="locale" required="true" hint="java.util.Locale: the locale to set">
		<cfscript>
			instance.locale = locale;
		</cfscript>
	</cffunction>


</cfcomponent>
