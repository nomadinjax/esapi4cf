<cfcomponent implements="cfesapi.org.owasp.esapi.User" output="false" hint="The ANONYMOUS user is used to represent an unidentified user. Since there is always a real user, the ANONYMOUS user is better than using null to represent this.">

	<cfscript>
		instance.csrfToken = "";
    	//instance.sessions = {};
		//instance.locale = "";
	</cfscript>
	<!--- addRole --->
	<!--- addRoles --->
	<!--- changePassword --->
	<!--- disable --->
	<!--- enable --->
	<!--- getAccountId --->

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

	<!--- getExpirationTime --->
	<!--- getFailedLoginCount --->
	<!--- getLastFailedLoginTime --->

	<cffunction access="public" returntype="String" name="getLastHostAddress" output="false">
		<cfscript>
	        return "unknown";
        </cfscript>
	</cffunction>

	<!--- getLastLoginTime --->
	<!--- getLastPasswordChangeTime --->

	<cffunction access="public" returntype="Array" name="getRoles" output="false">
		<cfscript>
        	return [];
		</cfscript>
	</cffunction>

	<!--- getScreenName --->

	<cffunction access="package" returntype="void" name="addSession" output="false" hint="Adds a session for this User.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpSession" name="s" required="true" hint="The session to associate with this user.">
		<cfscript>
			// do nothing
		</cfscript>
	</cffunction>


	<cffunction access="package" returntype="void" name="removeSession" output="false" hint="Removes a session for this User.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpSession" name="s" required="true" hint="The session to remove from being associated with this user.">
		<cfscript>
			// do nothing
		</cfscript>
	</cffunction>

	<!--- getSessions --->
	<!--- incrementFailedLoginCount --->

	<cffunction access="public" returntype="boolean" name="isAnonymous" output="false">
		<cfscript>
        	return true;
        </cfscript>
	</cffunction>

	<!--- isEnabled --->
	<!--- isExpired --->
	<!--- isInRole --->
	<!--- isLocked --->
	<!--- isLoggedIn --->
	<!--- isSessionAbsoluteTimeout --->
	<!--- isSessionTimeout --->
	<!--- lock --->
	<!--- loginWithPassword --->
	<!--- logout --->
	<!--- removeRole --->
	<!--- resetCSRFToken --->
	<!--- setAccountName --->
	<!--- setExpirationTime --->
	<!--- setRoles --->
	<!--- setScreenName --->
	<!--- unlock --->
	<!--- verifyPassword --->
	<!--- setLastFailedLoginTime --->
	<!--- setLastLoginTime --->

	<cffunction access="public" returntype="void" name="setLastHostAddress" output="false">
		<cfargument type="String" name="remoteHost" required="true">
		<cfscript>
        	throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
        </cfscript>
	</cffunction>

	<!--- setLastPasswordChangeTime --->

	<cffunction access="public" returntype="Struct" name="getEventMap" output="false">
		<cfscript>
			throw(object=createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>
	</cffunction>

	<!--- getLocale --->
	<!--- setLocale --->

</cfcomponent>
