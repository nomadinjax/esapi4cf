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
<cfcomponent implements="User" extends="org.owasp.esapi.util.Object" output="false" hint="The ANONYMOUS user is used to represent an unidentified user. Since there is always a real user, the ANONYMOUS user is better than using null to represent this.">

	<cfscript>
		variables.ESAPI = "";
		variables.csrfToken = "";
		variables.sessions = {};
		variables.locale = "";
	</cfscript>

	<cffunction access="public" returntype="User$ANONYMOUS" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addRoles" output="false">
		<cfargument required="true" type="Array" name="newRoles"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfargument required="true" type="String" name="oldPassword"/>
		<cfargument required="true" type="String" name="newPassword1"/>
		<cfargument required="true" type="String" name="newPassword2"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="disable" output="false">

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="enable" output="false">

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
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

	<cffunction access="public" returntype="String" name="getName" output="false"
	            hint="Alias method that is equivalent to getAccountName()">

		<cfscript>
			return getAccountName();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCSRFToken" output="false">

		<cfscript>
			return variables.csrfToken;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getExpirationTime" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getFailedLoginCount" output="false">

		<cfscript>
			return 0;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLastFailedLoginTime" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLastHostAddress" output="false">

		<cfscript>
			return "unknown";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLastLoginTime" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLastPasswordChangeTime" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getRoles" output="false">

		<cfscript>
			return arrayNew(1);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getScreenName" output="false">

		<cfscript>
			return "Anonymous";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addSession" output="false">
		<cfargument required="true" name="s"/>

		<cfscript>
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeSession" output="false">
		<cfargument required="true" name="s"/>

		<cfscript>
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getSessions" output="false">

		<cfscript>
			return variables.sessions;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="incrementFailedLoginCount" output="false">

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
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
		<cfargument required="true" type="String" name="role"/>

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
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="loginWithPassword" output="false">
		<cfargument required="true" type="String" name="password"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="logout" output="false">

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="resetCSRFToken" output="false">

		<cfscript>
			variables.csrfToken = variables.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			return variables.csrfToken;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAccountName" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setExpirationTime" output="false">
		<cfargument required="true" type="Date" name="expirationTime"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setRoles" output="false">
		<cfargument required="true" type="Array" name="roles"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setScreenName" output="false">
		<cfargument required="true" type="String" name="screenName"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="unlock" output="false">

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false">
		<cfargument required="true" type="String" name="password"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastFailedLoginTime" output="false">
		<cfargument required="true" type="Date" name="lastFailedLoginTime"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastLoginTime" output="false">
		<cfargument required="true" type="Date" name="lastLoginTime"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastHostAddress" output="false">
		<cfargument required="true" type="String" name="remoteHost"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastPasswordChangeTime" output="false">
		<cfargument required="true" type="Date" name="lastPasswordChangeTime"/>

		<cfscript>
			throw(object=newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLocaleData" output="false"
		hint="the locale">

		<cfscript>
			return variables.locale;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLocaleData" output="false">
		<cfargument required="true" name="locale" hint="the locale to set">

		<cfscript>
			variables.locale = arguments.locale;
		</cfscript>
	</cffunction>

</cfcomponent>
