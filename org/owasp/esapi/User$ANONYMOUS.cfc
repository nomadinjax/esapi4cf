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
<cfcomponent displayname="ANONYMOUS" extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.User" output="false">

	<cfscript>
		instance.ESAPI = "";

		instance.csrfToken = "";
		instance.sessions = [];
		instance.locale = "";
	</cfscript>

	<cffunction access="public" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addRoles" output="false">
		<cfargument required="true" type="Array" name="newRoles"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfargument required="true" type="String" name="oldPassword"/>
		<cfargument required="true" type="String" name="newPassword1"/>
		<cfargument required="true" type="String" name="newPassword2"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="disable" output="false">

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="enable" output="false">

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
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
			return instance.csrfToken;
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
		<cfset var local = {}/>

		<cfscript>
			local.empty = [];
			return local.empty;
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
			return instance.sessions;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="incrementFailedLoginCount" output="false">

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
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
		<cfargument name="request"/>

		<cfscript>
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isSessionTimeout" output="false">
		<cfargument name="request"/>

		<cfscript>
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="lock" output="false">

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="loginWithPassword" output="false">
		<cfargument name="request"/>
		<cfargument required="true" type="String" name="password"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="logout" output="false">

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="resetCSRFToken" output="false">

		<cfscript>
			instance.csrfToken = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			return instance.csrfToken;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAccountName" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setExpirationTime" output="false">
		<cfargument required="true" type="Date" name="expirationTime"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setRoles" output="false">
		<cfargument required="true" type="Array" name="roles"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setScreenName" output="false">
		<cfargument required="true" type="String" name="screenName"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="unlock" output="false">

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false">
		<cfargument required="true" type="String" name="password"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastFailedLoginTime" output="false">
		<cfargument required="true" type="Date" name="lastFailedLoginTime"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastLoginTime" output="false">
		<cfargument required="true" type="Date" name="lastLoginTime"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastHostAddress" output="false">
		<cfargument required="true" type="String" name="remoteHost"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastPasswordChangeTime" output="false">
		<cfargument required="true" type="Date" name="lastPasswordChangeTime"/>

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="getEventMap" output="false">

		<cfscript>
			throwError(newJava("java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
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

	<cffunction access="public" returntype="String" name="toStringESAPI" output="false">

		<cfscript>
			return "USER:" & getAccountName();
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