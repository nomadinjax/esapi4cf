<cfcomponent implements="User" extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="The ANONYMOUS user is used to represent an unidentified user. Since there is always a real user, the ANONYMOUS user is better than using null to represent this.">

	<cfscript>
		instance.ESAPI = "";
		instance.csrfToken = "";
		instance.sessions = {};
	</cfscript>

	<cffunction access="public" returntype="User$ANONYMOUS" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addRoles" output="false">
		<cfargument required="true" type="Array" name="newRoles"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfargument required="true" type="String" name="oldPassword"/>
		<cfargument required="true" type="String" name="newPassword1"/>
		<cfargument required="true" type="String" name="newPassword2"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="disable" output="false">

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="enable" output="false">

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
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

	<cffunction access="public" returntype="Date" name="getExpirationTime" output="false">

		<cfscript>
			return null;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getFailedLoginCount" output="false">

		<cfscript>
			return 0;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getLastFailedLoginTime" output="false">

		<cfscript>
			return null;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLastHostAddress" output="false">

		<cfscript>
			return "unknown";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getLastLoginTime" output="false">

		<cfscript>
			return null;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getLastPasswordChangeTime" output="false">

		<cfscript>
			return null;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getRoles" output="false">

		<cfscript>
			return arrayNew( 1 );
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
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
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
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="loginWithPassword" output="false">
		<cfargument required="true" type="String" name="password"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="logout" output="false">

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="resetCSRFToken" output="false">

		<cfscript>
			instance.csrfToken = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.Encoder" ).CHAR_ALPHANUMERICS );
			return instance.csrfToken;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAccountName" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setExpirationTime" output="false">
		<cfargument required="true" type="Date" name="expirationTime"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setRoles" output="false">
		<cfargument required="true" type="Array" name="roles"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setScreenName" output="false">
		<cfargument required="true" type="String" name="screenName"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="unlock" output="false">

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false">
		<cfargument required="true" type="String" name="password"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastFailedLoginTime" output="false">
		<cfargument required="true" type="Date" name="lastFailedLoginTime"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastLoginTime" output="false">
		<cfargument required="true" type="Date" name="lastLoginTime"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastHostAddress" output="false">
		<cfargument required="true" type="String" name="remoteHost"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLastPasswordChangeTime" output="false">
		<cfargument required="true" type="Date" name="lastPasswordChangeTime"/>

		<cfscript>
			throwException( getJava( "java.lang.RuntimeException" ).init( "Invalid operation for the anonymous user" ) );
		</cfscript>

	</cffunction>

</cfcomponent>