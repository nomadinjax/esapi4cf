<cfinterface extends="cfesapi.org.owasp.esapi.util.ServletRequest">

	<cffunction access="public" returntype="String" name="getAuthType" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getContextPath" output="false">
	</cffunction>

	<cffunction access="public" returntype="Array" name="getCookies" output="false">
	</cffunction>

	<cffunction access="public" returntype="Date" name="getDateHeader" output="false">
		<cfargument required="true" type="String" name="name"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getHeader" output="false">
		<cfargument required="true" type="String" name="name"/>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getHeaderNames" output="false">
	</cffunction>

	<cffunction access="public" returntype="Array" name="getHeaders" output="false">
		<cfargument required="true" type="String" name="name"/>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getIntHeader" output="false">
		<cfargument required="true" type="String" name="name"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getMethod" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getPathInfo" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getPathTranslated" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getQueryString" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteUser" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getRequestedSessionId" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getRequestURI" output="false">
	</cffunction>

	<cffunction access="public" name="getRequestURL" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getServletPath" output="false">
	</cffunction>

	<cffunction access="public" name="getSession" output="false">
		<cfargument type="boolean" name="create"/>

	</cffunction>

	<cffunction access="public" name="getUserPrincipal" output="false">
	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromCookie" output="false">
	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromURL" output="false">
	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdValid" output="false">
	</cffunction>

	<cffunction access="public" returntype="boolean" name="isUserInRoleData" output="false">
		<cfargument required="true" type="String" name="role"/>

	</cffunction>

</cfinterface>