<cfinterface>

	<cffunction access="public" name="getAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getContentLength" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getContentType" output="false">
	</cffunction>

	<cffunction access="public" name="getInputStream" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getLocalAddr" output="false">
	</cffunction>

	<cffunction access="public" name="getLocaleData" output="false">
	</cffunction>

	<cffunction access="public" returntype="Array" name="getLocales" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getLocalName" output="false">
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getLocalPort" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getParameter" output="false">
		<cfargument required="true" type="String" name="name"/>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="getParameterMap" output="false">
	</cffunction>

	<cffunction access="public" returntype="Array" name="getParameterNames" output="false">
	</cffunction>

	<cffunction access="public" returntype="Array" name="getParameterValues" output="false">
		<cfargument required="true" type="String" name="name"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getProtocol" output="false">
	</cffunction>

	<cffunction access="public" name="getReader" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getRealPath" output="false">
		<cfargument required="true" type="String" name="path"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteAddr" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteHost" output="false">
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRemotePort" output="false">
	</cffunction>

	<cffunction access="public" name="getRequestDispatcher" output="false">
		<cfargument required="true" type="String" name="path"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getScheme" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getServerName" output="false">
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getServerPort" output="false">
	</cffunction>

	<cffunction access="public" returntype="boolean" name="isSecure" output="false">
	</cffunction>

	<cffunction access="public" returntype="void" name="removeAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" name="o"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCharacterEncoding" output="false">
		<cfargument required="true" type="String" name="enc"/>

	</cffunction>

</cfinterface>