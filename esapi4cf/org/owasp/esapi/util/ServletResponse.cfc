<cfinterface>

	<cffunction access="public" returntype="void" name="flushBuffer" output="false">
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getBufferSize" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getContentType" output="false">
	</cffunction>

	<cffunction access="public" name="getLocaleData" output="false">
	</cffunction>

	<cffunction access="public" name="getOutputStream" output="false">
	</cffunction>

	<cffunction access="public" name="getWriter" output="false">
	</cffunction>

	<cffunction access="public" returntype="boolean" name="isCommitted" output="false">
	</cffunction>

	<cffunction access="public" returntype="void" name="reset" output="false">
	</cffunction>

	<cffunction access="public" returntype="void" name="resetBuffer" output="false">
	</cffunction>

	<cffunction access="public" returntype="void" name="setBufferSize" output="false">
		<cfargument required="true" type="numeric" name="size"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCharacterEncoding" output="false">
		<cfargument required="true" type="String" name="charset"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setContentLength" output="false">
		<cfargument required="true" type="numeric" name="len"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setContentType" output="false">
		<cfargument required="true" type="String" name="type"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLocaleData" output="false">
		<cfargument required="true" name="loc"/>

	</cffunction>

</cfinterface>