<cfcomponent extends="BaseACR" output="false">

	<cfscript>
		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="AlwaysTrueACR" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAuthorized" output="false">
		<cfargument type="any" name="runtimeParameter" required="true">
		<cfscript>
			return true;
		</cfscript>
	</cffunction>


</cfcomponent>
