<cfcomponent extends="cfesapi.org.owasp.esapi.reference.accesscontrol.BaseACR" output="false">

	<cfscript>
		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="EchoDynaBeanPolicyParameterACR" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			return this;
		</cfscript>
	</cffunction>

	<!--- isAuthorized --->

</cfcomponent>
