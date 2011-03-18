<cfcomponent implements="cfesapi.org.owasp.esapi.AccessControlRule" output="false" hint="Abstract Class; do not directly instantiate">

	<cfscript>
		instance.policyParameters = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setPolicyParameters" output="false">
		<cfargument type="any" name="policyParameter" required="true">
		<cfscript>
			instance.policyParameters = arguments.policyParameter;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getPolicyParameters" output="false">
		<cfscript>
			return instance.policyParameters;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAuthorized" output="false">
		<cfargument type="any" name="runtimeParameter" required="true">
		<!--- don't return so if extending class forgets to override, an error will be thrown --->
	</cffunction>


</cfcomponent>
