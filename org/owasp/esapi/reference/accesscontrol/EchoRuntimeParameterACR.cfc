<cfcomponent extends="BaseACR" output="false">

	<cfscript>
		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="EchoRuntimeParameterACR" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAuthorized" output="false" hint="Returns true iff runtimeParameter is a Boolean true.">
		<cfargument type="any" name="runtimeParameter" required="true" hint="java.lang.Boolean">
		<cfscript>
			try {
				return arguments.runtimeParameter.booleanValue();
			}
			catch (Object e) {
				return false;
			}
		</cfscript>
	</cffunction>


</cfcomponent>
