<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="ACRParameterLoader" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
	</cfscript>

	<cffunction access="public" returntype="DynaBeanACRParameterLoader" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger(listLast(getMetaData(this).name, "."));

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getParameters" output="false" hint="cfesapi.org.owasp.esapi.reference.accesscontrol.DynaBeanACRParameter">
		<cfargument type="any" name="config" required="true" hint="org.apache.commons.configuration.XMLConfiguration">
		<cfargument type="numeric" name="currentRule" required="true">
		<cfscript>
			local.policyParameter = createObject("component", "cfesapi.org.owasp.esapi.reference.accesscontrol.DynaBeanACRParameter").init();
			local.numberOfParameters = config.getList("AccessControlRules.AccessControlRule(" & currentRule & ").Parameters.Parameter[@name]").size();
			for(local.currentParameter = 0; local.currentParameter < local.numberOfParameters; local.currentParameter++) {
				local.parameterName = config.getString("AccessControlRules.AccessControlRule(" & currentRule & ").Parameters.Parameter(" & local.currentParameter & ")[@name]");
				local.parameterType = config.getString("AccessControlRules.AccessControlRule(" & currentRule & ").Parameters.Parameter(" & local.currentParameter & ")[@type]");
				local.parameterValue = createObject("component", "ACRParameterLoaderHelper").getParameterValue(config, currentRule, local.currentParameter, local.parameterType);
				local.policyParameter.set(local.parameterName, local.parameterValue);
			}
			local.policyParameter.lock(); //This line makes the policyParameter read only.
			instance.logger.info(createObject("java", "org.owasp.esapi.Logger").SECURITY_SUCCESS, "Loaded " & local.numberOfParameters & " parameters: " & local.policyParameter.toString());
			return local.policyParameter;
		</cfscript>
	</cffunction>


</cfcomponent>
