<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		instance.ESAPI = "";

		instance.accessControlRules = {};
	</cfscript>

	<cffunction access="public" returntype="PolicyDTO" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.accessControlRules = {};

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Struct" name="getAccessControlRules" output="false">
		<cfscript>
			return instance.accessControlRules;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="addAccessControlRule" output="false">
		<cfargument type="String" name="key" required="true">
		<cfargument type="String" name="accessControlRuleClassName" required="false">
		<cfargument type="any" name="policyParameter" required="true">
		<cfscript>
			if (!isNull(instance.accessControlRules.get(arguments.key))) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Duplicate keys are not allowed. " & "Key: " & arguments.key, "");
            	throw(message=cfex.getMessage(), type=cfex.getType());
			}
			//try {
				local.accessControlRule = createObject("component", arguments.accessControlRuleClassName).init(instance.ESAPI);
				local.accessControlRule.setPolicyParameters(arguments.policyParameter);
				instance.accessControlRules.put(arguments.key, local.accessControlRule);
			/*}
			catch (Application e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, 'Unable to create Access Control Rule for key: "' & arguments.key & '" with policyParameters: "' & arguments.policyParameter.toString() & '"', "", e);
            	throw(message=cfex.getMessage(), type=cfex.getType());
			}*/
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="toString" output="false">
		<cfscript>
			return instance.accessControlRules.toString();
		</cfscript>
	</cffunction>


</cfcomponent>
