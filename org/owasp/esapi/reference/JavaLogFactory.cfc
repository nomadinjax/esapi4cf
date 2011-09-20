<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.LogFactory" output="false">

	<cfscript>
		instance.ESAPI = "";

		instance.loggersMap = {};
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.LogFactory" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;

	        return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Logger" name="getLogger" output="false">
		<cfargument type="String" name="moduleName" required="true">
		<cfscript>
	    	// If a logger for this module already exists, we return the same one, otherwise we create a new one.
	    	if (structKeyExists(instance.loggersMap, arguments.moduleName)) {
	    		local.moduleLogger = instance.loggersMap.get(arguments.moduleName);
	    	}

	    	if (isNull(local.moduleLogger)) {
	    		local.moduleLogger = createObject("component", "JavaLogger").init(instance.ESAPI, arguments.moduleName);
	    		instance.loggersMap.put(arguments.moduleName, local.moduleLogger);
	    	}
			return local.moduleLogger;
    	</cfscript>
	</cffunction>


</cfcomponent>
