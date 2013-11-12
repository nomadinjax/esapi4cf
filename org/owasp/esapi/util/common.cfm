<cffunction access="private" returntype="Struct" name="getCFMLMetaData" output="false">

	<cfscript>
		var results = {};
		if(structKeyExists(server, "railo")) {
			results["engine"] = server.ColdFusion.ProductName;
			results["version"] = server.railo.version;
		}
		else {
			results["engine"] = listFirst(server.ColdFusion.ProductName, " ");
			results["version"] = server.ColdFusion.ProductVersion;
		}
		return results;
	</cfscript>

</cffunction>

<cfscript>
	variables.javaObjectCache = {};
</cfscript>

<cffunction access="private" name="newJava" output="false">
	<cfargument required="true" type="String" name="classpath"/>

	<cfscript>
		var cp = arguments.classpath;
		var data = getCFMLMetaData();
		// prefer StringBuilder in newer CFML engines
		if(cp == "java.lang.StringBuffer" && !(data.engine == "ColdFusion" && listFirst(data.version, ",") == "8")) {
			cp = "java.lang.StringBuilder";
		}

		if(!structKeyExists(variables.javaObjectCache, cp)) {
			variables.javaObjectCache[cp] = createObject("java", cp);
		}

		return variables.javaObjectCache[cp];
	</cfscript>

</cffunction>

<cffunction access="public" name="getSecurityType" output="false">
	<cfargument required="true" type="String" name="type"/>

	<cfscript>
		var logger = newJava("org.owasp.esapi.Logger");
		if(this.ESAPI4JVERSION EQ 1) {
			return logger.SECURITY;
		}
		else {
			return logger[arguments.type];
		}
	</cfscript>

</cffunction>

<cffunction access="private" returntype="void" name="throwException" output="false">
	<cfargument required="true" type="org.owasp.esapi.util.Exception" name="exception"/>

	<cfif isInstanceOf(arguments.exception, "org.owasp.esapi.util.RuntimeException")>
		<!--- ESAPI RuntimeExceptions --->
		<cfthrow type="#arguments.exception.getType()#" message="#arguments.exception.getMessage()#" extendedinfo="#arguments.exception.getCause()#"/>
	<cfelseif isInstanceOf(arguments.exception, "org.owasp.esapi.util.Exception")>
		<!--- ESAPI Exceptions --->
		<cfthrow type="#arguments.exception.getType()#" message="#arguments.exception.getUserMessage()#" detail="#arguments.exception.getLogMessage()#" extendedinfo="#arguments.exception.getCause()#"/>
	</cfif>
</cffunction>

<!---
	Method backport for older CFML versions.
	Based upon technique from https://github.com/misterdai/cfbackport
--->
<cfset variables.cfmlData = getCFMLMetaData() />
<cfif variables.cfmlData["engine"] EQ "ColdFusion">
	<cfif listFirst(variables.cfmlData["version"]) LT 9>
		<cfinclude template="backport_cf9.cfm" />
	</cfif>
	<cfif listFirst(variables.cfmlData["version"]) LT 10>
		<cfinclude template="backport_cf10.cfm" />
	</cfif>
</cfif>