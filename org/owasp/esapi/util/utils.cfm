<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
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

<cffunction access="private" returntype="String" name="getBoolean" output="false"
	hint="Provides a consistent true/false return for a boolean value regardless of whether true/false, yes/no, or 1/0 were provided.">
	<cfargument required="true" type="String" name="bool">

	<cfscript>
		if (!len(trim(arguments.bool)) || !isBoolean(arguments.bool)) {
			return "";
		}

		// NOTE: do not include on/off - they are NOT valid booleans
		if (listFindNoCase("false,no,0", arguments.bool)) {
			return false;
		}
		return true;
	</cfscript>

</cffunction>

<cffunction access="public" name="getSecurityType" output="false">
	<cfargument required="true" type="String" name="type"/>

	<cfscript>
		var logger = createObject("java", "org.owasp.esapi.Logger");
		if(createObject("component", "org.owasp.esapi.util.Version").getESAPI4JVersion() == 2) {
			return logger[arguments.type];
		}
		else {
			return logger.SECURITY;
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

<cffunction access="private" returntype="String" name="toUnicode" output="false">
	<cfargument required="true" type="String" name="string"/>

	<cfscript>
		// CF8 requires 'var' at the top
		var i = "";
		var thisChr = "";

		var sb = createObject("java", "java.lang.StringBuffer").init();
		for(i = 1; i <= len(arguments.string); i++) {
			thisChr = mid(arguments.string, i, 6);
			if(left(thisChr, 2) == "\u") {
				sb.append(chr(inputBaseN(right(thisChr, 4), 16)));
				i = i + 5;
			}
			else {
				sb.append(left(thisChr, 1));
			}
		}
		return sb.toString();
	</cfscript>

</cffunction>

<!---
	Method backport for older CFML versions.
	Based upon technique from https://github.com/misterdai/cfbackport
--->
<cfset variables.cfmlData = getCFMLMetaData() />
<cfif variables.cfmlData["engine"] EQ "ColdFusion">
	<cfinclude template="utils_railo.cfm" />
	<cfif listFirst(variables.cfmlData["version"]) LT 9>
		<cfinclude template="utils_cf9.cfm" />
	</cfif>
	<cfif listFirst(variables.cfmlData["version"]) LT 10>
		<cfinclude template="utils_cf10.cfm" />
	</cfif>
</cfif>