<!---
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 */
--->
<cfcomponent output="false">

	<cfscript>
		// all ESAPI components will have these
		this.ESAPI4JVERSION = getESAPI4JVersion();	// ESAPI4J version
		this.ESAPINAME = "ESAPI4CF";				// ESAPI library name
		this.VERSION = "1.0.3a";					// ESAPI library version
		variables.javaObjectCache = {};

		System = newJava("java.lang.System");
	</cfscript>

	<cffunction access="public" name="init" output="false" hint="Default constructor">

		<cfscript>
			return this;
		</cfscript>

	</cffunction>

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

	<cffunction access="private" returntype="numeric" name="getESAPI4JVersion" output="false">

		<cfscript>
			try {
				// cannot use newJava() here
				createObject("java", "org.owasp.esapi.util.ObjFactory");
				return 2;
			}
			catch(Object e) {
				// occurs if this version is less than 2.0
				return 1;
			}

			return 0;
		</cfscript>

	</cffunction>

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
		<cfargument required="true" name="exception"/>

		<cfif isInstanceOf(arguments.exception, "org.owasp.esapi.util.RuntimeException")>
			<!--- ESAPI RuntimeExceptions --->
			<cfthrow type="#arguments.exception.getType()#" message="#arguments.exception.getMessage()#" extendedinfo="#arguments.exception.getCause()#"/>
		<cfelseif isInstanceOf(arguments.exception, "org.owasp.esapi.util.Exception")>
			<!--- ESAPI Exceptions --->
			<cfthrow type="#arguments.exception.getType()#" message="#arguments.exception.getUserMessage()#" detail="#arguments.exception.getLogMessage()#" extendedinfo="#arguments.exception.getCause()#"/>
		<cfelseif isInstanceOf(arguments.exception, "java.lang.Throwable")>
			<!--- Java Exceptions --->
			<cfthrow object="#arguments.exception#"/>
		<cfelseif isStruct(arguments.exception)>
			<!--- CFML Exceptions --->
			<cfthrow attributecollection="#arguments.exception#"/>
		</cfif>
	</cffunction>

	<cffunction access="private" returntype="boolean" name="cf8_isNull" output="false">
		<cfargument required="true" name="value"/>

		<cfscript>
			var data = getCFMLMetaData();
			// CF8 lacks support for isNull() so don't check it
			if(!(data.engine == "ColdFusion" && listFirst(data.version, ",") == 8)) {
				return isNull(arguments.value);
			}
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="cf8_writeDump" output="true">
		<cfargument required="true" name="var"/>
		<cfargument type="boolean" name="abort" default="false"/>

		<cfdump var="#arguments.var#"/>
		<cfif arguments.abort>
			<cfabort/>
		</cfif>
	</cffunction>

	<cffunction access="private" returntype="void" name="cf8_writeLog" output="false">
		<cfargument required="true" type="string" name="text"/>
		<cfargument type="string" name="type"/>
		<cfargument type="boolean" name="application"/>
		<cfargument type="string" name="file"/>
		<cfargument type="string" name="log"/>

		<cfscript>
			var atts = {text=arguments.text};
			if(structKeyExists(arguments, "type")) {
				atts.type = arguments.type;
			}
			if(structKeyExists(arguments, "application")) {
				atts.application = arguments.application;
			}
			if(structKeyExists(arguments, "file")) {
				atts.file = arguments.file;
			}
			if(structKeyExists(arguments, "log")) {
				atts.log = arguments.log;
			}
		</cfscript>

		<cflog attributecollection="#atts#"/>
	</cffunction>

</cfcomponent>