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
<cfcomponent extends="mxunit.framework.TestCase" output="false">

	<cfscript>
		variables.javaObjectCache = {};

		System = newJava("java.lang.System");

		// The following property must be set in order for the tests to find the resources directory
		System.setProperty("org.owasp.esapi.resources", "/esapi4cf/test/resources");
		System.setProperty("basedir", expandPath("../../../../"));
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			structClear(session);
			structClear(request);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			structClear(session);
			structClear(request);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="clearUserFile" output="false">
		<!--- clear the User file to prep for tests --->

		<cfscript>
			var filePath = variables.ESAPI.securityConfiguration().getResourceDirectory() & "users.txt";
			var writer = "";
			writer &= "## This is the user file associated with the ESAPI library from http://www.owasp.org" & chr(13) & chr(10);
			writer &= "## accountName | hashedPassword | roles | locked | enabled | rememberToken | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount" & chr(13) & chr(10);
			writer &= chr(13) & chr(10);
		</cfscript>

		<cffile action="write" file="#expandPath(filePath)#" output="#writer#"/>
	</cffunction>

	<cffunction access="private" name="newJava" output="false">
		<cfargument required="true" type="String" name="classpath"/>

		<cfscript>
			if(!structKeyExists(variables.javaObjectCache, arguments.classpath)) {
				variables.javaObjectCache[arguments.classpath] = createObject("java", arguments.classpath);
			}

			return variables.javaObjectCache[arguments.classpath];
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

	<cffunction access="private" name="getSecurityType" output="false">
		<cfargument required="true" type="String" name="type"/>

		<cfscript>
			var logger = newJava("org.owasp.esapi.Logger");
			// ESAPI 1.4.4
			if(structKeyExists(logger, "SECURITY")) {
				return logger.SECURITY;
			}
			// ESAPI 2.0+
			else {
				return logger[arguments.type];
			}
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

</cfcomponent>