<!--- /**
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
 */ --->
<cfcomponent displayname="JavaLogFactory" extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.LogFactory" output="false" hint="Reference implementation of the LogFactory and Logger interfaces. This implementation uses the Java logging package, and marks each log message with the currently logged in user and the word 'SECURITY' for security related events. See the JavaLogFactory.JavaLogger Javadocs for the details on the JavaLogger reference implementation.">

	<cfscript>
		instance.ESAPI = "";
		instance.loggersMap = {};
	</cfscript>
	
	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.LogFactory" name="init" output="false"
	            hint="Null argument constructor for this implementation of the LogFactory interface needed for dynamic configuration.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
	
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
		
			return this;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Logger" name="getLogger" output="false">
		<cfargument required="true" type="String" name="moduleName"/>
	
		<cfset var local = {}/>
		
		<cfscript>
			// If a logger for this module already exists, we return the same one, otherwise we create a new one.
			if(structKeyExists(instance.loggersMap, arguments.moduleName)) {
				local.moduleLogger = instance.loggersMap.get(arguments.moduleName);
			}
			if(!structKeyExists(local, "moduleLogger")) {
				local.moduleLogger = newComponent("cfesapi.org.owasp.esapi.reference.JavaLogger").init(instance.ESAPI, arguments.moduleName);
				instance.loggersMap.put(arguments.moduleName, local.moduleLogger);
			}
			return local.moduleLogger;
		</cfscript>
		
	</cffunction>
	
</cfcomponent>