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
<cfcomponent displayname="Conf" extends="cfesapi.test.org.owasp.esapi.SecurityConfigurationWrapper" output="false">
	
	<cfscript>
		instance.allowedExes = "";
		instance.workingDir = "";
	</cfscript>
	
	<cffunction access="public" returntype="ExecutorTest$Conf" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.SecurityConfiguration" name="orig"/>
		<cfargument required="true" type="Array" name="allowedExes"/>
		<cfargument required="true" name="workingDir"/>
	
		<cfscript>
			super.init(arguments.orig);
			instance.allowedExes = arguments.allowedExes;
			instance.workingDir = arguments.workingDir;
		
			return this;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Array" name="getAllowedExecutables" output="false">
		
		<cfscript>
			return instance.allowedExes;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="getWorkingDirectory" output="false">
		
		<cfscript>
			return instance.workingDir;
		</cfscript>
		
	</cffunction>
	
</cfcomponent>