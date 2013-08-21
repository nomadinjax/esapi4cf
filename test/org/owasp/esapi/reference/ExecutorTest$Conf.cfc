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
<cfcomponent extends="esapi4cf.test.org.owasp.esapi.SecurityConfigurationWrapper" output="false" hint="Config wrapper to temporarly set the allowedExecutables and workingDirectory.">

	<cfscript>
		variables.allowedExes = [];
		variables.workingDir = "";
	</cfscript>
	
	<cffunction access="public" returntype="ExecutorTest$Conf" name="init" output="false"
	            hint="Create wrapper with the specified allowed execs and workingDir.">
		<cfargument required="true" type="org.owasp.esapi.SecurityConfiguration" name="orig" hint="The configuration to wrap."/>
		<cfargument required="true" type="Array" name="allowedExes" hint="The executables to be allowed"/>
		<cfargument required="true" name="workingDir" hint="The working directory for execution"/>
	
		<cfscript>
			super.init(arguments.orig);
			variables.allowedExes = arguments.allowedExes;
			variables.workingDir = arguments.workingDir;
		
			return this;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Array" name="getAllowedExecutables" output="false"
	            hint="Override real one with our temporary one.">
		
		<cfscript>
			return variables.allowedExes;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="getWorkingDirectory" output="false" hint="Override real one with our temporary one.">
		
		<cfscript>
			return variables.workingDir;
		</cfscript>
		
	</cffunction>
	
</cfcomponent>