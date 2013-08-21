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
<cfcomponent extends="Object" output="false">

	<cfscript>
		variables.exception = "";
		variables.stackTrace = [];
		variables.type = "";
	</cfscript>
	
	<cffunction access="public" returntype="Exception" name="init" output="false">
		<cfargument type="String" name="message"/>
		<cfargument name="cause"/>
	
		<cfscript>
			var rootCause = "";
			if(structKeyExists(arguments, "message")) {
				if(structKeyExists(arguments, "cause") && isObject(arguments.cause)) {
					// CF exceptions extend java.lang.Exception
					if(isInstanceOf(arguments.cause, "java.lang.Throwable")) {
						rootCause = arguments.cause;
					}
					// RAILO exceptions do not extend java.lang.Exception
					// ? is there a better way ? I hope so...
					else if(isStruct(arguments.cause)) {
						rootCause = newJava("java.lang.Exception").init(arguments.cause.message);
					}
					variables.exception = newJava("java.lang.Exception").init(arguments.message, cause);
				}
				else {
					variables.exception = newJava("java.lang.Exception").init(arguments.message);
				}
			}
			else {
				variables.exception = newJava("java.lang.Exception").init();
			}
		
			setType();
			// RAILO ERROR: setStackTrace(variables.exception.tagContext);
			setStackTrace(variables.exception.getStackTrace());
		
			return this;
		</cfscript>
		
	</cffunction>
	
	<!--- fillInStackTrace --->
	
	<cffunction access="public" name="getCause" output="false">
		
		<cfscript>
			return variables.exception.getCause();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getLocalizedMessage" output="false">
		
		<cfscript>
			return variables.exception.getLocalizedMessage();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getMessage" output="false">
		
		<cfscript>
			return variables.exception.getMessage();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Array" name="getStackTrace" output="false">
		
		<cfscript>
			//return variables.exception.getStackTrace();
			return variables.stackTrace;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Exception" name="initCause" output="false">
		<cfargument required="true" name="cause"/>
	
		<cfscript>
			return variables.exception.initCause(arguments.cause);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="printStackTrace" output="false">
		
		<cfscript>
			return variables.exception.printStackTrace();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setStackTrace" output="false">
		<cfargument required="true" type="Array" name="stackTrace"/>
	
		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var item = "";
		
			// loop to include only the template calls
			for(i = 1; i <= arrayLen(arguments.stackTrace); i++) {
				item = arguments.stackTrace[i];
				// CF: runFunction; Railo: udfCall
				if(listFind("runFunction,udfCall", item.getMethodName())) {
					// drop indexes that contain "org\owasp\esapi\errors"
					if(findNoCase("org\owasp\esapi\util\Exception.cfc", item.getFileName()) || findNoCase("org\owasp\esapi\errors", item.getFileName())) {
						continue;
					}
					arrayAppend(variables.stackTrace, item);
				}
			}
		</cfscript>
		
	</cffunction>
	
	<!--- toString() --->
	
	<cffunction access="public" returntype="String" name="getType" output="false">
		
		<cfscript>
			return variables.type;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="private" returntype="void" name="setType" output="false">
		
		<cfscript>
			variables.type = getMetaData().name;
			// full path is missing when ESAPI is virtual directory
			if(listLen(variables.type, ".") EQ 1) {
				variables.type = "org.owasp.esapi.errors." & variables.type;
			}
		</cfscript>
		
	</cffunction>
	
</cfcomponent>