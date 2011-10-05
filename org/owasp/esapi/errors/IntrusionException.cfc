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
<cfcomponent extends="Exception" output="false" hint="An IntrusionException should be thrown anytime an error condition arises that is likely to be the result of an attack in progress. IntrusionExceptions are handled specially by the IntrusionDetector, which is equipped to respond by either specially logging the event, logging out the current user, or invalidating the current user's account.">

	<cfscript>
		instance.ESAPI = "";
		instance.logMessage = "";

		/* The logger. */
		instsance.logger = "";
	</cfscript>
 
	<cffunction access="public" returntype="IntrusionException" name="init" output="false" hint="Creates a new instance of IntrusionException.">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="userMessage" required="true" hint="the message to display to users">
		<cfargument type="String" name="logMessage" required="true" hint="the message logged">
		<cfargument type="any" name="cause" required="false" hint="the cause">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger('IntrusionException');

			if (structKeyExists(arguments, "cause")) {
				super.init(arguments.userMessage, arguments.cause);
		        instance.logMessage = arguments.logMessage;
				instance.logger.error(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "INTRUSION - " & arguments.logMessage, arguments.cause);
			}
			else {
				super.init(arguments.userMessage);
		        instance.logMessage = arguments.logMessage;
	        	instance.logger.error(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "INTRUSION - " & arguments.logMessage);
			}

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getUserMessage" output="false" hint="Returns a String containing a message that is safe to display to users">
		<cfscript>
        	return getMessage();
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getLogMessage" output="false" hint="Returns a String that is safe to display in logs, but probably not to users">
		<cfscript>
        	return instance.logMessage;
        </cfscript> 
	</cffunction>


</cfcomponent>
