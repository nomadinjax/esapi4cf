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
<cfcomponent extends="Exception" output="false">

	<cfscript>
		instance.ESAPI = '';
		instance.logger = '';
		instance.logMessage = '';
	</cfscript>
 
	<cffunction access="public" returntype="EnterpriseSecurityException" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="string" name="userMessage" required="false" hint="the message displayed to the user">
		<cfargument type="string" name="logMessage" required="false" hint="the message logged">
		<cfargument type="any" name="cause" required="false" hint="the cause">
		<cfscript>
			if (structKeyExists(arguments, "userMessage") && structKeyExists(arguments, "logMessage")) {
				if (structKeyExists(arguments, "cause")) {
					super.init(arguments.userMessage, arguments.cause);
				}
				else {
					super.init(arguments.userMessage);
				}

				instance.ESAPI = arguments.ESAPI;
				instance.logger = instance.ESAPI.getLogger('EnterpriseSecurityException');
				instance.logMessage = arguments.logMessage;

				if (!instance.ESAPI.securityConfiguration().getDisableIntrusionDetection()) {
					instance.ESAPI.intrusionDetector().addException(this);
				}
			}

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getUserMessage" output="false" hint="Returns message meant for display to users. Note that if you are unsure of what set this message, it would probably be a good idea to encode this message before displaying it to the end user.">
		<cfscript>
        	return getMessage();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="string" name="getLogMessage" output="false" hint="Returns a message that is safe to display in logs, but may contain sensitive information and therefore probably should not be displayed to users.">
		<cfscript>
			return instance.logMessage;
		</cfscript> 
	</cffunction>


</cfcomponent>
