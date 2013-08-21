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
<cfcomponent extends="org.owasp.esapi.util.Exception" output="false" hint="EnterpriseSecurityException is the base class for all security related exceptions. You should pass in the root cause exception where possible. Constructors for classes extending EnterpriseSecurityException should be sure to call the appropriate super() method in order to ensure that logging and intrusion detection occur properly. All EnterpriseSecurityExceptions have two messages, one for the user and one for the log file. This way, a message can be shown to the user that doesn't contain sensitive information or unnecessary implementation details. Meanwhile, all the critical information can be included in the exception so that it gets logged. Note that the 'logMessage' for ALL EnterpriseSecurityExceptions is logged in the log file. This feature should be used extensively throughout ESAPI implementations and the result is a fairly complete set of security log records. ALL EnterpriseSecurityExceptions are also sent to the IntrusionDetector for use in detecting anomolous patterns of application usage.">

	<cfscript>
		variables.ESAPI = "";
	
		/** The logger. */
		variables.logger = "";
	
		variables.logMessage = "";
	</cfscript>
	
	<cffunction access="public" returntype="EnterpriseSecurityException" name="init" output="false"
	            hint="Creates a new instance of EnterpriseSecurityException. This exception is automatically logged, so that simply by using this API, applications will generate an extensive security log. In addition, this exception is automatically registered with the IntrusionDetector, so that quotas can be checked.">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="String" name="userMessage" hint="the message displayed to the user"/>
		<cfargument required="true" type="String" name="logMessage" hint="the message logged"/>
		<cfargument name="cause" hint="the cause"/>
	
		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("EnterpriseSecurityException");
		
			if(structKeyExists(arguments, "cause")) {
				super.init(arguments.userMessage, arguments.cause);
			}
			else {
				super.init(arguments.userMessage);
			}
			variables.logMessage = arguments.logMessage;
		
			if(!variables.ESAPI.securityConfiguration().getDisableIntrusionDetection()) {
				variables.ESAPI.intrusionDetector().addException(this);
			}
		
			return this;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getUserMessage" output="false"
	            hint="Returns message that is safe to display to users">
		
		<cfscript>
			return getMessage();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getLogMessage" output="false"
	            hint="Returns a message that is safe to display in logs, but probably not to users">
		
		<cfscript>
			return variables.logMessage;
		</cfscript>
		
	</cffunction>
	
</cfcomponent>