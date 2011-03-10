<cfcomponent extends="Exception" output="false">

	<cfscript>
		instance.ESAPI = '';
		instance.logger = '';
		instance.logMessage = '';
	</cfscript>

	<cffunction access="public" returntype="EnterpriseSecurityException" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="string" name="userMessage" required="false">
		<cfargument type="string" name="logMessage" required="false">
		<cfargument type="any" name="cause" required="false" hint="java.lang.Throwable">
		<cfscript>
			if (structKeyExists(arguments, "userMessage") && structKeyExists(arguments, "logMessage")) {
				local.ret = '';
				if (structKeyExists(arguments, "cause")) {
					local.ret = super.init(arguments.userMessage, arguments.cause);
				}
				else {
					local.ret = super.init(arguments.userMessage);
				}

				instance.ESAPI = arguments.ESAPI;
				instance.logger = instance.ESAPI.getLogger('EnterpriseSecurityException');
				instance.logMessage = arguments.logMessage;

				if (!instance.ESAPI.securityConfiguration().getDisableIntrusionDetection()) {
					instance.ESAPI.intrusionDetector().addException(this);
				}

				return local.ret;
			}
			else {
				return this;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getUserMessage" output="false" hint="Returns message meant for display to users. Note that if you are unsure of what set this message, it would probably be a good idea to encode this message before displaying it to the end user.">
		<cfscript>
        	return instance.errorObject.getMessage();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="string" name="getLogMessage" output="false" hint="Returns a message that is safe to display in logs, but may contain sensitive information and therefore probably should not be displayed to users.">
		<cfscript>
			return instance.logMessage;
		</cfscript>
	</cffunction>


</cfcomponent>
